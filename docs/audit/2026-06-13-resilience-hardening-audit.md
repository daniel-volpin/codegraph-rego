# CodeGraph — Resilience-Hardening & Thesis-Defensibility Audit

- **Date:** 2026-06-13
- **Audited commit:** `ab228813dfd634bde13d5f06e0a33a85562a4be3` (working tree clean at audit start)
- **Branch (work):** `claude/codegraph-thesis-audit-7fi309` (harness-designated; see note below)
- **Scope:** end-to-end trace of the symbolic-first detection + bounded-remediation pipeline:
  Java ingestion → graph persistence → evidence-bundle build → OPA/Rego evaluation →
  explanation context → policy→remediation transfer → patch apply → build verification →
  re-ingestion/re-evaluation → evaluation/provenance/artifact generation.
- **Method:** four independent read-only review passes (ingestion/evidence, policy/OPA,
  remediation, evaluation/provenance), each finding re-verified firsthand against source.

> **Branch note.** The task text requested a `thesis/resilience-hardening` branch, but the
> session harness mandates development on `claude/codegraph-thesis-audit-7fi309` and forbids
> pushing elsewhere without explicit permission. Work proceeds on the designated branch; the
> logical intent ("resilience hardening") is preserved.

---

## Executive verdict

The repository is **substantially sound and the two load-bearing thesis claims hold under
code inspection**:

1. **FAISS / vector retrieval is provably *not* in the authoritative detection path.**
   `vector_context` is built in `bundles.py`, stored on the bundle, and surfaced only under
   `evidence.vector_context`; **no `.rego` module references it** (grep-confirmed). Detection
   reads only `source_code`, `graph_context`, `analysis_flags`, `helper_summaries`, `taint_paths`.
2. **A skipped/failed build cannot be counted as `fully_verified`.** At the metrics layer,
   `fully_verified := policy_fixed AND build_success`, and a skipped build yields
   `build_pass=None → build_success=False` (`remediation_runtime.py`). The headline remediation
   number is conservative.

However, the audit found **one Critical construct-validity defect, several High resilience/
reproducibility gaps, and a cluster of correctness/honesty issues** that a thesis examiner would
probe. The most important is a **benchmark-corpus fingerprint baked into the authoritative Rego
detection layer** (PoLICY-C1), which makes part of the weak-random detection rate a function of
recognizing OWASP Benchmark's class-naming convention rather than the security property.

**Thesis readiness:** defensible after (a) the metric-safe resilience/reproducibility fixes in
this pass land, and (b) the **document-and-stop** items below are resolved by the author with
deliberate, justified metric regeneration. The metric-affecting items were **not** auto-applied,
per the task's guardrail.

---

## How findings are dispositioned

| Disposition | Meaning |
|---|---|
| **FIX (this pass)** | Metric-safe, high-value; implemented with regression tests. |
| **STOP-FOR-REVIEW** | A correct fix would (or could) change a thesis-reported metric, benchmark population, evidence contract, policy meaning, or canonical artifact. Documented only; **not** auto-applied. |
| **DOC** | Framing/terminology alignment; no code change required. |

---

## Critical

### POLICY-C1 — Benchmark corpus fingerprint in the authoritative Rego layer (benchmark leakage) · **STOP-FOR-REVIEW**
- **Confidence:** High
- **Files:** `policy/iso_27001_access.rego:67-70` (`benchmark_context`), consumed at
  `policy/iso_27001_crypto.rego:23-25` (`random_context`), gating `insecure_random`
  (`crypto.rego:100-113`).
- **Evidence:**
  ```rego
  # access.rego
  benchmark_context if {
      input.target_method != null
      contains(lower(input.target_method), "benchmarktest")
  }
  # crypto.rego
  random_context if { servlet_context }
  random_context if { benchmark_context }
  insecure_random if { random_context; analysis_insecure_random }   # (+ 2 more clauses)
  ```
  OWASP Benchmark v1.2 names every test class `BenchmarkTestNNNNN`, so `benchmark_context` is a
  literal corpus-name gate wired into the authoritative detector. Weak-random fires only when
  `random_context` holds; outside a servlet context that gate is satisfied purely by the string
  `benchmarktest` in the method signature.
- **Impact:** The weak-random (CWE-330 / `ISO-A.10-WEAK-RANDOM`) detection rate on OWASP
  Benchmark is partly a function of recognizing the benchmark's naming convention, not the
  vulnerability. The result does not transfer to non-benchmark corpora — the classic train/test
  leakage failure mode.
- **Thesis claim at risk:** "OWASP Benchmark is the primary **controlled** detection oracle";
  "OPA/Rego as authoritative detection layer." Construct validity of the weak-random slice.
- **Why STOP:** Removing the clause **will change the reported weak-random TP/FP** and therefore
  the headline precision/recall/F1. This requires a deliberate, documented metric regeneration by
  the author.
- **Recommended change:** Delete `benchmark_context` and the `random_context if { benchmark_context }`
  clause. Gate weak-random on a real security context (servlet/endpoint annotation), or report it
  context-free like the weak-hash/weak-cipher rules (which are *not* context-gated — the gating is
  already inconsistent). If a benchmark harness genuinely needs it, move it to a benchmark-only
  overlay explicitly excluded from real-world claims.
- **Validation:** Re-run the weak-random slice with the clause removed; report the TP/FP delta and
  regenerate the affected canonical artifacts. Once removed, add a guard test asserting **no** Rego
  module under `policy/` references `benchmarktest`. (Not added in this pass — such a test cannot
  pass while the fingerprint remains, and removing the fingerprint is a STOP-FOR-REVIEW change.)

---

## High

### ING-C1 — Naive brace counting corrupts method `end_line` (snippet truncation/over-capture) · **STOP-FOR-REVIEW**
- **Confidence:** High
- **Files:** `codegraph/ingestion/service.py:33-49` (`_infer_block_end_line`), consumed at
  `:291-295` / `:357-359`; spans feed `extract_snippet_by_lines` in `bundles.py:206-211`.
- **Evidence:** The loop counts every `{`/`}` including those inside string literals (`"}"`,
  `"{0}"`), char literals, and comments. A single `String s = "}";` before the real body closes
  the count early; a `"{"` format string inflates it.
- **Impact:** `start_line`/`end_line` are persisted to Neo4j and drive the snippet fed to Rego
  (`source_code`) and to the LLM (`source_code_raw`). A mis-computed span yields a truncated or
  over-captured body — the load-bearing input to every policy decision.
- **Thesis claim at risk:** Graph-structured-evidence fidelity; any OWASP TP/FP whose sink line
  sits near a brace-in-string/comment.
- **Why STOP:** Correcting span inference **can shift detection results** (the Rego `contains()`
  view changes). Needs metric regeneration.
- **Recommended change:** Reuse javalang token/position spans, or strip string/char/comment
  content (the project already has `strip_java_lexical_noise`) before counting.
- **Validation:** Unit test with `"}"`, `'{'`, block comments with unbalanced braces, and
  `@SuppressWarnings({"a","b"})`; assert `end_line` is the true closing brace.

### ING-H2 — `safe_extract_zip` ignores symlink members (Zip-Slip via symlink) · **FIX**
- **Confidence:** High
- **Files:** `codegraph/ingestion/utils.py:14-77`.
- **Evidence:** The traversal guard checks the member *name* against `dest_root` but never
  inspects `external_attr` for symlink mode bits. A zip entry that is a symlink (`link -> /etc`)
  is materialized; a subsequent entry whose realpath is computed before the link exists can pass
  the prefix check and then be written *through* the symlink, escaping `dest_dir`. Attacker
  controls archive ordering. The docstring explicitly claims Zip-Slip protection.
- **Impact:** Arbitrary file write outside the upload workspace from a malicious upload — a
  path-traversal hole in the ingestion front door of a security framework.
- **Why FIX (metric-safe):** Upload hardening; no effect on OWASP detection metrics.
- **Change applied:** Reject members whose mode bits indicate a symlink, and refuse to write
  through any existing symlink component of the destination path.

### ING-H3 — `member_path == dest_root` non-dir write attempts to open the dest dir · **FIX** (folded into ING-H2 fix)
- **Confidence:** Medium · **Files:** `utils.py:42-46`.
- A crafted entry normalizing exactly to `dest_root` falls through to `open(dest_root, "wb")` →
  `IsADirectoryError` surfaced as a generic 500. Fixed by skipping non-dir members that resolve
  to the root.

### POLICY-H1 — OPA subprocess has no timeout (unbounded hang) · **FIX**
- **Confidence:** High
- **Files:** `codegraph/policy/runtime/opa.py:130` (`evaluate_bundle`), `:176`
  (`evaluate_package_root`). Both omit `timeout=`. Run across a 32-wide thread pool
  (`integration.py:127-131`), one OPA process per bundle.
- **Impact:** A single hung `opa eval` blocks a worker indefinitely; a few hangs stall an entire
  benchmark run with no error surfaced — a liveness/reproducibility hazard.
- **Why FIX (metric-safe):** Only triggers on a hang; normal runs are unaffected.
- **Change applied:** Added a configurable `timeout` (default 120 s) to both calls and converted
  `subprocess.TimeoutExpired` into the existing `RuntimeError` contract. Regression test asserts a
  hang becomes a `RuntimeError`, not a stall.

### POLICY-H2 — OPA binary unpinned in the container; diverges from the venv pin · **FIX**
- **Confidence:** High
- **Files:** `Dockerfile.backend:17` downloads `downloads/latest/opa_linux_..._static`
  (**unpinned "latest"**); `scripts/setup_benchmark_env.sh` pins `v1.14.1`. Runtime resolves bare
  `opa` from PATH (`opa.py:119`, `integration.py:107`); all Rego modules `import rego.v1`.
- **Impact:** A rebuilt image can silently change the policy engine version and shift results; the
  venv (1.14.1) and container ("latest") can disagree, so benchmark numbers depend on which
  environment ran them.
- **Why FIX (metric-safe):** Reproducibility hardening; pins the container to the version the
  numbers were produced with.
- **Change applied:** Pinned the Dockerfile to the same `v1.14.1` tag as the setup script.

### POLICY-H3 — Batch detection aborts the whole run on the first bundle failure · **FIX**
- **Confidence:** High
- **Files:** `codegraph/policy/integration.py:132-136` — any single bundle raising `RuntimeError`
  discards all already-computed violations and returns a bare `{"error": ...}`.
- **Impact:** One malformed method aborts a whole-corpus evaluation; an examiner re-running may
  get an error instead of metrics. The per-method path already degrades gracefully — the batch
  path is inconsistent.
- **Why FIX (metric-safe on the happy path):** On a clean OWASP corpus no bundle fails, so metrics
  are unchanged; the change only adds resilience + per-bundle error attribution.
- **Change applied:** Record per-bundle failures and continue; surface a `failed_bundles` list in
  the response. Regression test: one failing bundle no longer hides the others.

### EVAL-F1 — Primary detection oracle's provenance omits ground-truth/corpus identity · **FIX**
- **Confidence:** High
- **Files:** `codegraph/evaluation/provenance.py`; the full-pipeline detection/explanation evals
  record `config.sha256` but never hash the ground-truth CSV or the OWASP corpus. Configs point at
  the corpus by env var (`${OWASP_BENCHMARK_ROOT}/expectedresults-1.2.csv`). The committed
  `outputs/thesis_final_detection_full_v2/provenance.json` has no corpus SHA — yet the *secondary*
  file-level evals (`run_owasp_lexical_eval.py`, `run_owasp_multiseed_eval.py`) **do** record
  `owasp_benchmark_sha`. The primary oracle is less provenanced than the secondary one.
- **Impact:** A reviewer cannot prove the canonical P/R/F1 was computed against a specific
  BenchmarkJava commit (whose `master`/v1.2 tag is known to drift).
- **Why FIX (additive, metric-safe):** Adds fields to future `provenance.json`; does not touch
  existing canonical artifacts.
- **Change applied:** `collect_provenance` now hashes the resolved ground-truth file and records
  the benchmark-root git SHA when available. Regression test asserts the fields appear.

### EVAL-F2 — Canonical thesis artifacts are tracked but unprotected from silent overwrite · **FIX**
- **Confidence:** High
- **Files:** `.gitignore` selectively un-ignores `outputs/thesis_final_*`; no checksum manifest,
  CI diff-guard, or test pins the headline values. Eval scripts `mkdir(..., exist_ok=True)` and
  unconditionally write into `--output-dir`, so pointing a run at a canonical dir silently
  overwrites the oracle.
- **Impact:** Directly at risk: "canonical thesis artifacts and reported metrics must not be
  silently changed." A stray `--output-dir outputs/thesis_final_detection_full_v2` overwrites it
  with no tripwire.
- **Why FIX (additive guard):** Adds a manifest + test; changes no metric.
- **Change applied:** Added `outputs/canonical_manifest.sha256` (hashes of the un-ignored
  `thesis_final_*` metric files) plus a pytest guard that recomputes and compares, failing if any
  canonical metric file changes without an explicit manifest update.

---

## Medium

### REM-F1 — `dry_run` mutates the shared live Neo4j graph during verification · **STOP-FOR-REVIEW**
- **Confidence:** High · **Files:** `apply_flow.py:322-324, 396-401`; `ingestion/service.py:798-801`.
- In `dry_run` the candidate is re-ingested into the **live** graph (`process_single_file_content`
  → purge + re-ingest), then restored in `finally`. The remediation module docstring claims "the
  Neo4j graph ... remain untouched" — **false for dry_run**. A crash between mutate and restore
  leaves the candidate source in the graph as if it were ground truth, biasing later cases; any
  concurrent evaluation sees purged/half state.
- **Why STOP:** Re-architecting verification to an isolated graph scope (or driving dry_run off the
  temp-file virtual bundle, as `preview_virtual_fix` already does) is non-trivial and **changes the
  re-evaluation substrate** that produced the remediation numbers. Needs deliberate review (couples
  with REM-F2).
- **Recommended:** Verify candidates off the temp file + virtual bundle without touching Neo4j, or
  use a namespaced/rolled-back graph scope. Add crash-injection and concurrency tests.

### REM-F2 — Candidate re-eval slices source with graph line spans (correctness coupled to REM-F1) · **STOP-FOR-REVIEW**
- **Confidence:** Medium · **Files:** `bundles.py:199-213`; `apply_flow.py:344-348`.
- The override bundle reads candidate **text** from the temp file but slices it with `start_line`/
  `end_line` from the graph snapshot. This is consistent today only because REM-F1 mutates the
  graph first. Fixing F1 naively desynchronizes spans whenever the edit changes line count →
  false PASS/FAIL. Fix **with** F1: recompute the method span from the override file and assert the
  sliced snippet contains the target signature.

### REM-F3 — Apply-mode write gate treats a *skipped* build as a passing build gate · **FIX**
- **Confidence:** High · **Files:** `apply_flow.py:371-377`.
- `... and (not compilation.get("attempted") or compilation.get("success"))` lets a skipped build
  (no build system detected) satisfy the apply gate, so a remediation that was never compiled can
  be written to the live workspace with `status=OK`.
- **Why FIX (metric-safe for the thesis):** The benchmark runs in `dry_run`; the headline
  `fully_verified` already requires `build_pass=True`. Hardening the **apply** path fail-closed
  changes no benchmark metric.
- **Change applied:** Apply-mode now requires `compilation.attempted AND compilation.success`;
  a skipped build no longer authorizes a live write. Regression test covers the no-build-root case.

### REM-F9 — Failed rollback leaves modified state but reports success-adjacent status · **FIX**
- **Confidence:** High · **Files:** `apply_flow.py:396-406`.
- The `finally` restore catches and only WARN-logs; if restoring the live file or graph fails, the
  case is still reported with its computed `status` (possibly `OK`) while the workspace/graph is
  left in the candidate state.
- **Why FIX (metric-safe):** Only triggers on a restore failure; makes a latent silent-failure
  loud.
- **Change applied:** A restore failure now downgrades the case to a non-success status
  (`ROLLBACK_ERROR`) and surfaces the error, so it cannot be counted as a clean success.
  Regression test injects a restore failure.

### ING-M5 — Non-deterministic `calls`/`callers`/`uses_fields` ordering breaks byte-level repro · **FIX**
- **Confidence:** High · **Files:** `policy/runtime/bundles.py:77-118`.
- Neo4j `collect(DISTINCT …)` has no defined order; `annotations` is sorted but `calls`,
  `callers`, and `uses_fields` are passed through unsorted into `graph_context`, so the bundle
  JSON differs across reruns from an identical graph.
- **Why FIX (metric-safe):** Rego sink checks are any-match, so **detection outcomes are
  invariant** under reordering; this strictly improves reproducibility. (Explanation citation IDs
  are constrained to a card-ID enum, so citation correctness is also invariant; only display order
  could shift — noted for optional explanation-artifact regeneration.)
- **Change applied:** Deterministically sort `calls`, `callers`, and `uses_fields`. Golden-style
  test asserts stable ordering.

### ING-M8 — Silent parse-skip turns unparseable Java into false negatives · **FIX**
- **Confidence:** High · **Files:** `ingestion/service.py:417-441`.
- A file that fails `javalang.parse` contributes zero entities but ingestion reports success — a
  skipped TP case looks like a clean pass.
- **Why FIX (additive surfacing):** Does not change what is ingested for parseable files; adds a
  loud, countable signal.
- **Change applied:** Parse failures are aggregated and surfaced (count + sample) so a non-trivial
  parse-failure rate is visible rather than masquerading as a clean run.

### POLICY-M1 — Non-deterministic `decision_id`/`evaluated_at` in the authoritative response · **DOC**
- `build_violation_response` already accepts `decision_id`/`evaluated_at` kwargs but the batch path
  never threads them, so each run embeds a fresh UUID + wall clock. Detection content is
  deterministic; only these two fields vary. **Recommendation:** thread a fixed clock/ID source for
  benchmark promotion, or document these as the only permitted-to-vary fields and exclude them from
  artifact diffs. (Left as DOC to avoid touching the canonical response shape without sign-off.)

### POLICY-M2 — Dead Rego source-fallback branches (`input.analysis_flags == null`) · **DOC**
- `source_insecure_random` / injection `no_analysis_flags` branches require `analysis_flags == null`,
  but the production builder always populates a full flag dict, so these branches never fire in the
  live pipeline. Either feed `analysis_flags=None` where a pure-Rego path is intended, or remove the
  dead guards and document that Python pre-analysis is mandatory.

### POLICY-M3 / REM-F5 — Feature extraction is Python; Rego decides (honesty/framing) · **DOC**
- Decisive injection/crypto predicates are computed in Python (`source_analysis_core.py`,
  `analysis/*`) and surfaced to Rego as booleans; remediation ships raw method source to the LLM.
  The code is honest, but `docs/thesis_context.md` should state "Rego is the authoritative
  **decision** layer over deterministic Python/Rego-extracted features," and that bounded
  remediation is **method-local-source-grounded** (distinct from the graph-evidence explanation
  surface). No code change.

### POLICY-M4 — Multi-hop "taint" is reachability-gated, not source→sink flow (honesty) · **DOC**
- `TaintPathFinder` BFS over `CALLS` flags a sink if any callee's text matches a sink regex, with
  no value-flow correlation. Consistent with the thesis "not a full taint analysis" disclosure
  (already in `docs/thesis_context.md`). Ensure no prose calls these "verified taint flows" — call
  them "reachability-gated heuristics."

### ING-M7 — Overloaded methods collapse to one graph node (param-less signature key) · **STOP-FOR-REVIEW**
- `MERGE (m:Method {signature: "<fqn>.<name>()"})` drops parameter types, so overloads collapse;
  the last write wins and `CALLS`/`USES` edges mis-attribute. `method_index` keys on
  `full_signature` (partial mitigation). **Why STOP:** keying nodes on `full_signature` changes
  graph structure and can shift per-method TP/FP. Document; regenerate metrics if changed.

### EVAL-F5 — Missing OWASP source files silently shrink the denominator · **STOP-FOR-REVIEW (partial)**
- CSV rows whose `.java` is absent are dropped before sampling (`owasp_lexical_eval.py:253-254`);
  `stage_benchmark_subset` logs a missing count that never reaches `metrics.json`. On a complete
  checkout this is benign; on a partial one the population silently differs from the config.
  **Recommendation (additive, safe):** record `missing_testcase_ids`/`staged_count` in metrics +
  provenance so the population is self-describing. The metric *definition* is unchanged, but because
  it touches the evaluation output schema it is flagged for author sign-off before wiring into the
  canonical runners.

### EVAL-F4 — Per-CWE bootstrap CIs share one resample seed (correlated "independent" CIs) · **DOC**
- Within an `evaluate_owasp` call the sampling seed is reused as the bootstrap seed for every CWE
  block, so per-CWE resample index sequences are identical. Point estimates and CI widths are fine;
  cross-CWE CI **independence** is not. Derive per-block seeds (`seed + index`) if the thesis claims
  CWE-level CI independence.

---

## Low (selected)

- **POLICY-M5 / EVAL-F7** — `evaluate_bundle` trusts `result[0].expressions[0].value` shape; an
  unexpected OPA envelope returns `[]` (zero violations) as success. Validate envelope cardinality
  and raise on surprise rather than silently under-report. (DOC / small follow-up.)
- **ING-L11** — `extract_snippet_by_lines` returns the file head when `start_line is None` but
  `end_line` is set; should return `""`. (Small FIX-adjacent.)
- **ING-L13** — `scripts/ingestion/codebase_to_neo4j.py:48-50` sets module attributes for
  `--neo4j-uri/-user/-pass` that the service never reads (settings-sourced) — flags silently
  ignored. (DOC.)
- **REM-F7** — Per-case full `copytree` of the build root (can be the whole benchmark tree) is an
  I/O/disk/runtime hazard; exclude `target/`, `.git`, build outputs and copy only the target module
  subtree. (Follow-up.)
- **REM-F8** — Build timeout is hard-coded 120 s; large modules can legitimately exceed it →
  mislabel a valid fix as `BUILD_ERROR`. Make it configurable. (Folded into POLICY-H1's settings
  approach where practical.)
- **REM-F10 / EVAL-F8** — `resolve_file_path` honors absolute/`..` paths from violation records with
  no containment check (apply-mode write target); hybrid-search/FAISS failures are swallowed with no
  artifact flag. (DOC / follow-up.)
- **Test infra** — Detection tests call `evaluate_bundle` (needs the `opa` binary) with **no skip
  guard**, so 25 tests fail confusingly in any environment without OPA. **FIX:** added an autouse
  skip when `shutil.which("opa")` is absent, turning environment failures into explicit skips.

---

## Claims independently confirmed sound (no action)

- Vector/LLM excluded from authoritative detection (grep-verified, multiple agents).
- Lexical-anchoring contract is coherent and deterministic; raw source kept only for display.
- Catalog alignment (registry ↔ Rego ↔ catalog ↔ iso_rules) is enforced by
  `tests/codegraph/policy/test_policy_artifacts.py`, not by hope.
- Data-contract normalization in `contracts.py` is strict and total.
- `fully_verified` is conservative; capability gating is fail-closed to the three supported crypto
  categories; edit application is structurally re-validated via javalang.
- Calibration population splits (`full` / `attempted_only` / `no_fix_only`), Wilson/bootstrap CIs,
  and McNemar (b=c=0 → n/a) are implemented correctly.
- Stratified sampling is seeded and deterministic; "overall" dedups via `sampled_union`.

---

## Top 5 remaining risks (for the author)

1. **POLICY-C1** — benchmark-name fingerprint in the authoritative detector; resolve and regenerate
   the weak-random slice before citing those numbers (highest construct-validity risk).
2. **ING-C1 / ING-M7** — span inference and overload collapse can shift the very snippets/graph
   nodes all OWASP TP/FP rest on; correct and regenerate deliberately.
3. **REM-F1/F2** — dry_run mutates the live graph and couples re-eval correctness to that mutation;
   contradicts the "graph untouched" claim and is a latent concurrency/crash hazard.
4. **EVAL-F1/F2** — provenance/corpus identity and canonical-artifact protection (both addressed
   additively this pass; verify the manifest is kept current on every promotion).
5. **POLICY-M1 / EVAL-F4** — residual non-determinism (UUID/timestamp fields; shared bootstrap
   seed) that complicates byte-level artifact reproducibility and CI-level CI independence.

---

# Appendix — Reviewer sign-off packet (2026-06-14)

Added in response to reviewer decisions. **Execution constraint:** this audit
sandbox has **no `opa` binary** (network-blocked download, HTTP 403) and **no
OWASP Benchmark corpus checked out**. Every item below that needs OPA or the
corpus to produce a *number* is marked **BLOCKED (needs runner)** — no such
number is fabricated. Static mechanism, traces, and code edits are complete.

## A. POLICY-C1 — benchmark fingerprint

- **Rego file/rule/symbol:** `policy/iso_27001_access.rego`, rule `benchmark_context`
  (previously lines 67-70). Consumed by `policy/iso_27001_crypto.rego` rule
  `random_context` (previously the clause at lines 23-25), which gates
  `insecure_random` (`crypto.rego:100-113`).
- **Python input field feeding it:** `input.target_method` — the method
  full-signature placed on the bundle as `target_method`
  (`bundles.build_evidence_bundle`), surfaced to OPA as `input.target_method`.
- **Exact condition:** `contains(lower(input.target_method), "benchmarktest")`.
  OWASP Benchmark v1.2 names every test class `BenchmarkTestNNNNN`, so the
  predicate is true for every benchmark method and false for general code.
- **Minimal counterexample (proof from the Rego logic):** identical
  `new java.util.Random()` used outside a servlet context.
  - In `org.example.Foo.bar()` → `servlet_context` false, `benchmark_context`
    false → `random_context` false → `insecure_random` does **not** fire.
  - In `org.owasp.benchmark.testcode.BenchmarkTest00123.doPost(...)` →
    `benchmark_context` true → `random_context` true → `insecure_random` fires.
  The decision differs solely because of the class name. (Logical proof; the
  empirical run is BLOCKED.)
- **Affected family:** `ISO-A.10-WEAK-RANDOM` (CWE-330).
- **Canonical sampled cases exercising the condition:** BLOCKED (needs corpus +
  OPA to enumerate IDs).
- **Isolated removal commit:** done — `fix(policy): remove OWASP benchmark
  fingerprint…`. Guard test `tests/codegraph/policy/test_no_benchmark_fingerprint.py`.
- **Before/after weak-random deltas (TP/FP/FN, P/R/F1 by family + full 454):**
  BLOCKED (needs runner). Reproduce with:
  `OWASP_BENCHMARK_ROOT=… python run_benchmark_eval.py --config configs/benchmark/multicat_full.json --output-dir outputs/cmp_c1_after_<sha>`
  run once on the evidence tag and once on this branch; diff `metrics.json`.
  **Do not write into any `outputs/thesis_final_*` directory.**
- **Canonical artifacts:** NOT modified (verified — manifest unchanged).
- **`opa check` of the edited Rego:** BLOCKED (no binary). Edits are deletions of
  complete rules/clauses; syntactically low-risk but **must** pass `opa check`
  before merge.

## B. REM-F1/F2 — canonical remediation path trace

**Canonical run identity (recovered from `outputs/thesis_final_remediation_v4/provenance.json`):**
`mode: "dry_run"`, `sample_size: 60`, `seed: 11`, `max_attempts: 2`,
`reset_neo4j: true`, OPA `1.15.1`. So the canonical evidence **did** use the
dry_run path under audit.

**Path (files/symbols):**
`run_remediation_eval.py` (serial loop, `:211`) → `orchestration.apply_remediation(mode="dry_run")`
→ `service.RemediationService.apply_fix` → `apply_flow._execute_apply_fix_inner`:
1. candidate generation: `service.propose_method_edits` → `editing.apply_method_edits` → `updated_content`.
2. temp workspace + build: `apply_flow:313-316` (`TemporaryDirectory`, `_prepare_temp_workspace`,
   write patched temp file, `_compile_project` → `verification.compile_project`, `timeout=120`).
3. **graph mutation:** `apply_flow:323-324` `process_single_file_content(file_path, updated_content)`
   → `ingestion/service.py:798-810` = `_purge_file_entities` + `ingest_to_neo4j` (purge + re-ingest
   of the **patched** source into the **live** Neo4j graph).
4. **OPA re-eval:** `apply_flow:345-348` `PolicyEvaluator().evaluate(target_method,
   source_path_override=temp_file)` → `integration.PolicyEvaluator.evaluate:234-269` →
   `_fetch_method_snapshot(driver, …)` (reads the **mutated live graph**) →
   `build_evidence_bundle(snapshot, …, source_path_override=temp_file)` (source **text** from the
   patched temp file; graph_context calls/callers/annotations + line spans from the **mutated**
   snapshot).
5. classification: `build_verification_summary` (baseline vs after) → `remediation_runtime`
   `fully_verified := policy_fixed AND build_success`.
6. **restore:** `apply_flow:397-406` finally block re-ingests the **original** source (and restores
   the live file in apply mode) **after** the eval.

**Explicit answers:**
- *Does dry_run write to the live Neo4j graph?* **Yes** — purge + re-ingest of patched content.
- *Is the graph restored before verification?* **No** — restored *after*, in `finally`. Verification
  deliberately reads the mutated (patched) graph; that is how patched graph facts reach OPA.
- *Does OPA re-eval read source-derived facts, graph-derived facts, or both?* **Both** — source text
  from the override temp file; calls/callers/annotations/line-spans from the mutated live-graph snapshot.
- *Could any canonical case pass because of prior dry-run mutation?* Under the **serial** canonical run
  (`run_remediation_eval` is single-loop) with `reset_neo4j: true` and per-case
  mutate→eval→restore, each case verifies against **its own** patch's facts, not a prior case's.
  No path was found by which a *prior* case's mutation leaks into a later case's recorded verdict in
  serial execution. The residual hazards are (a) a crash between mutate and restore corrupting
  *subsequent* cases, and (b) concurrent evaluation — neither occurs in the canonical serial run.
- *Is the re-ingested graph "a clean representation of the patched source"?* **Yes** —
  `process_single_file_content` is a full purge + re-ingest, so the graph facts are exactly what a
  fresh ingest of the patched file would produce.
- *Rollback consistency (source/graph/status)?* dry_run never writes the live file; the graph is
  mutated then restored; with the REM-F9 fix a restore failure now downgrades status to
  `VERIFICATION_ERROR`, so a left-mutated state can no longer be reported as a clean success.

**Assessment / revised severity:** post-repair verification **is** evaluated against the patched
representation (both source and graph derive from the patch), **not** stale or prematurely-mutated
state, under the serial canonical run. The canonical fully-verified counts are therefore **not
invalidated** by REM-F1 on correctness grounds. REM-F1/F2 remain genuine defects — the
"graph remains untouched" docstring is false, and a naive F1 fix (stop mutating) would desynchronize
graph line-spans from the patched source (REM-F2) — but the correct rating is **High-priority
engineering hardening, not a falsification of the remediation evidence.** Recommended fix: verify the
candidate off the temp-file virtual bundle (as `preview_virtual_fix` already does via
`evaluate_bundle`) without touching Neo4j; that change needs its own before/after.
- *Instrumented trace / regression:* a true instrumented Neo4j trace is BLOCKED (no Neo4j here).
  Existing `tests/codegraph/remediation/test_apply_fix.py:139-145` already proves the
  mutate→eval→restore **ordering** (`reingest_calls == [(path, updated), (path, original)]`) and that
  the re-eval consumes the patched override (`temp_file_content == updated_content`).

## C. ING-C1 / ING-M7 impact analysis (no implementation — measurement first)

**ING-C1** — `codegraph/ingestion/service.py:33-49` `_infer_block_end_line`. Root cause: counts `{`/`}`
in raw line text including string/char/comment content. Real nested blocks (anonymous classes,
lambdas) are handled correctly — only braces inside literals/comments break it. Counterexamples:
1. `String s = "}";` — literal `}` closes the count early → truncated `end_line`.
2. `char c = '}';` — char-literal `}`.
3. `// done }` — line comment containing `}`.
4. `/* } */` — block comment containing `}`.
5. `String fmt = "{0}";` — literal `{` inflates the count → over-captured `end_line`.
6. `String s = "if (x) {";` — unbalanced `{` in a string.
- **Affected file/node counts across the 454-case sample:** BLOCKED (needs corpus).
- **Presentation-only vs detection-outcome:** a span error changes which lines populate `source_code`;
  detection changes only if the sink token falls outside the miscomputed span (Rego matches over the
  substring-safe view). Splitting the two requires running detection on the corpus — BLOCKED.

**ING-M7** — `service.py:277` `method_sig = f"{class_fqn}.{method_name}()"` (parameter-less) is the
MERGE key; `full_sig` (`:278`) carries params but the node MERGE and `CALLS`/`USES` edges key on the
bare signature. Collision: `void process(String)` and `void process(int)` → both `Foo.process()` →
last-write-wins single node, mis-attributed edges. `method_index` in `build_policy_input` keys on
`full_signature` (partial mitigation for bundle building). Whether any TP/FP/FN/remediation case
depends on a collision: BLOCKED (needs corpus). Likely consistent with the explicit selective-graph
claim; **defer/document** unless measurement shows an evidence impact. No parser redesign proposed.

## D. Validation gap (explicit)

- The branch is **not** fully validated: the authoritative OPA path did not execute here.
- **Skipped-test inventory by reason** (53 total; none mask a logic failure — all are external
  tool/corpus absence):
  - ~24 — `opa binary not found on PATH` (detection suites `test_crypto_detection`,
    `test_injection_detection` via the new `requires_opa` skip, plus `test_policy_contract_golden`).
  - ~13 — `opa CLI not installed` (`test_owasp_lexical_eval`, `test_lexical_noise_eval`).
  - 5 — `semgrep CLI not installed` (`tests/baselines/semgrep/…`).
  - 1 — `/tmp/owasp-benchmark is not a git repo`.
  - remainder — pre-existing Neo4j/other environment skips.
- **Run-when-runner-available:** full OPA-dependent suite, `make policy-check` (`opa check --strict` +
  `opa fmt`), under the pinned OPA 1.15.1. Confirm a timeout / bundle error / per-bundle failure is
  never counted as a clean negative or a silent denominator reduction:
  - timeout → `RuntimeError` (`opa.py`); in `PolicyEvaluator.evaluate` it returns
    `{"violations": [], "error": …}` and `apply_flow` maps a present `error` to `VERIFICATION_ERROR`
    (not a clean pass); in batch `evaluate_policies` it lands in `failed_bundles` (not zero-violation
    success).
  - **Residual (documented, not yet implemented):** the detection runner does not yet assert
    `failed_bundles == []` in thesis mode, so a per-bundle failure could still drop one method's
    violations from the population. Recommend a thesis-mode assertion mirroring EVAL-F5.
- **CI environmental evidence:** workflow run `27462785191`; `changes` job attempt 1
  (`81179599442`) and the re-run attempt 2 (`81179640926`) both failed in 2-3 s with
  `runner_id: 0` (no runner allocated, before checkout). Both 2026-06-08 dependabot PRs also failed;
  last green run was `main` on 2026-06-02. Conclusion: account-level GitHub Actions runner
  availability, independent of this branch.

## E. Historical evidence vs hardened implementation

**OPA versions:** canonical evidence (detection v2, remediation v3/v4 provenance) used **OPA 1.15.1**
(darwin/arm64, Rego v1). The repo previously pinned **1.14.1** (setup script) / unpinned `latest`
(Dockerfile, CI) — a mismatch. Now aligned to **v1.15.1** across Dockerfile, setup script, and CI,
pinned **by tag, not digest** (digest pin is a recommended follow-up). Provenance captures: git SHA +
branch + dirty flag, `config.sha256`, `uv_lock_sha256`, `pyproject_sha256`, `opa.raw`, `seed`, `llm`
block, redacted Neo4j URI, and (new) `ground_truth.sha256` + `ground_truth.corpus_git_sha`
(`ground_truth` was `null` in all pre-fix canonical manifests).

| Commit (subject) | Alters frozen artifact bytes | Can change future rerun output | Can change metric under normal success | Only failure/provenance/order | Requires artifact/thesis regen |
|---|---|---|---|---|---|
| docs(audit): report | no | no | no | n/a | no |
| fix(policy): OPA timeout + skip tests | no | only on hang/missing-binary | no | failure-handling | no |
| fix(ingestion): zip symlink/root hardening | no | yes (rejects malicious uploads) | no (OWASP detection unaffected) | upload behaviour | no |
| fix(ci): OPA pin v1.14.1 (superseded) | no | yes (pinned engine) | conditional | env | no |
| fix(policy): deterministic graph-context sort | no | yes (byte order) | no (detection invariant) | order-only | conditional (explanation card order) |
| fix(remediation): fail-closed gate + rollback downgrade | no | yes (apply-mode only) | no (dry_run benchmark unaffected) | failure-handling | no |
| fix(policy): batch per-bundle failures | no | only on failures | no (clean corpus identical) | failure-handling | no |
| feat(provenance): ground-truth + corpus hash | no | yes (adds fields) | no | provenance-only | no |
| test(eval): canonical tripwire + manifest | no | no | no | n/a (guard) | no |
| fix(ci): OPA align to v1.15.1 (canonical) | no | yes (matches canonical engine) | conditional (1.14→1.15 could shift policy; **aligns to** canonical) | env | no (aligns to canonical) |
| fix(policy): remove benchmark fingerprint (C1) | no | **yes** | **YES (weak-random)** | no | **YES — regenerate weak-random/detection** |
| feat(eval): require-complete-corpus guard (F5) | no | yes (fails fast on partial) | no (complete corpus identical) | failure-handling | no |
| refactor: streamline error msg + inline helper | no | no | no | n/a | no |

**Net:** existing canonical files remain unchanged and checksum-protected; the only commit that changes
metric outcomes under normal successful execution is **POLICY-C1** (and the OPA 1.15.1 alignment, which
moves the runtime *toward* the canonical-evidence engine). The branch is therefore behaviourally
distinct from the evidence-tag implementation, which is acceptable provided both baselines are named —
the evidence tag for the frozen numbers, this branch for the hardened re-run path.

---

# Appendix — Live OPA validation (2026-06-14)

OPA `1.15.1` (the canonical-evidence version) was installed from the pinned
GitHub release (`releases/download/v1.15.1/opa_linux_amd64_static`; the
`/downloads/latest` redirect 403s but the pinned URL works) and the full OWASP
BenchmarkJava corpus was cloned (commit `278105dcd6cba9f851806d9578984243e1cfd527`,
2740 testcases + `expectedresults-1.2.csv`). This unblocks the items previously
marked BLOCKED.

## Authoritative policy path — validated live
- `opa check --strict policy/` → **PASS** (the POLICY-C1 Rego edit compiles).
- `opa fmt -d policy/` → **no diff** (`make policy-check` would pass).
- Full suite with OPA on PATH → **692 passed, 27 skipped, 0 failed** (the 24+
  previously-skipped OPA detection tests now execute and pass, including the
  crypto/injection detection suites with the fingerprint removed).
- No test depends on the benchmark fingerprint (grep + green suite).

## POLICY-C1 — empirical A/B on the weak-random family (resolves the C1 blocker)
Method: for every `weakrand` (CWE-330) testcase in `expectedresults-1.2.csv`,
build the production-wiring minimal bundle (`_build_minimal_bundle`,
`f10_active=True`) and evaluate `ISO-A.10-WEAK-RANDOM` under (A) the current
policy (fingerprint removed) and (B) a temp copy with `benchmark_context` and its
`random_context` clause restored (pre-C1 state). `benchmark_context` only ever
gated `insecure_random`, so weak-random is the **complete** affected population.

| Policy variant | TP | FP | FN | TN | P | R | F1 |
|---|---|---|---|---|---|---|---|
| A — fingerprint removed (branch) | 218 | 0 | 0 | 275 | 1.000 | 1.000 | 1.000 |
| B — fingerprint restored (pre-C1) | 218 | 0 | 0 | 275 | 1.000 | 1.000 | 1.000 |

**Decisions that differ: 0 of 493.** Every OWASP testcase is a
`doPost(HttpServletRequest …)` servlet, so `servlet_context` is always satisfied
and `benchmark_context` was redundant. **POLICY-C1 removal is empirically
metric-neutral on the OWASP Benchmark corpus** — the fingerprint is a real
construct-validity smell (it would leak on a non-servlet corpus) but does not
change any canonical detection number, so **no canonical regeneration is required**.

Caveat: this uses the file-level minimal-bundle path (no Neo4j graph context).
The `random_context` gate depends only on `servlet_context`/`benchmark_context`,
both derived from `target_method`/`source_code`, which are identical in both
pipelines; the full graph pipeline can *additionally* satisfy `servlet_context`
via endpoint annotations, so it is at least as neutral. A full graph-pipeline
A/B (needs Neo4j) would confirm, but the gate logic makes the result determinate.

## Still pending a Neo4j-equipped runner
The full graph-pipeline detection eval (`run_benchmark_eval.py`) and the
remediation re-eval both require Neo4j, which is not available in this sandbox.
The ING-C1/ING-M7 per-case corpus counts likewise need the full ingest pipeline.

---

# Appendix — Live Neo4j graph-pipeline verification (2026-06-15)

Neo4j 5.26.20 (Docker) was brought up alongside OPA 1.15.1 + the OWASP corpus,
closing the previously-BLOCKED graph-pipeline items.

## Full-pipeline detection (ingest → Neo4j → OPA → metrics)
- Pipeline runs end-to-end. Baseline smoke: Crypto P=1.0/R=0.875, Hash
  P=1.0/R=0.79, overall FP=0.
- **POLICY-C1 confirmed metric-neutral in the real graph pipeline** (not just the
  file-level path): weak-random A/B with the fingerprint removed vs restored is
  **identical — TP=218, FP=0, FN=0, P=R=F1=1.000 both ways**, matching the canonical
  `thesis_final_detection_full_v2` weak-random number.
- The sentence-transformer/embedding model was HTTP-403 blocked for the entire
  run, yet detection completed with perfect metrics — a live demonstration that
  **FAISS/vector retrieval is not in the authoritative detection path**.

## REM-F1/F2 — instrumented dry_run trace against the live graph
Replaying `apply_flow`'s exact dry_run sequence on a real ingested MD5 case
(BenchmarkTest00046), querying the Neo4j method node and re-evaluating at each step:

| Question | Result | Evidence |
|---|---|---|
| dry_run mutates the live graph? | **YES** | method `end_line` shifted 97→98 after the patched re-ingest |
| graph restored after eval? | **YES** | reverted 98→97 after rollback |
| verification reflects the patched state (not stale)? | **YES** | baseline weak-hash fires → after-patch does not |
| serial-safe (next case sees clean baseline)? | **YES** | post-restore weak-hash fires again |

**Conclusion (confirms the REM-F1/F2 write-up):** the live-graph mutation is real
(so the old "graph untouched" docstring was false — now corrected in
`service.py`), but under the serial canonical run the post-repair verification is
evaluated against the patched representation and the graph is restored, so the
canonical fully-verified counts are **not invalidated**. The residual risk is the
crash/concurrency window between mutate and restore (out of scope for the serial
benchmark; recommended hardening: verify off the temp-file virtual bundle without
touching Neo4j, as `preview_virtual_fix` already does).

---

# Appendix — Full multi-category detection reproduction (2026-06-15)

Ran the canonical detection config (`configs/benchmark/multicat_full.json`, 8
categories × 60, seed 7) on this branch with the real Neo4j + OPA 1.15.1 stack and
compared against the committed `outputs/thesis_final_detection_full_v2/metrics.json`.

| Overall | TP | FP | FN | P | R | F1 | support |
|---|---|---|---|---|---|---|---|
| Canonical (committed) | 222 | 11 | 11 | 0.9528 | 0.9528 | 0.9528 | 454 |
| This branch (all changes) | 222 | 11 | 11 | 0.9528 | 0.9528 | 0.9528 | 454 |

**Bit-for-bit identical**, including per-category (Randomness 32/0/0 = 1.000 with the
fingerprint removed). Every change in this PR preserves the thesis headline
detection metric. The embedding model was 403-blocked throughout, again confirming
FAISS/vector is not in the detection path.

## Remediation loop (live, real Neo4j + OPA)
- The apply/verify/re-evaluate orchestration runs end-to-end.
- The conservative gate held in every probe: a partial/failed patch never produced
  a verified result — any reconstruction/parse hiccup yields `VERIFICATION_ERROR`,
  not success (`fully_verified := policy_fixed AND build_success`, no fallback).
- The policy re-evaluation gate clearing a *real* fix is demonstrated in the
  REM-F1/F2 trace above (baseline weak-hash fires → patched override clears).
  Detection reads method **source text** from the file/override (not the graph),
  so candidate verification must supply the patched override — which dry_run does.
