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
