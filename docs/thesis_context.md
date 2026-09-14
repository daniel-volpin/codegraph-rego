# Thesis Context

## Thesis
- Title: `Operationalizing Security Policies: Graph-Based Code Understanding and LLM-Driven Compliance Enforcement`
- Project goal: build a neurosymbolic compliance workflow that translates security controls into executable checks, grounds findings in graph-structured code evidence, and uses LLMs for explanations and remediation.

## What This Repo Is Trying To Prove
- Natural-language security requirements can be operationalized into machine-actionable policy checks.
- Graph-based code understanding is useful as an evidence layer for policy evaluation and retrieval.
- LLMs are most useful after symbolic evidence retrieval, not as standalone detectors.
- The full workflow is:
  1. ingest JVM code into Neo4j
  2. evaluate controls with OPA/Rego
  3. generate grounded explanations
  4. attempt remediation
  5. re-verify in a fix-and-scan loop

## Scope
- Main implementation target: JVM microservices, especially Java/Spring style codebases.
- Main benchmark/evaluation target and primary demo substrate: OWASP Benchmark.
- Core evaluated categories currently include weak crypto/hash, insecure randomness, SQL injection, path traversal, command injection, LDAP injection, and XPath injection checks.
- Realistic sample apps such as Spring PetClinic and gs-securing-web are secondary qualitative case studies for upload/search/policy browsing, not the primary remediation evidence surface.

## Important Thesis Framing
- Prefer the phrase `graph-based code understanding` or `graph-structured evidence`.
- Do not overclaim full Code Property Graph / control-flow / data-dependency support unless it is explicitly implemented and verified.
- The strongest thesis contribution is the integrated compliance workflow, not just one isolated model or one isolated detector.

## Graph Scope and Approximation Disclosures
- The Neo4j graph contains four node labels (`Class`, `Method`, `Field`,
  `Annotation`) and the following relationship types: `CALLS`, `ANNOTATED_WITH`, `USES`, `DECLARES`, `DECLARES_FIELD`, `EXTENDS`, `IMPLEMENTS`, `DEPENDS_ON`, `NESTED_IN`. There are no AST-level, parameter-binding, or value-flow nodes.
- "Taint" in this project means **intra-file dataflow taint analysis** performed by the OpenGrep engine (`codegraph/policy/opengrep_bridge.py`, the only registered non-OPA engine in `codegraph/policy/engines.py`), which propagates taint interprocedurally within a compilation unit and reports the flow as SARIF `codeFlows`. It replaced a bounded BFS over `CALLS` edges with regex sink matching, which could not distinguish a value that reaches a sink from one that is discarded and replaced by a literal first. Two limits are documented scope rather than defects: taint is **not propagated across file boundaries**, so a flow reaching a sink through a helper in another compilation unit is missed, and container tracking is **index-insensitive**, so an element added to a collection and later replaced is still treated as tainted. These account for most residual false negatives in the injection families. See `docs/architecture/2026-09-12-detection-engine-plugin-contract.md`, and `2026-09-13-cpg-engine-evaluation.md` for the cross-file engine that was measured and rejected.
- Several Rego heuristics use case-insensitive `contains()` over a deterministic
  lexical view. `source_code_substring_safe` blanks comments and literals, while `source_code_active` blanks comments but preserves literals for rules that must inspect algorithm names or query strings. This is lexical anchoring, not value-flow analysis; describe the selected view when reporting detection behavior.

## Ablation Semantics (Citation@Context vs Citation@NoContext)
- Both modes share the same violation set and the same expected citation
  string (`format_citation(file_path, start_line, end_line)`).
- `with_context` provides the model with the evidence cards (E1/E2/E3),
  graph context (annotations, calls, callers), and vector context (FAISS neighbours). Citation IDs are constrained to an enum of card IDs, so the model cannot invent a citation; the citation text is then resolved server side from the chosen card.
- `without_context` zeros the evidence cards, the graph context, and the
  vector context. The schema for that mode requires a literal citation string (no enum). The violation's `file_path` and line range remain visible to the prompt assembly machinery via `build_expected_citation`, but the evidence cards themselves are absent.
- `Citation@NoContext = 0.000` therefore measures the model's behavior under
  the **stricter, no-card schema** with zeroed graph + vector context. It is not a test of whether the model could regurgitate a path it has never seen. Document this distinction in the thesis methodology section.
- Earlier revisions of the explanation eval measured citation grounding
  only on positive predictions, while the detection eval scored every selected case. The current explanation eval evaluates **two cohorts** per category:
  - **TP cohort** (`Citation@TP`): violations on positive testcases.
    This is the legacy `Citation@Context` metric, renamed for clarity.
  - **FP cohort** (`Citation@FP`): violations on benign testcases — i.e.
    citation grounding on the detector's false positives.
  Legacy artifact fields (top-level `count` / `with_context` / `rate_with_context` / etc.) remain populated and alias the TP cohort, so existing downstream tooling keeps working. The new `tp.*` and `fp.*` blocks (with Wilson 95% CIs on each rate) are additive.

## Calibration Populations

The remediation calibration is reported over three populations so reviewers can separate "calibrated success probability" from "knew-when-to-abstain":

- `full` — every result with a confidence score, including `NO_FIX`
  abstentions. Matches the v1/v2 headline; remains the legacy top-level Brier/ECE.
- `attempted_only` — results where the system actually tried to apply
  a remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR / BUILD_ERROR / VERIFICATION_ERROR). The right number when arguing that confidence predicts fix success.
- `no_fix_only` — declared abstentions (status NO_FIX). Low confidence
  on these cases is well-calibrated abstention, not failure.

Cite the population explicitly when quoting Brier/ECE; do not use the legacy top-level number without naming the population it refers to.

## Uncertainty Quantification

`codegraph/evaluation/uncertainty.py` provides:

- `wilson_score_ci(successes, trials, confidence=0.95)` — closed-form
  binomial proportion CI. Used for precision, recall, and `Citation@*` rates.
- `bootstrap_prf_ci(outcomes, n_resamples=2000, confidence=0.95, seed=...)` —
  percentile bootstrap over per-testcase `(predicted, label)` outcomes. Returns `precision`, `recall`, `f1` intervals computed from the same resamples (deterministic given the seed).

The detection eval emits both Wilson and bootstrap CIs; the explanation eval emits Wilson CIs (each rate is a binomial proportion). Cite the CI alongside the point estimate; for per-category numbers (n=60) the intervals are informative, not cosmetic.

## Provenance Manifest

Every eval run writes a `provenance.json` next to its other artifacts (see `codegraph/evaluation/provenance.py`). It records:

- `git`: SHA, branch, dirty flag, last commit subject
- `python`, `platform`, `package_version`
- `opa.raw` (output of `opa version`)
- `neo4j.uri` with credentials redacted
- `config.path` + `config.sha256`
- `ground_truth.path`, `ground_truth.sha256`, and
  `ground_truth.corpus_git_sha` when a benchmark ground-truth file is provided
- `uv_lock_sha256`, `pyproject_sha256`
- `seed`
- `llm` block (model, temperature, max_tokens) when applicable

Schema v2 records repository- and corpus-relative paths where possible and otherwise retains only the final path component, including path-like fields inside `extra`. This keeps new manifests portable and avoids publishing local machine prefixes. Historical canonical manifests remain unchanged as part of the thesis evidence record.

Cite the artifact directory **plus the SHA recorded in `provenance.json`** when referring to canonical numbers. v1 numbers are addressable via the `thesis-evidence-2026-05-31-source` git tag.

A composed detection directory carries no `provenance.json` of its own. `compose_benchmark_eval.py` records `composed_from` in `metrics.json`, and each per-group directory it names carries the provenance; cite those. For `outputs/2026-09-14-detection-full/detection_composed/` the eight group runs all record SHA `1dd1510` with `dirty: false`, a commit on `main`, so the figure is pinned to a clean named revision.

Recorded SHAs are feature-branch commits and this repository squash-merges, so none of them is an ancestor of `main`. Each is therefore held by an annotated tag: `thesis-detection-v2-source` (`7ad90a2`, also the source of remediation v3), `thesis-explanation-v2-source` (`701d051`), `thesis-remediation-v4-source` (`80d0084`), and `thesis-detection-baseline-2026-09-13-source` (`6aa9026`). Without them, three were reachable from no ref and the fourth only from a feature branch, so none would have survived a fresh clone.

Canonical thesis outputs that are intentionally versioned under `outputs/thesis_final_*` are protected by `outputs/canonical_manifest.sha256`. If a metric-affecting rerun is deliberate, regenerate the manifest with `scripts/evaluation/generate_canonical_manifest.py` and commit the updated artifacts and manifest together. Do not update the manifest for incidental local reruns.

Canonical thesis runs:

- detection v2: `outputs/thesis_final_detection_full_v2/`, provenance
  SHA `7ad90a2`, precision/recall/F1 all `0.9528` with bootstrap 95% CIs. **Do not cite this figure without the qualification below.**

  At SHA `7ad90a2` the authoritative Rego layer still contained the OWASP-Benchmark class-name fingerprint later removed by audit POLICY-C1: `benchmark_context` matched `contains(lower(target_method), "benchmarktest")` and gated `random_context` in `policy/iso_27001_crypto.rego`, so weak-random detection depended on the corpus naming convention rather than on the code under analysis. `tests/codegraph/policy/test_no_benchmark_fingerprint.py` now prevents reintroduction. The recorded `rng-insecure` precision of `1.000` is attributable in part to that fingerprint; post-removal runs score `0.889` on the same sample.

  The figure is also not reproducible on the current source baseline under its own matched configuration (`multicat_full.json`, 60 cases/category, seed 7). Measured on that identical configuration:

  | Engine | Precision | Recall | F1 |
  | --- | --- | --- | --- |
  | Rego lexical heuristics (pre-OpenGrep `main`) | 0.712 | 0.901 | 0.795 |
  | OpenGrep taint analysis | 0.793 | 0.888 | 0.838 |
  | Recorded detection v2 (SHA `7ad90a2`) | 0.953 | 0.953 | 0.953 |

  Crypto and hash reproduced bit-identically across all three rows, which pinned the harness and sample and confined the divergence to the taint-dependent controls. That no longer holds after configuration-backed detection: those two categories now decide on the algorithm declared in the workspace's properties files and reach `1.000` on both, so they are no longer the invariant control. The taint-dependent controls have taken that role, reproducing exactly across the configuration change. For external context, published OWASP Benchmark v1.2 figures put CodeQL near `0.744` F1 and Semgrep near `0.694`, so treat any result materially above that range as requiring construct-validity scrutiny rather than as a target.
- detection, configuration-backed (current):
  `outputs/2026-09-14-detection-full/detection_composed/`, full corpus of 2092 cases composed from eight per-group runs: precision `0.7966`, recall `0.9324`, F1 `0.8591` (`TP/FP/FN = 979/250/71`). Crypto (CWE-327) and hash (CWE-328) reach precision, recall and F1 of `1.000` (`130/0/0` and `129/0/0`); every other category reproduces its prior figures exactly, and false positives do not increase.

  All 73 crypto and hash false negatives in the preceding baseline selected their algorithm from a properties file rather than a literal, so they were unreachable by API or alias patterns. The in-source defaults mislead in both directions, and deciding on them would have produced 40 false negatives and 27 false positives at once. See `docs/architecture/2026-09-13-configuration-facts.md`.

  Two claim limits belong with this figure. First, it means **the configured value is unsafe**, not that a deployed system is vulnerable: environment variables, system properties and profile overlays can override a declared value at runtime. Second, the per-category gain (+73 true positives) exceeds the Overall gain (+48) because the Overall row is union any-rule, so 25 recovered cases were already counted through an off-target rule from another family; do not add the category rows.

  These controls are detection-only. A remediation recheck cannot reproduce configuration evidence from a virtual candidate snapshot, so it refuses rather than reporting a candidate as fixed.
- explanation v2: `outputs/thesis_final_explanation_full_v2/`,
  provenance SHA `701d051`, `Citation@TP=1.000` (`222/222`), `Citation@TP@NoContext=0.009` (`2/222`), `Citation@FP=1.000` (`9/9`), `Citation@FP@NoContext=0.000` (`0/9`).
- remediation v2: `outputs/thesis_final_remediation_v2/`, the full per-case
  evidence bundle: 25 case directories and `results.jsonl` alongside the metrics. It records the same outcome as v4, fully verified `1.00` (`25/25`), and carries no `provenance.json`, so v4 is the anchor to cite when a recorded commit is needed. All 181 files are protected by `outputs/canonical_manifest.sha256`.
- remediation v3: `outputs/thesis_final_remediation_v3/`, provenance
  SHA `7ad90a2`, fully verified success rate `0.72` (`18/25`), attempted-only calibration Brier `0.094698` / ECE `0.083900`.
- remediation v4: `outputs/thesis_final_remediation_v4/`, provenance
  SHA `80d0084`, fully verified success rate `1.00` (`25/25`), Brier `0.005723` / ECE `0.069612`.

## Remediation IR (`RepairIntent`)

`codegraph/remediation/repair_intent.py` defines a typed intermediate representation for bounded JVM security repairs. It is the backbone of the **deterministic-vs-LLM remediation comparison harness**. `comparison.py:144` consumes a `RepairIntent` via `compile_repair_intent` (from `patch_compiler.py`), and `run_comparison_eval.py` drives this end-to-end as a separate evaluation surface from the live `run_remediation_eval.py` flow.

Practical implications for the thesis:

- Frame `RepairIntent` as *"a typed IR that lets the deterministic
  comparison harness emit the exact same patch shape as the LLM-driven pipeline, so the two can be evaluated head-to-head."* That sentence is true today; "the system uses an IR-based repair planner in production" is not.
- The production live path (`apply_flow.py → service.propose_method_edits`)
  goes LLM-output → structured edit dicts → `editing.apply_method_edits` directly. The IR is not part of this live path.
- Keep `repair_intent.py` and `patch_compiler.py` as comparison-eval
  infrastructure. Removing them would delete a non-trivial chunk of the comparison-eval surface that `run_comparison_eval.py` depends on.

## Control ID Conventions

`policy/catalog.json` lists each control under a single canonical `id` of the form `ISO-A.<clause>` (for example `ISO-A.9.4.1`, `ISO-A.10-WEAK-HASH`). New code, tests, configs, and prose should use this short form exclusively.

The longer `ISO-27001-<clause>` form survives only inside the `alias_ids` arrays of `policy/catalog.json` and `configs/benchmark/policy_registry.json`, and is resolved at runtime by `codegraph/policy/runtime/catalog.py::violation_id_variants` and `codegraph/remediation/capabilities.py`. It exists exclusively for backward compatibility with pre-existing artifacts and external clients that may have stored the long form. Treat it as deprecated:

- Do not introduce new `ISO-27001-…` references in code, tests,
  configs, dashboards, frontend, or thesis prose.
- Do not delete `alias_ids` from the catalogs without a deprecation
  cycle that includes a runtime warning and an audit of every downstream artifact.

When citing a control in the thesis, use the short canonical form.

## Current System Design
- Symbolic layer:
  - Java parsing + graph ingestion into Neo4j
  - policy evaluation with OPA/Rego
- Neural layer:
  - LLM explanations over retrieved evidence
  - remediation proposals in a guarded apply/verify loop
- Retrieval layer:
  - graph evidence from Neo4j
  - optional vector/FAISS support where useful

## Current Validated Explanation-Eval Setup
- Preferred evaluation configuration:
  - `evidence_mode=lean`
  - `llm_max_tokens_eval=192`
  - `LLM_CONCURRENCY=1`
  - structured output enabled for explanation evaluation
- Important recent finding:
  - plain-text prompting led to poor citation compliance and `Thinking Process` leakage
  - structured JSON-schema output materially improved explanation citation quality
  - explicit stop sequences for local Qwen/LM Studio requests were added to stop repeated `<|im_end|>` token spam

## Maintenance Invariants
- Keep evaluation changes isolated from remediation unless there is a clear reason to couple them.
- Keep explanation-eval optimizations measurable:
  - compare throughput
  - compare citation quality
  - do not accept speedups that materially degrade quality
- Prefer minimal, standards-based fixes over local hacks.
- Preserve reproducibility:
  - separate output directories per evaluation run
  - keep metrics artifacts
  - avoid overwriting baseline runs

## Practical Evaluation Guidance
- Detection benchmark is the foundation.
- Explanation evaluation should measure grounded citations, not generic prose quality.
- Remediation should be judged by fix success and re-verification, not only by patch appearance.
- Benchmark-centered live demos should show both:
  - bounded success on full-support categories
  - explicit safe refusal on guarded categories when the evidence is insufficient
  - explanation/manual-review coverage across multiple non-remediated benchmark families
- If a local LLM behaves badly, first look at:
  - output contract
  - stop behavior
  - token budget
  - prompt size
  - concurrency

## Current Implementation Status
- Performance bottlenecks were already reduced substantially in ingestion and evaluation orchestration.
- Explanation evaluation now has:
  - live progress reporting
  - partial metrics
  - request-level telemetry
  - structured explanation output
- Before changing evaluation behavior again, check whether the change helps both:
  - throughput
  - citation/grounding quality

## Read Together With
- [repository layout and boundaries](./architecture/repo-layout.md)
- [benchmark context and claim guardrails](./benchmark_context.md)
- [remediation prompting design](./remediation_prompting_design.md)
