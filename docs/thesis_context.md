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
- Realistic sample apps such as JHipster are secondary qualitative case studies for upload/search/policy browsing, not the primary remediation evidence surface.

## Important Thesis Framing
- Prefer the phrase `graph-based code understanding` or `graph-structured evidence`.
- Do not overclaim full Code Property Graph / control-flow / data-dependency support unless it is explicitly implemented and verified.
- The strongest thesis contribution is the integrated compliance workflow, not just one isolated model or one isolated detector.

## Graph Scope and Approximation Disclosures
- The Neo4j graph contains four node labels (`Class`, `Method`, `Field`,
  `Annotation`) and the following relationship types: `CALLS`, `ANNOTATED_WITH`,
  `USES`, `DECLARES`, `DECLARES_FIELD`, `EXTENDS`, `IMPLEMENTS`, `DEPENDS_ON`,
  `NESTED_IN`. There are no AST-level, parameter-binding, or value-flow nodes.
- "Taint" in this project means a bounded, conservative BFS over `CALLS` edges
  (`codegraph/policy/taint_graph.py`), with `max_depth=4` and regex-based sink
  matching at each hop. This is an **approximation, not formal taint analysis**.
  It is sound by construction (visited set prevents loops) but incomplete: any
  data flow that bypasses the call graph (e.g. through a primitive type passed
  via a method we did not analyse) is missed.
- Several Rego heuristics use case-insensitive `contains()` over the raw
  source string. They do not strip comments or string literals. Be explicit
  about this whenever describing detection behavior.

## Ablation Semantics (Citation@Context vs Citation@NoContext)
- Both modes share the same violation set and the same expected citation
  string (`format_citation(file_path, start_line, end_line)`).
- `with_context` provides the model with the evidence cards (E1/E2/E3),
  graph context (annotations, calls, callers), and vector context (FAISS
  neighbours). Citation IDs are constrained to an enum of card IDs, so the
  model cannot invent a citation; the citation text is then resolved server
  side from the chosen card.
- `without_context` zeros the evidence cards, the graph context, and the
  vector context. The schema for that mode requires a literal citation
  string (no enum). The violation's `file_path` and line range remain visible
  to the prompt assembly machinery via `build_expected_citation`, but the
  evidence cards themselves are absent.
- `Citation@NoContext = 0.000` therefore measures the model's behavior under
  the **stricter, no-card schema** with zeroed graph + vector context. It is
  not a test of whether the model could regurgitate a path it has never seen.
  Document this distinction in the thesis methodology section.
- Earlier revisions of the explanation eval measured citation grounding
  only on positive predictions, while the detection eval scored every
  selected case. The current explanation eval evaluates **two cohorts**
  per category:
  - **TP cohort** (`Citation@TP`): violations on positive testcases.
    This is the legacy `Citation@Context` metric, renamed for clarity.
  - **FP cohort** (`Citation@FP`): violations on benign testcases — i.e.
    citation grounding on the detector's false positives.
  Legacy artifact fields (top-level `count` / `with_context` /
  `rate_with_context` / etc.) remain populated and alias the TP cohort,
  so existing downstream tooling keeps working. The new `tp.*` and
  `fp.*` blocks (with Wilson 95% CIs on each rate) are additive.

## Calibration Populations

The remediation calibration is reported over three populations so
reviewers can separate "calibrated success probability" from
"knew-when-to-abstain":

- `full` — every result with a confidence score, including `NO_FIX`
  abstentions. Matches the v1/v2 headline; remains the legacy
  top-level Brier/ECE.
- `attempted_only` — results where the system actually tried to apply
  a remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR /
  BUILD_ERROR / VERIFICATION_ERROR). The right number when arguing
  that confidence predicts fix success.
- `no_fix_only` — declared abstentions (status NO_FIX). Low confidence
  on these cases is well-calibrated abstention, not failure.

Cite the population explicitly when quoting Brier/ECE; do not use the
legacy top-level number without naming the population it refers to.

## Uncertainty Quantification

`codegraph/evaluation/uncertainty.py` provides:

- `wilson_score_ci(successes, trials, confidence=0.95)` — closed-form
  binomial proportion CI. Used for precision, recall, and
  `Citation@*` rates.
- `bootstrap_prf_ci(outcomes, n_resamples=2000, confidence=0.95, seed=...)` —
  percentile bootstrap over per-testcase `(predicted, label)` outcomes.
  Returns `precision`, `recall`, `f1` intervals computed from the same
  resamples (deterministic given the seed).

The detection eval emits both Wilson and bootstrap CIs; the explanation
eval emits Wilson CIs (each rate is a binomial proportion). Cite the CI
alongside the point estimate; for per-category numbers (n=60) the
intervals are informative, not cosmetic.

## Provenance Manifest

Every eval run writes a `provenance.json` next to its other artifacts
(see `codegraph/evaluation/provenance.py`). It records:

- `git`: SHA, branch, dirty flag, last commit subject
- `python`, `platform`, `package_version`
- `opa.raw` (output of `opa version`)
- `neo4j.uri` with credentials redacted
- `config.path` + `config.sha256`
- `uv_lock_sha256`, `pyproject_sha256`
- `seed`
- `llm` block (model, temperature, max_tokens) when applicable

Cite the artifact directory **plus the SHA recorded in
`provenance.json`** when referring to v2/v3 numbers. v1 numbers are
addressable via the `thesis-final-v1` git tag.

Latest PR #107 reruns (2026-05-03):

- detection v2: `outputs/thesis_final_detection_full_v2/`, provenance
  SHA `7ad90a2`, precision/recall/F1 all `0.9528` with bootstrap 95%
  CIs.
- explanation v2: `outputs/thesis_final_explanation_full_v2/`,
  provenance SHA `701d051`, `Citation@TP=1.000` (`222/222`),
  `Citation@TP@NoContext=0.009` (`2/222`), `Citation@FP=1.000`
  (`9/9`), `Citation@FP@NoContext=0.000` (`0/9`).
- remediation v3: `outputs/thesis_final_remediation_v3/`, provenance
  SHA `7ad90a2`, fully verified success rate `0.72` (`18/25`),
  attempted-only calibration Brier `0.094698` / ECE `0.083900`.

## Remediation IR (`RepairIntent`)

`codegraph/remediation/repair_intent.py` defines a typed intermediate
representation for bounded JVM security repairs. Its own header
self-describes the module as *"shadow-mode only"* with respect to the
production remediation pipeline (`apply_flow.py` does not call
`plan_repair_intent`), and an earlier draft of this review framed the
module as dead code. That framing was wrong.

The IR is not dead: it is the backbone of the **deterministic-vs-LLM
remediation comparison harness**. `comparison.py:144` consumes a
`RepairIntent` via `compile_repair_intent` (from `patch_compiler.py`),
and `run_comparison_eval.py` drives this end-to-end as a separate
evaluation surface from the live `run_remediation_eval.py` flow.

Practical implications for the thesis:

- Frame `RepairIntent` as *"a typed IR that lets the deterministic
  comparison harness emit the exact same patch shape as the LLM-driven
  pipeline, so the two can be evaluated head-to-head."* That sentence
  is true today; "the system uses an IR-based repair planner in
  production" is not.
- The production live path (`apply_flow.py → service.propose_method_edits`)
  goes LLM-output → structured edit dicts → `editing.apply_method_edits`
  directly. The IR is not yet on this path; deciding whether to
  promote it onto the live path is a design choice for a future PR,
  not a clean-up item for this one.
- Keep `repair_intent.py` and `patch_compiler.py` as comparison-eval
  infrastructure. Removing them would delete a non-trivial chunk of the
  comparison-eval surface that `run_comparison_eval.py` depends on.

## Control ID Conventions

`policy/catalog.json` lists each control under a single canonical `id`
of the form `ISO-A.<clause>` (for example `ISO-A.9.4.1`,
`ISO-A.10-WEAK-HASH`). New code, tests, configs, and prose should use
this short form exclusively.

The longer `ISO-27001-<clause>` form survives only inside the
`alias_ids` arrays of `policy/catalog.json` and
`configs/benchmark/policy_registry.json`, and is resolved at runtime by
`codegraph/policy/runtime/catalog.py::violation_id_variants` and
`codegraph/remediation/capabilities.py`. It exists exclusively for
backward compatibility with pre-existing artifacts and external clients
that may have stored the long form. Treat it as deprecated:

- Do not introduce new `ISO-27001-…` references in code, tests,
  configs, dashboards, frontend, or thesis prose.
- Do not delete `alias_ids` from the catalogs without a deprecation
  cycle that includes a runtime warning and an audit of every
  downstream artifact.

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

## What Future Agents Should Preserve
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

## Current State Of The Branch
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
- [architecture overview](./../copilot-context/architecture.md)
- [remediation prompting design](./remediation_prompting_design.md)
