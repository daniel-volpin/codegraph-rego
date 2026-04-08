# 04 — Thesis Claims vs. Repo Evidence

This document maps each potential thesis claim to concrete repo evidence, assesses support strength, and provides recommended thesis wording.

---

## Claim 1: System Identity

**Claim:** CodeGraph is a neurosymbolic framework for operationalizing security policies over JVM codebases.

**Repo evidence:**
- Symbolic layer: Rego rules (`policy/*.rego`), OPA subprocess evaluation (`codegraph/policy/runtime/opa.py`), graph queries to Neo4j.
- Neural layer: LLM explanations (`codegraph/llm/`), LLM remediation generation (`codegraph/remediation/service.py`).
- Integration: The pipeline is Rego-first, LLM-second — the LLM never makes detection decisions.

**Support:** **Strong**

**Caveat:** "Neurosymbolic" is accurate only if the thesis clearly defines the term as: symbolic detection + neural explanation/remediation, not as a neural-symbolic joint reasoning model.

**Recommended wording:** "CodeGraph is a neurosymbolic framework that combines symbolic policy evaluation (OPA/Rego over graph-structured code evidence) with LLM-assisted explanation and bounded remediation."

---

## Claim 2: Graph-Backed Code Analysis

**Claim:** CodeGraph uses graph-based code understanding for evidence-backed policy evaluation.

**Repo evidence:**
- `codegraph/ingestion/service.py` ingests Java source into Neo4j with Class, Method, Field nodes and CONTAINS, CALLS, IMPLEMENTS, EXTENDS, USES_FIELD edges.
- `codegraph/policy/runtime/bundles.py` queries the graph for method context.
- `codegraph/policy/taint_graph.py` performs BFS over CALLS edges.
- `codegraph/search/` provides graph-based search.

**Support:** **Strong**

**Caveat:** This is NOT a Code Property Graph (CPG) in the academic sense. There are no control-flow edges, no data-dependency edges, no intra-procedural flow analysis. The graph is a selective structural extraction.

**Recommended wording:** "CodeGraph constructs a selective code graph in Neo4j capturing class hierarchies, method call relationships, field usage, and annotations. This graph serves as the primary evidence substrate for policy evaluation and multi-hop reachability analysis."

**Do NOT say:** "Code Property Graph", "CPG", "control-flow graph", "data-dependency graph", "inter-procedural data-flow analysis".

---

## Claim 3: OPA/Rego Policy Evaluation

**Claim:** Natural-language security requirements are translated into machine-actionable Rego policies evaluated by OPA.

**Repo evidence:**
- 10 controls in `policy/catalog.json` mapped to 3 Rego modules.
- `policy/iso_27001_crypto.rego` covers CWE-327, 328, 330.
- `policy/iso_27001_injection.rego` covers CWE-89, 22, 78, 90, 643.
- `policy/iso_27001_access.rego` covers access control and logging.
- OPA evaluation via subprocess in `codegraph/policy/runtime/opa.py`.
- Evidence bundles assembled from graph + source analysis in `codegraph/policy/runtime/bundles.py`.

**Support:** **Strong**

**Caveat:** The "translation" from natural language to Rego is manual, done by the developer. The system does not automatically translate requirements. The Rego rules are hand-written encodings of ISO 27001 control intent.

**Recommended wording:** "We manually operationalize selected ISO 27001 security controls as Rego policy rules evaluated by OPA against graph-structured code evidence. The current catalog covers 10 controls across 8 CWE categories."

---

## Claim 4: Benchmark-Backed Detection

**Claim:** The detection pipeline achieves F1=0.953 on OWASP Benchmark v1.2.

**Repo evidence:**
- `outputs/thesis_final_detection_full/metrics.json`: P=0.9528, R=0.9528, F1=0.9528.
- 454 cases evaluated across 8 CWE categories.
- Deterministic (no LLM), reproducible with `--reset-neo4j`.
- Full per-category breakdown available.

**Support:** **Strong**

**Caveat:** The evaluated subset is 454 of 2,740 cases (16.6%). Sampling is deterministic (seed=7, max 60/category). Some categories are exhaustively evaluated (LDAP: 59/59, XPath: 35/35). Not all 2,740 cases have corresponding rules.

**Recommended wording:** "On a stratified sample of 454 cases from OWASP Benchmark v1.2 covering 8 CWE categories, CodeGraph achieves macro-averaged precision 0.953, recall 0.953, and F1 0.953. Detection is fully deterministic — no LLM is involved."

---

## Claim 5: Structured Explanation with Grounded Citations

**Claim:** LLM explanations achieve Citation@Context=0.9955 and Citation@NoContext=0.000.

**Repo evidence:**
- `outputs/thesis_final_explanation_full/citation_metrics.json`: 222 TPs evaluated, Citation@Context=0.9955, Citation@NoContext=0.000.
- Structured JSON schema enforced via `codegraph/llm/schema/explanation.py`.
- Ablation (no-context) confirms evidence is load-bearing.

**Support:** **Strong**

**Caveat:** Citation@Context measures whether the LLM's `citation` field references evidence elements, not whether the citation is semantically correct or complete. It is a necessary-but-not-sufficient measure of grounding quality.

**Recommended wording:** "When provided with graph-structured evidence context, the explanation model produces grounded citations in 99.55% of cases (221/222). Under the no-context ablation, Citation@NoContext drops to 0.000, confirming that the structured evidence context is necessary for grounded citation behavior."

---

## Claim 6: Grounded Citation Behavior (Ablation)

**Claim:** Citation@NoContext=0.000 demonstrates that evidence context is necessary.

**Repo evidence:**
- `citation_metrics.json`: `rate_without_context: 0.0` for all categories.
- Ablation is built into the evaluation harness (`codegraph/evaluation/explanation_runtime.py`).
- The same LLM produces citations when given context, and does not when context is withheld.

**Support:** **Strong**

**Caveat:** This is the expected lower-bound result, not a surprising finding. It validates the design rather than demonstrating a novel insight.

**Recommended wording:** "The no-context ablation (Citation@NoContext=0.000) serves as a design validation: without structured evidence, the LLM cannot ground its citations. This confirms the evidence context is load-bearing, not decorative."

---

## Claim 7: Bounded Remediation with Fix-Rescan Verification

**Claim:** Remediation achieves 25/25 fix+build success with Brier=0.006.

**Repo evidence:**
- `outputs/thesis_final_remediation_v2/remediation_metrics.json`: 25/25 OK, fix_success_rate=1.0, build_success_rate=1.0.
- `confidence_calibration.json`: Brier=0.005723, ECE=0.069612.
- Fix-rescan loop in `codegraph/remediation/apply_flow.py`: generates fix → builds in temp workspace → re-ingests → re-evaluates policy.
- Confidence gating in same file.
- `PolicyStateTrace` captures before/after predicate states.

**Support:** **Strong**

**Caveat:** 25 cases is small. All are in 3 crypto-related categories (hash, random, crypto). Injection categories are explicitly excluded from auto-fix. The sample size limits statistical power for calibration metrics.

**Recommended wording:** "On 25 true-positive cases across three supported categories (weak hash, weak random, weak crypto), the remediation pipeline achieves a 100% fix-and-build success rate with a confidence calibration Brier score of 0.006. Each fix is verified through a fix-rescan loop: the patched file is compiled, re-ingested into the graph, and re-evaluated against the policy to confirm the violation is resolved without introducing new violations."

---

## Claim 8: Deterministic Repair Planning / Execution

**Claim:** CodeGraph includes a deterministic repair planning and compilation pipeline.

**Repo evidence:**
- `codegraph/remediation/repair_intent.py`: `RepairIntent` IR with typed operations.
- `codegraph/remediation/patch_compiler.py`: `compile_repair_intent()` deterministic patch compiler.
- Tests: `tests/codegraph/remediation/test_repair_intent.py`, `test_patch_compiler.py`.
- Comparison infrastructure: `codegraph/remediation/comparison.py`, `ranking.py`, `dossier.py`.
- `run_comparison_eval.py` runs the comparison evaluation.

**Support:** **Moderate**

**Caveat:** Both `repair_intent.py` and `patch_compiler.py` explicitly state "shadow-mode only" in their docstrings. The deterministic path is NOT wired into the live remediation flow. It is callable for logging and comparison but does not alter live results. The thesis-final remediation results use the LLM path exclusively.

**Recommended wording:** "We additionally developed a deterministic repair planning and compilation pipeline as a shadow-mode comparison baseline. The Repair Intent IR (`RepairIntent`) captures typed repair operations and structural invariants, and the patch compiler produces edits via string-level matching. While this pipeline is not the primary remediation path in the thesis-final evaluation (which uses LLM generation), it provides a structured deterministic comparison point and demonstrates that many supported repairs are amenable to fully deterministic resolution."

---

## Claim 9: LLM-Assisted Remediation

**Claim:** Remediation uses LLM generation with structured output contracts.

**Repo evidence:**
- `codegraph/llm/schema/remediation.py`: strict JSON schema with `decision`, `replacement_method_lines`, `reason`.
- `codegraph/remediation/prompting.py`: prompt construction with `TASK_SPEC` from `FIX_STRATEGIES`.
- `codegraph/llm/services/remediation_generation_service.py`: LLM call with structured output.
- `codegraph/remediation/service.py`: main orchestration.
- Model: `qwen/qwen3-coder-30b` (local).

**Support:** **Strong**

**Caveat:** The LLM is a local model, not a commercial API. Results may vary with different models. The structured output contract constrains the LLM to a narrow decision space.

**Recommended wording:** "Remediation generation uses a local code-editing LLM with a strict structured JSON output contract. The LLM receives rule-specific objectives, evidence context, and a remediation plan, and must produce either a `replace_method` decision with replacement lines or a `no_fix` decision with a reason. Free-form text is not accepted."

---

## Claim 10: Fix-Rescan Verification Loop

**Claim:** Remediation includes compile-backed verification with policy re-evaluation.

**Repo evidence:**
- `codegraph/remediation/verification.py`: `compile_project()` runs Maven/Gradle compilation.
- `codegraph/remediation/apply_flow.py`: full loop — generate → replace → compile → re-ingest → re-evaluate.
- `build_verification_summary()` checks target rule status and overall status.
- Temp workspace isolation (`prepare_temp_workspace()`).

**Support:** **Strong**

**Recommended wording:** "Each remediation attempt is verified through a complete fix-rescan loop: the patched Java file is compiled in an isolated temporary workspace using the project's build system (Maven or Gradle), re-ingested into the code graph, and re-evaluated against the OPA/Rego policy. A fix is accepted only if the target violation is resolved and no new violations are introduced."

---

## Claim 11: Comparative Evaluation (Deterministic vs. LLM)

**Claim:** CodeGraph supports comparative evaluation of deterministic and LLM remediation paths.

**Repo evidence:**
- `codegraph/remediation/comparison.py`: structured comparison with `ComparisonLabel`, `CandidateOutcome`, `ComparisonResult`.
- `codegraph/remediation/ranking.py`: scoring and ranking with deterministic point system.
- `codegraph/remediation/dossier.py`: unified case dossier.
- `run_comparison_eval.py`: comparison evaluation harness.
- Tests: `test_comparison.py`, `test_ranking.py`, `test_dossier.py`.

**Support:** **Moderate**

**Caveat:** The comparison infrastructure is implemented and tested, but no thesis-final comparison evaluation results are stored in `outputs/`. The deterministic path is shadow-mode only. Without stored comparison results, this claim relies on code evidence rather than artifact evidence.

**Recommended wording:** "The framework includes a structured comparison infrastructure that normalizes deterministic and LLM remediation outcomes into a common `CandidateOutcome` representation, enabling scored ranking and per-case dossier assembly. This supports future analysis of when deterministic edits are sufficient versus when LLM flexibility is needed."

---

## Claim 12: Predicate Tracing / PolicyStateTrace

**Claim:** Remediation captures before/after policy predicate traces for auditability.

**Repo evidence:**
- `codegraph/policy/trace.py`: `PolicyStateTrace`, `TraceProfile`, `filter_predicate_trace()`, `project_trace_profile()`.
- `codegraph/remediation/apply_flow.py`: captures before/after traces during remediation.
- Tests: `tests/codegraph/policy/test_trace.py`.

**Support:** **Strong**

**Recommended wording:** "Each remediation produces a `PolicyStateTrace` capturing the boolean predicate states before and after the fix (e.g., `weak_hash_detected: true → false`). Traces are normalized into a `TraceProfile` that abstracts noisy OPA variables into a canonical signature, enabling structured auditing of remediation outcomes."

---

## Claim 13: Frontend Support

**Claim:** CodeGraph provides a web frontend for policy evaluation, explanation, and remediation workflow.

**Repo evidence:**
- `frontend/` — React + TypeScript + Vite application.
- Policy evaluation view with grouped violations table and framework demo focus preset.
- Explanation display with structured citation/why/fix format.
- Remediation preview and apply with confidence display.
- Upload ZIP functionality with graph isolation.
- `cd frontend && yarn build` passes.
- API routers in `api/` provide backend endpoints.
- Tests in `tests/api/routers/`.

**Support:** **Moderate**

**Caveat:** The frontend is a supporting tool, not a primary thesis contribution. It demonstrates the workflow but is not part of the benchmark evaluation surface.

**Recommended wording:** "A web-based frontend provides an interactive workflow for uploading codebases, browsing policy violations, viewing structured explanations, and previewing remediation proposals. The frontend supports the thesis demonstration but is not part of the quantitative evaluation."

---

## Summary Table

| Claim | Support | Key Caveat |
|---|---|---|
| Neurosymbolic framework | Strong | Define "neurosymbolic" precisely |
| Graph-backed analysis | Strong | Not a full CPG — selective structural extraction |
| OPA/Rego policy evaluation | Strong | Manual rule authoring, not automated translation |
| Benchmark-backed detection (F1=0.953) | Strong | 454/2740 cases evaluated |
| Structured explanation (Citation@Context=0.9955) | Strong | Citation presence, not semantic correctness |
| Ablation (Citation@NoContext=0.000) | Strong | Expected lower bound, design validation |
| Bounded remediation (25/25, Brier=0.006) | Strong | Small sample, 3 crypto categories only |
| Deterministic repair planning | Moderate | Shadow-mode only, not in live flow |
| LLM-assisted remediation | Strong | Local model, results may vary |
| Fix-rescan verification | Strong | Fully implemented and tested |
| Comparative evaluation | Moderate | No stored comparison results |
| Predicate tracing | Strong | Implemented and tested |
| Frontend support | Moderate | Supporting tool, not primary contribution |
