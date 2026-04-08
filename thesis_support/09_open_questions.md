# 09 — Open Questions

Questions for the thesis author to resolve before submission.

---

## Results / Artifacts

### Q1: Remediation Brier/ECE discrepancy
`summary.md` reports Brier=0.0119, ECE=0.1091, while `confidence_calibration.json` reports Brier=0.0057, ECE=0.0696. The discrepancy arises because `summary.md` is a live-progress artifact written during the run (streaming), while `confidence_calibration.json` is computed post-hoc over all completed cases.

**Recommendation:** Use `confidence_calibration.json` numbers (Brier=0.006, ECE=0.070) for the thesis. Verify that the thesis does not inadvertently cite the `summary.md` numbers.

### Q2: Why 25 remediation cases, not 60?
The config selects up to 60 cases across 3 categories (20/cat). Only 25 were detected as true positives and thus eligible for remediation. This means 35 cases either were true negatives in the benchmark ground truth or were false negatives of the detection pipeline.

**Action needed:** Verify this interpretation is correct. If desired, add a sentence to the thesis explaining the 25/60 ratio.

### Q3: No stored comparison evaluation results
The comparison infrastructure (`run_comparison_eval.py`, `comparison.py`, `ranking.py`, `dossier.py`) is implemented and tested, but no comparison results are stored in `outputs/`. If the thesis claims comparative evaluation results, an actual comparison run should be executed and stored.

**Action needed:** Decide whether to run `run_comparison_eval.py` and include comparison results, or describe the infrastructure as implemented-but-not-yet-evaluated.

### Q4: XPath Citation@Context=0.933
One XPath explanation (1 of 15) did not produce a grounded citation. This is a minor outlier but should be acknowledged.

**Action needed:** Consider investigating the specific case in `explanation_samples.jsonl` to understand whether it is a model limitation or an evidence quality issue.

---

## Terminology

### Q5: "Neurosymbolic" definition
The thesis should define what "neurosymbolic" means in this context. The standard academic usage implies joint neural-symbolic reasoning. CodeGraph uses symbolic detection followed by neural explanation/remediation — the two layers are sequential, not jointly optimized.

**Action needed:** Add a definition early in the thesis clarifying that "neurosymbolic" here means a pipeline where symbolic components handle detection and verification while neural components handle explanation and code generation, with structured evidence as the interface.

### Q6: Title wording
"Compliance Enforcement" may be too strong. The system evaluates code-level security patterns, not organizational ISO 27001 compliance.

**Action needed:** Consider whether to keep "Compliance Enforcement" or narrow to "Security Analysis" or "Security Policy Evaluation."

---

## Scope

### Q7: Real-world validation depth
The two case studies (PetClinic, gs-securing-web) validate ingestion, search, and policy evaluation, but not remediation. Neither surfaced a bounded remediation category.

**Action needed:** Acknowledge this limitation explicitly. The case studies demonstrate workflow breadth but not remediation depth.

### Q8: Step 7 trace-aware prompt enrichment
The `prompt_context["normalized_trace_profile"]` code in `apply_flow.py` passes before-trace data to the LLM prompt. Is this the "step 7 trace-aware prompt enrichment" that should be marked as experimental?

**Action needed:** Clarify whether the trace profile in the prompt context is the experimental feature-gated enrichment or a stable part of the pipeline. If experimental, ensure the thesis marks it as such.

### Q9: Remediation model sensitivity
The thesis should note that remediation results depend on the specific LLM model (`qwen/qwen3-coder-30b`). The `run_remediation_model_bakeoff.py` script exists for model comparison but no bakeoff results are stored in `outputs/`.

**Action needed:** Either run a model bakeoff and include comparative results, or add a limitation noting model dependency.

---

## Missing Thesis Sections

### Q10: Threats to validity
Does the current thesis draft include a threats to validity section? If not, use the threats identified in `05_thesis_gaps_and_fixes.md` Section 4.

### Q11: Limitations section
Does the thesis explicitly state what CodeGraph does NOT do? Key limitations:
- Not a full CPG (no control-flow, no data-dependency)
- Not formal taint analysis (bounded BFS reachability)
- Not production autonomous repair (bounded, verified, 3 categories)
- JVM/Java only
- Benchmark is synthetic (OWASP Benchmark)
- 8 CWE categories, not comprehensive CWE coverage
- Manual rule authoring (no automated requirement-to-policy translation)

### Q12: Future work
Does the thesis discuss future work? Natural candidates:
- Extending the deterministic repair path from shadow-mode to production
- Supporting additional CWE categories for remediation
- Adding data-flow edges to the graph model
- Multi-language support
- Evaluating on real-world vulnerability datasets
- Cross-model remediation evaluation
- Integrating the confidence gate with CI/CD pipelines

---

## Technical Verification

### Q13: Detection seed sensitivity
Results use seed=7 for detection and seed=42 for remediation. Has sensitivity to seed choice been explored? If different seeds produce materially different results, this should be discussed.

**Action needed:** Consider running detection with 2–3 alternative seeds to verify stability, or note seed choice as a limitation.

### Q14: Explanation model dependency
Explanation results use `qwen3.5-9b-mlx`. How sensitive are citation grounding rates to model choice? The structured output schema mitigates model-specific behavior, but the thesis should acknowledge this dependency.

### Q15: Build verification scope
The Maven compilation step (`mvn -q -DskipTests compile`) verifies Java compilation but does not run tests. This is intentional (the OWASP Benchmark test suite is not designed for the patched files), but the thesis should clarify that "build success" means "compilation success" not "test suite success."

---

## First Files to Inspect Manually

1. **`outputs/thesis_final_remediation_v2/confidence_calibration.json`** — verify Brier/ECE numbers match what the thesis cites.
2. **`outputs/thesis_final_explanation_full/citation_metrics.json`** — verify Citation@Context and review the per-category breakdown.
3. **`outputs/thesis_final_detection_full/metrics.json`** — verify TP/FP/FN counts match the thesis.
4. **`codegraph/remediation/repair_intent.py`** — verify the "shadow-mode only" status is clear.
5. **`codegraph/remediation/patch_compiler.py`** — same verification.
6. **`codegraph/policy/taint_graph.py`** — verify the BFS implementation matches how you describe it in the thesis.
7. **`outputs/thesis_final_remediation_v2/summary.md`** — note the Brier/ECE discrepancy vs. `confidence_calibration.json`.
