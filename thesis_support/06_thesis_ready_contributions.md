# 06 — Thesis-Ready Contributions

This document summarizes the contributions CodeGraph can credibly claim, with supporting evidence and recommended thesis language.

---

## Contribution 1: Integrated Neurosymbolic Security Analysis Pipeline

**What it is:** A complete pipeline from code ingestion → graph construction → policy evaluation → evidence-grounded explanation → bounded remediation → verification. The symbolic layer (OPA/Rego, Neo4j graph) handles detection; the neural layer (LLM) handles explanation and remediation only after symbolic evidence is assembled.

**Why it matters:** Most security analysis tools are either purely symbolic (SAST tools with high FP rates and no explanation) or purely neural (LLM-based with hallucination risk). CodeGraph demonstrates that combining both yields grounded, auditable results.

**Evidence:**
- F1=0.953 detection on OWASP Benchmark (454 cases, 8 CWE categories)
- Citation@Context=0.9955 explanation grounding (222 TPs)
- 25/25 fix+build success on supported remediation categories
- Zero LLM involvement in detection decisions

**Recommended thesis phrasing:**
> We present CodeGraph, a neurosymbolic framework that separates security violation detection (symbolic, deterministic) from explanation and remediation (neural, structured). By ensuring the LLM operates only over pre-assembled graph-structured evidence, we achieve 99.55% citation grounding while maintaining F1=0.953 detection accuracy.

---

## Contribution 2: Policy-as-Code with Graph-Structured Evidence

**What it is:** Security requirements encoded as OPA/Rego rules evaluated against evidence bundles assembled from a Neo4j code graph. The graph captures structural relationships (calls, inheritance, annotations) that provide context beyond what source-level pattern matching alone can offer.

**Evidence:**
- 10 controls in `policy/catalog.json`
- 3 Rego modules covering 8 CWE categories
- Evidence bundles include graph context, source analysis, multi-hop reachability, and vector context
- Deterministic evaluation (no LLM) — reproducible with `--reset-neo4j`

**Recommended thesis phrasing:**
> We operationalize security requirements as OPA/Rego policy rules evaluated against evidence bundles composed of graph-structured code context, source-level analysis flags, and bounded call-chain reachability. This design makes detection fully deterministic and auditable — each violation is traceable to specific evidence fields.

---

## Contribution 3: Evidence-Grounded LLM Explanations

**What it is:** A structured explanation generation pipeline where the LLM receives pre-assembled evidence (source code, graph context, violation metadata) and must produce structured JSON output with explicit `citation`, `why`, and `fix` fields. The ablation (Citation@NoContext=0.000) demonstrates that evidence context is necessary for grounded outputs.

**Evidence:**
- Citation@Context=0.9955 (221/222)
- Citation@NoContext=0.000 (ablation lower bound)
- Structured JSON schema enforced (`codegraph/llm/schema/explanation.py`)
- 7 of 8 categories achieve Citation@Context=1.000; XPath at 0.933 (14/15)

**Recommended thesis phrasing:**
> To ensure explanation quality, we enforce a structured output contract requiring explicit citations referencing evidence fields. Under this design, 99.55% of explanations ground their citations in the provided evidence. The no-context ablation (0.000) confirms the evidence context is load-bearing: without it, the LLM cannot produce grounded citations.

---

## Contribution 4: Bounded Remediation with Fix-Rescan Verification

**What it is:** A remediation pipeline with explicit support tiers (full/guarded/manual), pre-generation planning, structured LLM output, compilation verification, graph re-ingestion, and policy re-evaluation in a closed loop. The system refuses to attempt remediation for unsupported categories.

**Evidence:**
- 25/25 fix+build+verify success rate
- Brier=0.006 confidence calibration
- Fix-rescan loop: generate → compile → re-ingest → re-evaluate
- Bounded support matrix with typed refusal rationales
- Pre-generation planning with AST-based transformation classification and invariant extraction
- PolicyStateTrace captures before/after predicate states
- Zero GENERATION_ERROR, BUILD_ERROR, or VERIFICATION_ERROR

**Recommended thesis phrasing:**
> CodeGraph introduces a bounded remediation architecture with three key design decisions: (1) an explicit support matrix classifying each rule as full, guarded, or manual-review; (2) a fix-rescan verification loop that compiles, re-ingests, and re-evaluates each fix; and (3) a confidence gate that routes low-confidence fixes to manual review rather than auto-applying them. On 25 benchmark cases across three supported categories, this achieves a 100% fix-and-verify success rate with Brier score 0.006.

---

## Contribution 5: Confidence-Gated Remediation

**What it is:** A sigmoid-based confidence scoring model that classifies remediation outcomes into apply/review/abstain bands based on deterministic features (support tier, structured validity, attempt count, evidence quality). The confidence gate prevents low-confidence fixes from being auto-applied.

**Evidence:**
- `codegraph/remediation/confidence.py`: feature-based sigmoid model
- `codegraph/remediation/apply_flow.py`: confidence gate enforcement
- `outputs/thesis_final_remediation_v2/confidence_calibration.json`: Brier=0.006, ECE=0.070
- Reliability bins show gap < 0.11 across all bins

**Recommended thesis phrasing:**
> We introduce a confidence gating mechanism that scores each remediation attempt using a lightweight sigmoid model over deterministic features: support tier, structured output validity, evidence availability, and retry count. Remediations below the apply threshold are routed to manual review. On our evaluation, this model achieves Brier=0.006 and ECE=0.070, indicating good calibration between predicted confidence and actual success.

---

## Contribution 6: Deterministic Repair Planning and Comparison Framework

**What it is:** A typed Repair Intent IR and deterministic patch compiler that can produce security fixes without LLM involvement, plus a structured comparison framework for evaluating deterministic vs. LLM approaches.

**Evidence:**
- `codegraph/remediation/repair_intent.py`: typed IR with discriminated operation union
- `codegraph/remediation/patch_compiler.py`: deterministic compiler
- `codegraph/remediation/comparison.py`: structured comparison
- `codegraph/remediation/ranking.py`: multi-candidate scoring
- `codegraph/remediation/dossier.py`: unified case dossier
- `run_comparison_eval.py`: comparison harness
- Tests for all components

**Caveats:** Shadow-mode only. Not used in thesis-final results.

**Recommended thesis phrasing:**
> As an additional engineering contribution, we developed a deterministic repair planning pipeline: a typed Repair Intent IR captures the planned transformation (literal replacement, constructor replacement, method call replacement), and a patch compiler produces edits via string-level matching without LLM involvement. While this pipeline operates in shadow mode alongside the LLM path in our evaluation, it demonstrates that many bounded security fixes are amenable to fully deterministic resolution and provides a structured comparison baseline.

---

## Contribution Ranking (strongest to weakest)

1. **Bounded remediation with fix-rescan verification** — deepest engineering, novel integration pattern, strong results
2. **Integrated neurosymbolic pipeline** — the overall architecture and design
3. **Evidence-grounded explanations** — clear ablation result, practical structured output
4. **Policy-as-code with graph evidence** — solid foundation, well-tested
5. **Confidence-gated remediation** — novel safety mechanism, good calibration
6. **Deterministic repair planning** — interesting but shadow-mode only
