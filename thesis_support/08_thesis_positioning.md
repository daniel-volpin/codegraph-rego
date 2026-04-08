# 08 — Thesis Positioning

---

## Recommended Thesis Identity

**One-line:** CodeGraph is a benchmark-backed Java security analysis and remediation framework that combines graph-aware code modeling, policy-based detection, structured explanation, bounded remediation, and fix-rescan verification.

**Abstract-length:**
> We present CodeGraph, a neurosymbolic framework for operationalizing security policies over JVM codebases. CodeGraph ingests Java source into a Neo4j code graph, evaluates security controls as OPA/Rego policy rules against graph-structured evidence bundles, generates structured LLM explanations with grounded citations, and proposes bounded remediations verified through a compile-and-rescan loop. On OWASP Benchmark v1.2, CodeGraph achieves F₁=0.953 across 8 CWE categories (454 cases), Citation@Context=0.996 for explanation grounding (222 true positives), and 100% fix-and-verify success on 25 supported remediation cases with Brier score 0.006. Detection is fully deterministic; the LLM is used only for explanation and bounded remediation after symbolic evidence assembly.

---

## Research Question Alignment

### RQ1: How can natural-language security/privacy requirements be translated into machine-actionable policies?

**Answer from repo evidence:**
- Manual operationalization: security requirements (inspired by ISO 27001 Annex A) are encoded as OPA/Rego rules.
- The policy catalog (`policy/catalog.json`) maps 10 controls to Rego modules.
- Evidence bundles (`build_evidence_bundle()`) translate graph-structured code context into OPA input.
- The translation is manual but systematic: each rule has defined evidence fields, severity, and remediation tier.

**Thesis-safe claim:** "We demonstrate a systematic approach to operationalizing security requirements as machine-actionable Rego policies evaluated over graph-structured code evidence. The translation from natural-language controls to executable rules is performed manually but follows a structured methodology."

**Do not claim:** Automated natural language → policy translation. This is not implemented.

### RQ2: To what extent can graph-grounded policy evaluation and LLM explanation detect and explain violations?

**Answer from repo evidence:**
- Detection: F₁=0.953 on 454 OWASP Benchmark cases across 8 CWEs. Zero FP on crypto categories. Perfect recall on injection categories.
- Explanation: Citation@Context=0.996 (221/222). Citation@NoContext=0.000 (ablation).
- The graph provides structural context (calls, inheritance); source analysis provides API-level patterns; multi-hop BFS provides bounded reachability.

**Thesis-safe claim:** "Graph-grounded policy evaluation achieves F₁=0.953 on a stratified sample of OWASP Benchmark v1.2. LLM explanations grounded in graph-structured evidence achieve 99.6% citation grounding, while the no-context ablation (0.0%) confirms the evidence is necessary for grounded outputs."

### RQ3: Can bounded remediations be proposed and verified through a fix-rescan loop?

**Answer from repo evidence:**
- 25/25 fix+build+verify success rate.
- Fix-rescan loop: generate → compile → re-ingest → re-evaluate.
- Confidence gating: sigmoid model with Brier=0.006.
- Bounded support matrix: full/guarded/manual tiers with typed rationales.
- PolicyStateTrace captures before/after predicate states.

**Thesis-safe claim:** "Bounded remediations achieve 100% fix-and-verify success on 25 cases in three supported categories. The fix-rescan loop compiles, re-ingests, and re-evaluates each fix. A confidence gate routes low-confidence fixes to manual review."

---

## Positioning Against Related Work

### vs. Traditional SAST Tools (Fortify, SpotBugs, Semgrep)
- **Differentiation:** CodeGraph adds graph-structured evidence, LLM explanations, and bounded remediation. Traditional SAST tools detect but do not explain or remediate.
- **Limitation:** Traditional tools often cover more languages and CWEs. CodeGraph covers 8 CWEs on Java only.

### vs. LLM-Based Security Analysis (GPT-4 for code review, etc.)
- **Differentiation:** CodeGraph uses symbolic detection first, then LLM explanation/remediation over pre-assembled evidence. This avoids hallucinated detections and provides structured auditability.
- **Limitation:** LLM-based approaches may be more flexible for novel vulnerability patterns.

### vs. CPG-Based Tools (Joern, CodeQL)
- **Differentiation:** CodeGraph does not claim CPG capabilities. Its graph is selective (structural relationships only). The contribution is the integrated pipeline from detection through verified remediation, not the graph model itself.
- **Limitation:** CodeQL and Joern have richer graph models with data-flow support.

### vs. Automated Repair (APR) Tools
- **Differentiation:** CodeGraph's remediation is intentionally bounded — only 3 categories are supported, with explicit refusal for unsupported cases. The fix-rescan loop with confidence gating is a production-oriented safety design.
- **Limitation:** APR tools may address a wider range of fix patterns. CodeGraph's contribution is the integration with policy evaluation and verification, not repair generality.

---

## Recommended Thesis Structure Alignment

### Chapter: Architecture
Use `01_repo_inventory.md` for subsystem descriptions. Emphasize:
- The separation between symbolic detection and neural explanation/remediation
- Evidence bundle assembly as the integration point
- The graph's role as evidence substrate, not a code analysis engine per se

### Chapter: Detection Evaluation
Use `07_results_tables_draft.md` Table 1. Discuss:
- Zero FP on crypto categories (high precision from pattern specificity)
- Perfect recall on injection categories (multi-hop BFS catches transitive sinks)
- FN analysis: non-standard API patterns in crypto categories
- FP analysis: benchmark-safe transforms in injection categories

### Chapter: Explanation Evaluation
Use `07_results_tables_draft.md` Table 2. Discuss:
- Structured output contract as the key design decision
- Citation@NoContext ablation as design validation
- XPath as minor outlier from smallest category

### Chapter: Remediation Evaluation
Use `07_results_tables_draft.md` Tables 3–5. Discuss:
- Fix-rescan loop as architectural contribution
- Confidence gating as safety mechanism
- PolicyStateTrace for auditability
- Pre-generation planning with invariant extraction
- Bounded support matrix as principled scope decision

### Chapter: Discussion
- Remediation as the deepest engineering contribution
- The neurosymbolic design as enabling both precision and explainability
- Graph model limitations (not CPG, not data-flow)
- Benchmark limitations (synthetic, small remediation sample)

### Chapter: Threats to Validity
See `05_thesis_gaps_and_fixes.md` Section 4 for specific threats.

---

## What the Thesis Title Should Convey

**Current title:** "Operationalizing Security Policies: Graph-Based Code Understanding and LLM-Driven Compliance Enforcement"

**Assessment:** The title is mostly appropriate but "Compliance Enforcement" may overstate the system's scope.

**Alternative suggestions:**
- "Operationalizing Security Policies: Graph-Based Code Understanding and LLM-Assisted Security Analysis" (broader)
- "Graph-Grounded Security Policy Evaluation with Bounded LLM Remediation" (more precise)
- "A Neurosymbolic Framework for Security Policy Evaluation, Explanation, and Bounded Remediation" (contribution-focused)

---

## Three-Sentence Elevator Pitch

> CodeGraph separates security violation detection from explanation and remediation by using OPA/Rego policies evaluated over a Neo4j code graph. The LLM operates only after symbolic detection, receiving pre-assembled evidence that enables 99.6% citation grounding. Bounded remediations are verified through a compile-and-rescan loop that achieves 100% success on supported categories.
