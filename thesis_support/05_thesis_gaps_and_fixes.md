# 05 — Thesis Gaps and Recommended Fixes

---

## 1. Terminology Corrections

### Graph terminology

**Problem:** Describing the code graph as a "Code Property Graph" (CPG), "control-flow graph", or "data-dependency graph" is inaccurate. The repo implements a selective structural extraction.

**Fix:** Replace all instances of:
- "Code Property Graph" / "CPG" → "selective code graph" or "graph-based code model"
- "control-flow graph" → remove or qualify as "not implemented"
- "data-dependency graph" → remove or qualify as "not implemented"
- "inter-procedural data flow" → "multi-hop call reachability"

**Recommended passage:** "CodeGraph constructs a selective code graph in Neo4j capturing structural relationships: class hierarchies (EXTENDS, IMPLEMENTS), method call edges (CALLS), field usage (USES_FIELD), and annotation metadata. This graph does not include control-flow or data-dependency edges; detection logic relies on structural relationships, source-level pattern analysis, and bounded multi-hop call reachability."

### Taint analysis terminology

**Problem:** Describing the BFS reachability as "taint analysis" is an overstatement. The `TaintPathFinder` performs bounded BFS over CALLS edges checking callee source for sink patterns — it does not track data flow through variables.

**Fix:** Replace:
- "taint analysis" → "bounded multi-hop call reachability" or "BFS-based sink reachability"
- "taint path" → "call-chain reachability path"

**Recommended passage:** "For injection families, CodeGraph supplements single-method pattern analysis with bounded multi-hop call reachability: a BFS traversal over CALLS edges (maximum depth 4) checks whether transitive callees contain known sink API patterns. This approximates taint reachability but does not model variable-level data flow or sanitization."

### Compliance terminology

**Problem:** Broad "compliance" language may overstate what the system validates. CodeGraph evaluates specific security coding patterns, not organizational compliance with ISO 27001 as a management system standard.

**Fix:** Narrow "compliance" claims:
- "compliance enforcement" → "security policy evaluation" or "security coding pattern detection"
- "ISO 27001 compliance" → "security controls inspired by ISO 27001 Annex A"

**Recommended passage:** "CodeGraph operationalizes selected security coding requirements inspired by ISO 27001 Annex A controls. It evaluates code-level patterns (weak cryptography, injection vulnerabilities) rather than organizational-level compliance with the full ISO 27001 management system."

---

## 2. Sections That Can Be Completed Now

### Detection results section
- All numbers are authoritative and verified.
- Table from `outputs/thesis_final_detection_full/table.md` is thesis-ready.
- Per-category analysis can discuss zero FP for crypto and perfect recall for injection.
- The F1=0.953 claim is solid.

### Explanation results section
- Citation@Context=0.9955 and Citation@NoContext=0.000 are verified.
- Ablation interpretation is clear and documented.
- XPath deviation (0.933 vs 1.000) can be noted as a minor outlier from smallest category.

### Remediation results section
- 25/25 OK with Brier=0.006 is verified.
- Confidence calibration data is available including reliability bins and risk-coverage.
- The fix-rescan loop can be described in detail with code references.

### Architecture section
- The inventory in `01_repo_inventory.md` provides complete paths and maturity assessments.
- The implementation trace in `03_implementation_behind_results.md` covers end-to-end pipeline.

---

## 3. Claims That Should Be Narrowed

### "The system detects and explains violations across all CWE categories"
**Narrowing:** The system evaluates 8 specific CWE categories. It does not claim coverage of all CWEs. Narrow to: "The system evaluates 8 CWE categories covering cryptographic weakness and injection vulnerability families."

### "Graph-based code understanding enables precise policy evaluation"
**Narrowing:** The graph provides structural context but detection precision also depends heavily on source-level pattern analysis. Narrow to: "Graph-based code understanding combined with source-level pattern analysis enables policy evaluation. The graph provides call relationships and structural context; source analysis provides API-level pattern detection."

### "The remediation pipeline can fix security vulnerabilities"
**Narrowing:** Only 3 categories are supported. 25 cases tested. Narrow to: "The remediation pipeline demonstrates fix-and-verify capability for bounded transformation categories (weak hash, weak random, weak crypto) with a 100% success rate on 25 benchmark cases."

### "Confidence calibration validates remediation reliability"
**Narrowing:** 25 cases with 100% success is too few to fully validate calibration. The Brier score is excellent but the sample is small. Narrow to: "On the evaluated sample of 25 cases, the sigmoid-based confidence model achieves Brier=0.006 and ECE=0.070, suggesting good calibration in the supported remediation scope. Larger samples would be needed to validate calibration robustness."

---

## 4. Missing Limitations / Threats to Validity

### Internal validity threats
- **Benchmark representativeness:** OWASP Benchmark is synthetic, with artificially constructed test cases. Real-world codebases may have different vulnerability patterns.
- **Sampling:** 454 of 2,740 cases (16.6%) are evaluated. While sampling is deterministic and stratified, it does not cover all cases.
- **Model dependency:** Explanation and remediation results depend on specific local LLM models (qwen3.5-9b-mlx, qwen/qwen3-coder-30b). Different models may produce different results.
- **Single evaluation run:** Results are from a single run. No statistical testing across multiple runs or seeds is reported.

### External validity threats
- **JVM only:** The system is designed for Java/JVM codebases. Generalization to other languages is not demonstrated.
- **OWASP Benchmark only:** The primary proof surface is a synthetic benchmark. Real-world validation is limited to two qualitative case studies (PetClinic, gs-securing-web) that do not exercise remediation.
- **Bounded CWE scope:** 8 CWE categories from a much larger CWE taxonomy.

### Construct validity threats
- **Citation@Context:** Measures citation presence, not citation correctness or helpfulness.
- **Fix+build success:** Demonstrates compilation and policy-pass, but does not verify semantic correctness of the fix (e.g., the fix might change behavior in ways beyond security).
- **Brier/ECE with 100% success:** When all cases succeed, calibration metrics primarily measure confidence scores, not the model's ability to distinguish success from failure.

---

## 5. Stable vs. Experimental Clarification

### Must be explicitly marked as experimental in the thesis:
- **Repair Intent IR** (`codegraph/remediation/repair_intent.py`): "shadow-mode only" per docstring.
- **Patch Compiler** (`codegraph/remediation/patch_compiler.py`): "shadow-mode only" per docstring.
- **Step 7 trace-aware prompt enrichment**: Feature-gated, off by default, experimental.

### These are stable and can be claimed without qualification:
- Detection pipeline (all 8 CWE categories)
- Explanation pipeline (structured output, citation evaluation)
- LLM remediation pipeline (service, apply flow, verification)
- Confidence gating
- PolicyStateTrace
- Pre-generation planning (`planning.py`)
- Comparison/ranking/dossier infrastructure
- Frontend workbench

---

## 6. Where Remediation Contribution Should Be Strengthened

The remediation subsystem is arguably the most engineering-rich contribution. The thesis should emphasize:

1. **The fix-rescan loop as an architectural contribution:** This is a genuinely novel integration pattern — few systems compile + re-ingest + re-evaluate in a closed loop.

2. **Confidence gating:** The sigmoid-based confidence model with apply/review/abstain bands is a production-oriented safety mechanism.

3. **PolicyStateTrace:** Before/after predicate tracing provides structured auditability.

4. **Pre-generation planning:** Java AST-based transformation classification and terminal invocation contracts are a thoughtful engineering contribution.

5. **Bounded support matrix:** The explicit full/guarded/manual tier system with typed rationales is a principled approach to remediation scope.

6. **Structured output contract:** The strict JSON schema eliminates ambiguous LLM output parsing.

---

## 7. Where "Compliance" Framing Should Be Tightened

### Current state
The thesis title references "compliance enforcement" and the system maps to ISO 27001 controls. However:
- ISO 27001 is an information security management system (ISMS) standard — it covers organizational processes, risk management, and governance, not just code patterns.
- The system evaluates code-level security patterns only.
- The ISO mapping is a useful framing device but does not constitute compliance validation.

### Recommended adjustment
- Keep the ISO 27001 mapping as a structuring principle for the policy catalog.
- Avoid claiming the system validates "ISO 27001 compliance" — instead say it "operationalizes selected security controls inspired by ISO 27001 Annex A."
- Frame the contribution as "policy-as-code for security coding requirements" rather than "compliance enforcement."

### Specific thesis language
- "Compliance enforcement" → "security policy evaluation" or "policy-based security analysis"
- "ISO 27001 compliance" → "security policies structured around ISO 27001 Annex A controls"
- "Operationalizing compliance requirements" → "operationalizing security coding requirements"

---

## 8. Top Priority Thesis Fixes

1. **Replace all CPG/control-flow/data-dependency terminology** with "selective code graph" and "bounded multi-hop call reachability."

2. **Narrow compliance language** to "security policy evaluation" rather than "compliance enforcement."

3. **Add threats to validity section** covering benchmark representativeness, model dependency, sampling, and construct validity of metrics.

4. **Explicitly mark shadow-mode components** (Repair Intent IR, Patch Compiler, trace-aware enrichment) as experimental.

5. **Strengthen remediation description** — this is the deepest engineering contribution and should be described in detail.

6. **Add a limitations section for the confidence calibration** noting the small sample size and 100% success rate.

7. **Clarify the taint analysis terminology** — bounded BFS reachability, not formal taint tracking.
