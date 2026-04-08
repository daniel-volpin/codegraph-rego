# 03 — Implementation Behind the Results

This document traces exactly how each benchmark result is produced, with repo paths and code references.

---

## Detection Pipeline

### How a detection evaluation works (end-to-end)

1. **Case selection** (`codegraph/evaluation/benchmark.py`):
   - Loads ground truth from `BenchmarkJava/expectedresults-1.2.csv`.
   - Selects cases per category according to the config (e.g., `multicat_full.json`).
   - Each case maps to a Java file in the OWASP Benchmark source tree.

2. **Ingestion** (`codegraph/ingestion/service.py`):
   - Each Java file is parsed with `javalang`.
   - Classes, methods, fields, annotations, inheritance, calls, field usage are extracted.
   - Nodes and edges are written to Neo4j via Cypher queries.

3. **Evidence bundle assembly** (`codegraph/policy/runtime/bundles.py`):
   - For each method, `build_evidence_bundle()` queries Neo4j for:
     - Method metadata (signature, file path, line range, modifiers)
     - Graph context (annotations, calls, callers, used fields)
     - Source code snippet
   - Optionally adds FAISS vector context.

4. **Source analysis** (`codegraph/policy/source_analysis.py`, `source_analysis_core.py`):
   - Pattern-based source code analysis using compiled regex patterns.
   - Crypto patterns: detect `MD5`, `SHA-1`, `DES`, `RC4`, `AES/ECB`, `Random`, `Math.random()`, etc.
   - Injection patterns: detect `executeQuery`, `execute`, `Runtime.exec`, `ProcessBuilder`, `new File(`, `DirContext.search`, `XPath.evaluate`, etc.
   - Produces `analysis_flags` dict (e.g., `{"calls_md5": true, "source_md5": true}`).

5. **Multi-hop taint detection** (`codegraph/policy/taint_graph.py`):
   - `TaintPathFinder` performs BFS over CALLS edges (max depth 4) from the in-memory method index.
   - At each hop, loads callee source code and checks for sink patterns (SQL, command, path, LDAP, XPath).
   - Returns reachable sink types with hop counts.
   - This is used to confirm injection-family violations by requiring sink-level taint evidence.

6. **Helper summaries** (`codegraph/policy/helper_summaries.py`):
   - One-hop helper-return summaries resolve what a called helper method returns.
   - Falls back to same-file nested helpers when graph call edges are missing.

7. **OPA/Rego evaluation** (`codegraph/policy/runtime/opa.py`):
   - Evidence bundle + analysis flags + taint paths are assembled into OPA input JSON.
   - OPA is invoked as a subprocess against the appropriate Rego rule file.
   - `build_violation_response()` translates OPA output into violation dicts.

8. **Metric computation** (`codegraph/evaluation/pipeline.py`):
   - For each case, compares detected violations against ground truth.
   - Computes TP/FP/FN per category and overall.
   - Writes `metrics.json`, `metrics.csv`, `table.md`.

### Where rules live

| Rule File | CWEs | Key Rego Rules |
|---|---|---|
| `policy/iso_27001_crypto.rego` | 327, 328, 330 | `weak_hash_detected`, `weak_cipher_detected`, `insecure_random` |
| `policy/iso_27001_injection.rego` | 89, 22, 78, 90, 643 | `sql_injection`, `path_traversal`, `command_injection`, `ldap_injection`, `xpath_injection` |
| `policy/iso_27001_access.rego` | — | `access_control`, `logging` |

### Detection logic characterization

The detection logic is **hybrid**: graph + source + heuristic.

| Layer | What it does | Limitations |
|---|---|---|
| **Graph** | CALLS edges, inheritance, annotations queried from Neo4j | No control-flow or data-dependency edges |
| **Source** | Regex pattern matching on method source code | Cannot reason about value flow or sanitization |
| **Taint BFS** | Multi-hop BFS over CALLS edges checking callee source for sink patterns | Bounded heuristic, not formal taint analysis |
| **Helper summaries** | One-hop helper-return analysis | Only one level deep |
| **Rego** | Boolean combination of evidence flags | Deterministic, but only as good as the evidence |

---

## Explanation Pipeline

### How an explanation evaluation works

1. **Detection phase**: Same as detection pipeline above.

2. **TP selection**: Only true-positive violations (ground truth = vulnerable AND detected) are sent for explanation.

3. **Evidence assembly** (`codegraph/llm/evidence_cards.py`):
   - Violation context, graph context, source snippet, vector context are formatted into an evidence card.
   - `--evidence-mode lean` produces a compact evidence representation.

4. **Prompt construction** (`codegraph/llm/explanation_prompting.py`):
   - System prompt is rule-agnostic.
   - User message contains the evidence card.
   - Structured JSON schema output is enforced (`codegraph/llm/schema/explanation.py`).

5. **LLM call** (`codegraph/llm/transport/openai_compatible_transport.py`):
   - OpenAI-compatible API call to LM Studio.
   - Structured output schema: `{"citation": str, "why": str, "fix": str}`.
   - Explicit stop sequences to prevent token spam.

6. **Citation evaluation** (`codegraph/evaluation/explanation_runtime.py`):
   - **Citation@Context**: checks if the `citation` field references specific evidence elements (method names, file paths, API calls, etc. from the evidence card).
   - **Citation@NoContext**: ablation — same prompt without evidence → checks if citation is grounded. Expected to be 0.000 since the LLM has nothing to cite.
   - Computed per category and overall.

### Output schema

```json
{
  "citation": "The method calls MessageDigest.getInstance(\"MD5\") at line 42 of BenchmarkTest00372.java",
  "why": "MD5 is a weak hash algorithm vulnerable to collision attacks",
  "fix": "Replace MD5 with SHA-256 using MessageDigest.getInstance(\"SHA-256\")"
}
```

---

## Remediation Pipeline

### How a remediation evaluation works

1. **Detection phase**: Same as detection pipeline.

2. **Case selection**: Only detected TPs in supported categories (hash, random, crypto) are eligible.

3. **Capability check** (`codegraph/remediation/capabilities.py`):
   - `get_remediation_capability()` classifies the rule as full/guarded/manual.
   - Manual rules never call the LLM → return `INVALID`.

4. **Preflight check** (`codegraph/remediation/service.py: _preflight_fixability_reason()`):
   - Subcase-level check: e.g., weak-crypto only supports explicit DES/RC4/AES-ECB literals.
   - Weak-random only supports `Random`, `Math.random()`, `ThreadLocalRandom`, `SHA1PRNG` patterns.
   - Non-matching subcases get safe `NO_FIX`.

5. **Pre-generation planning** (`codegraph/remediation/planning.py`):
   - `build_remediation_plan()` parses the target method with `javalang`.
   - Classifies transformation shape: `local_literal_or_call_edit` or `receiver_chain_upgrade`.
   - Extracts terminal invocation contracts (method calls that must be preserved).
   - Plan payload is included in the LLM prompt.

6. **LLM generation** (`codegraph/llm/services/remediation_generation_service.py`):
   - System prompt: stable, rule-agnostic "Remediation Agent".
   - User message: violation context + evidence + deterministic `TASK_SPEC` JSON block (from `FIX_STRATEGIES`).
   - Structured JSON schema: `{"decision": "replace_method"|"no_fix", "replacement_method_lines": [...], "reason": "..."}`.
   - Model: `qwen/qwen3-coder-30b`.

7. **Method replacement** (`codegraph/remediation/editing.py`):
   - `replacement_method_lines` from LLM output are used to replace the target method in the Java source.

8. **Plan validation** (`codegraph/remediation/planning.py: validate_remediation_plan()`):
   - Post-edit validation: checks that terminal invocation contracts are preserved in the updated method.

9. **Build verification** (`codegraph/remediation/verification.py`):
   - Copies project to temp workspace.
   - Writes updated file.
   - Runs `mvn -q -DskipTests compile` (or Gradle equivalent).
   - Records `compilation.success`.

10. **Policy re-verification** (`codegraph/remediation/apply_flow.py`):
    - Re-ingests updated file into Neo4j.
    - Re-runs policy evaluation on the target method.
    - `build_verification_summary()` checks:
      - Target rule is no longer triggered (PASS).
      - No new violations introduced (PASS).

11. **PolicyStateTrace** (`codegraph/policy/trace.py`):
    - Captures before/after predicate traces (e.g., `weak_hash_detected: true → false`).
    - Normalizes into `TraceProfile` for comparison.

12. **Confidence scoring** (`codegraph/remediation/confidence.py`):
    - `assess_remediation_confidence()` computes a sigmoid-based score from features:
      - `support_tier` (full +1.1, guarded +0.2, manual -1.0)
      - `decision` (apply_edits +0.8, no_fix -2.0)
      - `structured_valid` (+0.9 / -0.9)
      - `has_exact_method_source` (+0.4)
      - `has_graph_context` (+0.2)
      - `attempt_count` retries (-0.7 per retry)
    - Bands: score ≥ threshold_apply → "apply", ≥ threshold_review → "review", else "abstain".

13. **Confidence calibration** (`codegraph/evaluation/remediation_runtime.py`):
    - `build_confidence_calibration()` computes Brier score and ECE over all cases.
    - Brier = mean((predicted_prob - actual_outcome)²).
    - ECE = weighted average |avg_confidence - empirical_success| across bins.

### Deterministic path (shadow-mode, experimental)

In parallel with the LLM path, the repo contains an experimental deterministic remediation pipeline:

1. **Repair Intent IR** (`codegraph/remediation/repair_intent.py`):
   - `plan_repair_intent()` produces a typed `RepairIntent` with discriminated `RepairOperation` union.
   - Per-rule operation builders: weak hash → `LiteralReplacementOp`, weak random → `ConstructorReplacementOp`/`MethodCallReplacementOp`, weak crypto → `LiteralReplacementOp`.

2. **Patch Compiler** (`codegraph/remediation/patch_compiler.py`):
   - `compile_repair_intent()` converts operations into edit dicts via string-level matching.
   - Supports literal replacement, constructor replacement, method call replacement.

3. **Comparison** (`codegraph/remediation/comparison.py`):
   - `compare_remediation()` runs both paths and produces structured `ComparisonResult` with `ComparisonLabel`.

4. **Ranking** (`codegraph/remediation/ranking.py`):
   - `rank_candidates()` scores and sorts candidates using a deterministic point system.
   - Prefers deterministic on tiebreak.

5. **Dossier** (`codegraph/remediation/dossier.py`):
   - `build_dossier()` assembles all artifacts into a `RemediationDossier`.

**Status:** All shadow-mode. `repair_intent.py` and `patch_compiler.py` explicitly state "shadow-mode only" in their docstrings. The live remediation flow uses only the LLM path. The comparison/ranking/dossier infrastructure runs during `run_comparison_eval.py` but does not alter live remediation results.

### How zero-error outcomes are recorded

The `final_status_counts` in `remediation_metrics.json` tracks:
- `OK`: successful fix + build + verification
- `NO_FIX`: LLM decided no safe fix available (expected for some guarded cases)
- `GENERATION_ERROR`: LLM output did not parse or failed schema validation
- `BUILD_ERROR`: compilation failed after patch
- `VERIFICATION_ERROR`: policy re-check failed (violation still present or new violation introduced)
- `REPLACEMENT_ERROR`: method replacement failed (could not locate target method)

All 25 cases in the thesis-final run are `OK`.
