# 01 — Repository Inventory

## Overview

CodeGraph-Rego is a neurosymbolic security analysis framework for JVM codebases. The repository is structured around a Python backend (`codegraph/`), a React frontend (`frontend/`), OPA/Rego policies (`policy/`), evaluation harnesses, and benchmark infrastructure.

---

## Subsystem Inventory

### 1. Ingestion / Graph Construction

| Path | Purpose | Maturity |
|---|---|---|
| `codegraph/ingestion/service.py` | Java source parsing via `javalang`, Neo4j graph construction. Creates Class, Method, Field nodes and CONTAINS, CALLS, IMPLEMENTS, EXTENDS, USES_FIELD edges. Also handles `process_single_file_content()` for re-ingestion after remediation. | **Stable** |
| `codegraph/ingestion/utils.py` | Parsing helpers for Java source files. | Stable |
| `codegraph/ingestion/models/method.py` | Method data model (signature, line ranges, modifiers). | Stable |
| `codegraph/ingestion/models/field.py` | Field data model. | Stable |
| `codegraph/db.py` | Neo4j connection management via `neo4j` driver. Provides `get_driver()`, `run_query()`, session management. | Stable |

**Evidence:** Tests at `tests/codegraph/ingestion/test_ingestion_service.py`, `test_ingestion_utils.py`.

**Important limitation:** This is a selective code graph, not a full Code Property Graph (CPG). It extracts:
- Classes, methods, fields, annotations
- Inheritance (`EXTENDS`), interface implementation (`IMPLEMENTS`)
- Method calls (`CALLS`), field usage (`USES_FIELD`)

It does **not** extract:
- Control-flow graphs
- Data-dependency edges
- Intra-procedural data flow

### 2. Graph Search / Retrieval

| Path | Purpose | Maturity |
|---|---|---|
| `codegraph/search/service.py` | Graph-based code search: find methods by signature, class, annotation. Neo4j Cypher queries. | Stable |
| `codegraph/search/hybrid.py` | Hybrid search combining graph queries with vector/FAISS similarity. | Stable |
| `codegraph/search/models/__init__.py` | Search result data models. | Stable |

**Evidence:** Used by policy evaluation and remediation context retrieval.

### 3. Embedding / FAISS

| Path | Purpose | Maturity |
|---|---|---|
| `codegraph/embedding/service.py` | Sentence-transformer embeddings for code snippets, FAISS index management. | Stable |
| `codegraph/embedding/models/__init__.py` | Embedding metadata models. | Stable |
| `index/embedding_*.json` | Pre-computed embedding metadata and signature maps. | Stable |

**Evidence:** Used for vector context in evidence bundles for policy evaluation.

### 4. Policy / Rego Evaluation

| Path | Purpose | Maturity |
|---|---|---|
| `policy/iso_27001_crypto.rego` | Rego rules for weak hash (CWE-328), weak random (CWE-330), weak crypto (CWE-327). | **Stable** |
| `policy/iso_27001_injection.rego` | Rego rules for SQL (CWE-89), path traversal (CWE-22), command (CWE-78), LDAP (CWE-90), XPath (CWE-643) injection. | Stable |
| `policy/iso_27001_access.rego` | Rego rules for access control (ISO-A.9.4.1) and logging (ISO-A.12.4.1). | Stable |
| `policy/catalog.json` | Control catalog: 10 controls (8 active CWE categories + access + logging). | Stable |
| `policy/iso_rules.json` | Rule definitions. | Stable |
| `codegraph/policy/runtime/opa.py` | OPA subprocess invocation, `build_violation_response()` — single authoritative point for violation dicts. | **Stable** |
| `codegraph/policy/runtime/bundles.py` | `build_evidence_bundle()` — assembles graph context, taint paths, FAISS vectors into evaluation input. | Stable |
| `codegraph/policy/runtime/catalog.py` | Catalog loading and control resolution. | Stable |
| `codegraph/policy/runtime/contracts.py` | Policy evaluation contracts. | Stable |
| `codegraph/policy/service.py` | Policy service orchestration. | Stable |
| `codegraph/policy/integration.py` | `PolicyEvaluator` class used by remediation for re-verification. | Stable |
| `codegraph/policy/source_analysis.py` | Source-level analysis for crypto/injection patterns. | Stable |
| `codegraph/policy/source_analysis_core.py` | Core pattern definitions: `SQL_EXECUTE_CALL_PATTERNS`, `CMDI_PATTERNS`, `PATH_TRAVERSAL_PATTERNS`, `LDAP_PATTERNS`, `XPATH_PATTERNS`. | Stable |
| `codegraph/policy/taint_graph.py` | `TaintPathFinder` — BFS multi-hop taint path detection over CALLS edges. | Stable |
| `codegraph/policy/helper_summaries.py` | One-hop helper-return summaries for method analysis. | Stable |
| `codegraph/policy/trace.py` | `PolicyStateTrace`, `TraceProfile`, predicate trace filtering/normalization. | Stable |
| `codegraph/policy/review_store.py` | Review status persistence for policy findings. | Stable |
| `codegraph/policy/analysis/` | Modular analyzers: `command.py`, `crypto.py`, `injection.py`, `primitives.py`, `state.py`. | Stable |

**Evidence:** 15+ test files under `tests/codegraph/policy/`, including golden contract tests, crypto detection, injection detection, taint graph tests, trace tests.

### 5. Explanation / LLM

| Path | Purpose | Maturity |
|---|---|---|
| `codegraph/llm/client.py` | LLM client abstraction. | Stable |
| `codegraph/llm/evidence_cards.py` | Evidence card formatting for LLM context. | Stable |
| `codegraph/llm/explanation_prompting.py` | Explanation prompt construction. | Stable |
| `codegraph/llm/schema/explanation.py` | Structured JSON schema for explanation output (`citation`, `why`, `fix`). | **Stable** |
| `codegraph/llm/schema/remediation.py` | Structured JSON schema for remediation output (`decision`, `replacement_method_lines`, `reason`). | Stable |
| `codegraph/llm/services/explanation_service.py` | Explanation generation service. | Stable |
| `codegraph/llm/services/remediation_generation_service.py` | Remediation LLM generation service. | Stable |
| `codegraph/llm/tasks/explanation.py` | Explanation task definition. | Stable |
| `codegraph/llm/tasks/remediation.py` | Remediation task definition. | Stable |
| `codegraph/llm/transport/openai_compatible_transport.py` | OpenAI-compatible transport (LM Studio, etc.). | Stable |
| `codegraph/llm/integration.py` | LLM integration orchestration. | Stable |

**Evidence:** Tests at `tests/codegraph/llm/` (6 test files: prompting, generation, structured output, schema, transport).

### 6. Remediation

| Path | Purpose | Maturity |
|---|---|---|
| `codegraph/remediation/service.py` | Main remediation service: `propose_method_edits()`, `_preflight_fixability_reason()`, strategy selection. | **Stable** |
| `codegraph/remediation/apply_flow.py` | `execute_apply_fix()` — orchestrates the full fix-rescan loop with confidence gating and `PolicyStateTrace`. | **Stable** |
| `codegraph/remediation/confidence.py` | `assess_remediation_confidence()` — sigmoid-based confidence scoring, bands: apply/review/abstain. | Stable |
| `codegraph/remediation/capabilities.py` | `get_remediation_capability()` — rule support matrix, tier classification, unsupported rule rationales. | Stable |
| `codegraph/remediation/contracts.py` | `FIX_STRATEGIES` — per-rule strategy definitions. | Stable |
| `codegraph/remediation/planning.py` | `build_remediation_plan()` — Java AST-based pre-generation planning: transformation class, terminal invocation contracts, invariants. `validate_remediation_plan()` for post-edit validation. | Stable |
| `codegraph/remediation/repair_intent.py` | `RepairIntent` IR — typed intermediate representation with `RepairIntentKind`, `RepairOperation` discriminated union, per-rule operation builders. **Shadow-mode only** (not in live flow). | **Experimental** |
| `codegraph/remediation/patch_compiler.py` | `compile_repair_intent()` — deterministic patch compiler for Repair Intent IR (literal, constructor, method-call replacements). **Shadow-mode only**. | **Experimental** |
| `codegraph/remediation/comparison.py` | `compare_remediation()` — structured deterministic-vs-LLM comparison with `CandidateOutcome`, `ComparisonResult`, `ComparisonLabel`. | Stable |
| `codegraph/remediation/ranking.py` | `rank_candidates()` — multi-candidate scoring with deterministic point system. | Stable |
| `codegraph/remediation/dossier.py` | `RemediationDossier` — unified case artifact with traces, outcomes, ranking. | Stable |
| `codegraph/remediation/verification.py` | `build_verification_summary()`, `compile_project()`, `prepare_temp_workspace()` — build-backed verification. | Stable |
| `codegraph/remediation/editing.py` | Method replacement in Java source files. | Stable |
| `codegraph/remediation/validation.py` | LLM output validation and content extraction. | Stable |
| `codegraph/remediation/prompting.py` | Remediation prompt construction. | Stable |
| `codegraph/remediation/context.py` | Violation context assembly. | Stable |
| `codegraph/remediation/metrics.py` | Raw capture, testcase ID extraction, retry error summarization. | Stable |
| `codegraph/remediation/result_models.py` | `ApplyFixResult`, `ApplyMetadata`, `CompilationResult` typed result dicts. | Stable |
| `codegraph/remediation/orchestration.py` | Remediation orchestration layer. | Stable |

**Evidence:** 12 test files under `tests/codegraph/remediation/` covering apply flow, comparison, dossier, generation parsing, patch compiler, ranking, confidence, editing, repair intent, verification.

### 7. Evaluation Harnesses

| Path | Purpose | Maturity |
|---|---|---|
| `run_benchmark_eval.py` | Detection evaluation harness. | **Stable** |
| `run_explanation_eval.py` | Explanation evaluation harness. | Stable |
| `run_remediation_eval.py` | Remediation evaluation harness. | Stable |
| `run_comparison_eval.py` | Deterministic-vs-LLM comparison evaluation. | Stable |
| `codegraph/evaluation/benchmark.py` | Benchmark case selection, ground truth loading from OWASP `expectedresults-1.2.csv`. | Stable |
| `codegraph/evaluation/pipeline.py` | Evaluation pipeline orchestration (ingest → eval → metrics). | Stable |
| `codegraph/evaluation/explanation_runtime.py` | Explanation evaluation runtime with Citation@Context/NoContext computation. | Stable |
| `codegraph/evaluation/remediation_runtime.py` | Remediation evaluation runtime, `build_confidence_calibration()` for Brier/ECE. | Stable |
| `codegraph/evaluation/io.py` | Output writing (JSON, CSV, Markdown tables). | Stable |
| `codegraph/benchmark_registry.py` | Policy registry loading, category-to-rule mapping. | Stable |

**Evidence:** Tests at `tests/codegraph/evaluation/` (5 test files). Configs at `configs/benchmark/`.

### 8. Benchmark Configs

| Path | Purpose |
|---|---|
| `configs/benchmark/multicat_full.json` | 8-category full evaluation (60 cases/cat, seed=7). |
| `configs/benchmark/remediation_supported_medium.json` | 3 supported remediation categories (20 cases/cat, seed=42). |
| `configs/benchmark/policy_registry.json` | Category→rule mapping, remediation tiers. |
| `configs/benchmark/smoke_mixed.json` | Quick smoke test. |
| `configs/benchmark/multicat_medium.json` | Medium calibration check. |
| `configs/benchmark/remediation_hash_smoke.json` | Hash-only remediation smoke. |
| `configs/benchmark/remediation_bounded_smoke.json` | Bounded remediation smoke (full + guarded). |
| `configs/benchmark/framework_demo.json` | Demo framework config. |
| `configs/benchmark/expanded_eval.json` | Expanded evaluation. |

### 9. Frontend

| Path | Purpose | Maturity |
|---|---|---|
| `frontend/` | React + TypeScript + Vite frontend. | Stable |
| `frontend/src/` | Source files for policy workbench, search, upload, explanation, remediation views. | Stable |

**Frontend capabilities:** Upload ZIP, policy evaluation view (grouped violations table, framework demo focus preset), search, explanation display (citation/why/fix structured), remediation preview/apply with confidence display.

**Evidence:** `cd frontend && yarn build` passes. Playwright screenshots exist.

### 10. API Backend

| Path | Purpose | Maturity |
|---|---|---|
| `api/` | FastAPI/Flask routers for health, policy, remediation, upload, search, explanation endpoints. | Stable |
| `codegraph/app.py` | Application startup and configuration. | Stable |
| `app.py` | Entry point. | Stable |

**Evidence:** Tests at `tests/api/routers/` (4 test files).

### 11. Scripts / Utilities

| Path | Purpose |
|---|---|
| `scripts/ingestion/codebase_to_neo4j.py` | CLI ingestion tool. |
| `scripts/ingestion/build_code_embeddings.py` | Embedding builder CLI. |
| `scripts/search/hybrid_code_search.py` | Hybrid search CLI. |
| `scripts/policy/policy_eval_cli.py` | Policy evaluation CLI. |
| `scripts/evaluation/inspect_benchmark_schema.py` | Benchmark schema inspector. |
| `scripts/evaluation/run_experiments.py` | Experiment runner. |
| `scripts/evaluation/build_benchmark_demo_pack.py` | Demo pack builder. |
| `scripts/evaluation/report_benchmark_results.py` | Results reporter. |
| `scripts/evaluation/run_remediation_model_bakeoff.py` | Model comparison tool. |

### 12. Test Coverage Summary

**Total test files:** 44
- API routers: 4 tests
- Ingestion: 2 tests
- Policy: 15 tests (detection, crypto, injection, taint, trace, golden contracts)
- LLM: 6 tests (prompting, generation, schema, transport)
- Remediation: 12 tests (apply flow, comparison, dossier, patch compiler, ranking, confidence, editing, repair intent, verification)
- Evaluation: 5 tests (config layout, selection, pipeline, explanation runtime, remediation runtime)
- Config/app: 2 tests
- Scripts: 4 tests

### 13. Documentation

| Path | Purpose |
|---|---|
| `CLAUDE.md` | Project context for AI agents. |
| `REPRODUCIBILITY.md` | Reproduction guide for all evaluations. |
| `docs/thesis_context.md` | Thesis framing and terminology constraints. |
| `docs/remediation_prompting_design.md` | Remediation prompting architecture. |
| `.opencode/project/benchmark_latest.md` | Current authoritative numbers. |
| `.opencode/project/current_state.md` | System state summary. |
| `.opencode/project/open_issues.md` | Known issues and limitations. |
| `.opencode/project/runbook.md` | Evaluation runbook. |

---

## Maturity Summary

| Component | Status |
|---|---|
| Ingestion / Graph | Stable |
| Search / Retrieval | Stable |
| Embedding / FAISS | Stable |
| Policy / Rego (10 rules) | Stable |
| Taint Graph (BFS) | Stable |
| Source Analysis | Stable |
| Explanation (structured) | Stable |
| Remediation (LLM path) | Stable |
| Planning (AST-based) | Stable |
| Repair Intent IR | **Experimental (shadow-mode)** |
| Patch Compiler | **Experimental (shadow-mode)** |
| Comparison / Ranking / Dossier | Stable |
| Verification (build-backed) | Stable |
| Confidence Gating | Stable |
| PolicyStateTrace | Stable |
| Evaluation Harnesses | Stable |
| Frontend | Stable |
| API | Stable |
