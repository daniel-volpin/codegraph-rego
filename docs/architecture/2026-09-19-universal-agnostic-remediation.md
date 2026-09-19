# Universal Agnostic Vulnerability Remediation Architecture

## Status
Accepted (2026-09-19)

## Context & Motivation
Traditional Automated Program Repair (APR) systems and earlier iterations of CodeGraph coupled vulnerability remediation to static dictionaries of per-rule transformation recipes (`FIX_STRATEGIES`). While hardcoding specific API replacements (such as naming a specific library class for a specific rule ID) provides a superficial boost on narrow benchmarks, it fails in three critical dimensions:
1. **Multi-Standard Scalability**: When new compliance standards (e.g. PCI-DSS 4.0, NIST SP 800-53, ISO-27001) or external SAST reports in OASIS SARIF v2.1.0 format are imported, hardcoded dictionaries cannot predict the unbounded universe of vulnerability types without continuous manual engineering.
2. **LLM Reasoning Underutilization**: Contemporary reasoning and code-generation models (e.g., Qwen 2.5/3 Coder, DeepSeek, GPT-4o, Claude) already possess extensive semantic knowledge of secure coding patterns. Over-specifying rigid recipes constrains their ability to synthesize context-appropriate, idiomatic refactorings suited to the specific codebase architecture.
3. **Verification Integrity vs Heuristic Guessing**: Security guarantees must originate from deterministic verification gates (compilation, test regression, and policy clearance), not from heuristic prompt templates.

## SOTA Scientific Foundations
Recent literature in Automated Vulnerability Repair (AVR) establishes several key paradigms adopted in this architecture:
- **RepairAgent (ICSE 2025)**: Demonstrates that autonomous tool-calling agents that interleave information gathering, surgical patch application, and external validator feedback significantly outperform one-shot or recipe-based repair.
- **SecureFixAgent & PatchAgent (USENIX Security 2025)**: Validates that feeding exact static analysis diagnostics, call-graph taint propagation paths, and compiler diagnostics into an iterative repair-validate loop enables high-precision repair without domain-specific rule hardcoding.
- **SARIF-Driven Prompt Paradigms**: Highlights that standardizing vulnerability metadata into structured properties (rule ID, control title, vulnerability summary, source location, and dataflow chain) provides sufficient context for autonomous agents to derive correct patches across diverse rule taxonomies.

## Universal Agnostic Architecture

### 1. Dynamic Remediation Contract Resolution
Rather than maintaining static per-rule code transformations, CodeGraph introduces dynamic contract resolution (`codegraph.remediation.contracts.resolve_remediation_contract`). The contract is synthesized dynamically at runtime from:
- Finding identification and control metadata (`rule_id`, `title`, `summary`, `standard`).
- Call-graph and dataflow propagation traces (`taint_paths`).
- Universal 3-gate invariant constraints.

### 2. Invariant-Driven Agent Protocol
The agent system prompt (`codegraph.remediation.agentic.prompts.SYSTEM_PROMPT_TEMPLATE`) is streamlined to be concise, universal, and strictly grounded in the 3 verification gates:
- **Compilation Gate**: Eclipse JDT / javac compiles the workspace with 0 errors.
- **Regression Gate**: Existing unit and integration test suites pass with 0 regressions.
- **Policy Gate**: The targeted security rule is satisfied (0 remaining violations), proving that untrusted taint reaching the vulnerable sink has been eliminated.

### 3. OpenTelemetry & OpenInference Telemetry
Full lifecycle telemetry is instrumented across all agent turns using OpenInference semantic conventions and OpenTelemetry spans (`remediation.agentic`), capturing:
- Target rule identifiers, model names, and maximum turn allowances.
- Per-turn tool invocations (`read_file`, `edit_file`, `add_import`, `run_verification`).
- Intermediate gate evaluations, compiler error diagnostics, and remaining violation taxonomies.

## Empirical Failure Diagnostics from the 100-Dataset
Analysis of the 84 benchmark findings from the 100-case evaluation corpus (`outputs/agentic_baseline_100/`) revealed that 90.7% of failures were caused by semantic mismatches between dynamic runtime escaping and static taint propagation, rather than inability to generate valid Java code:
1. **Custom Escaping vs Static Taint (53.5% of failures)**: Models frequently wrote valid custom runtime escaping methods (e.g. custom LDAP character encoders or path normalization checks) rather than using standard framework sanitizers (`ESAPI`). Because OpenGrep performs static dataflow tracking without executing custom runtime string logic, taint remained active at the sink.
2. **Resolver Callback Boundaries (14.0% of failures)**: Standard Java XML parameter bindings (`XPathVariableResolver`) were correctly implemented, but static taint engines flag the containing evaluator if the resolver captures a tainted variable.
3. **Hermetic Sandbox Worktrees & Config Findings (9.3% of failures)**: Config-driven findings evaluated in isolated worktrees fail-closed due to lack of shared graph state, preserving safety without emitting false-negative "fixed" reports.
4. **JDT Compilation Syntax Gates (9.3% of failures)**: Multiturn scoping slips (such as leaving a dangling catch block) were caught and rejected by the JDT compilation gate.

## Consequences & Guarantees
- **Generalization**: Any custom policy pack or third-party SARIF report can enter the autonomous repair pipeline without adding new Python dispatch code.
- **Determinism**: Code modifications are never accepted without passing all 3 independent gates in an isolated worktree.
- **Provenance**: All candidate evaluations, diffs, and verification receipts remain recorded and traceable.
