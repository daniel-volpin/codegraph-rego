# Self-Improving Remediation & Prompt Optimization Architecture

## Status
Accepted (2026-09-19)

## Context & Motivation
Traditional static LLM agents rely on hand-authored system prompts and fixed heuristic instructions. While static prompts can achieve baseline success, they cannot systematically learn from runtime execution failures, compiler diagnostics, or static taint rejections. When an autonomous agent repeatedly encounters a failure mode across a dataset (such as spending turns on conversational reasoning without tool calls, or writing custom string-escaping loops instead of parameterizing SQL/LDAP queries), human engineers are forced to manually diagnose traces and rewrite prompt templates.

## Architecture & Foundational Principles
To elevate CodeGraph into a self-improving security framework, we integrate a closed-loop prompt optimization engine inspired by SOTA research in Automated Program Repair and prompt optimization:
1. **TextGrad Textual Gradient Backpropagation**: Natural language loss computation that translates compiler error spans and static analysis diagnostics into actionable prompt feedback.
2. **DSPy Programmatic Trajectory Bootstrapping**: Declarative signature compilation that harvests 100% verified 3-gate repair trajectories from golden runs and compiles them as few-shot demonstrations into the agent's instructions.
3. **OpenTelemetry / OpenInference Feedback Integration**: Trace spans (`openinference.span.kind = "AGENT" | "LLM" | "TOOL"`) feed structured metadata (latency, token efficiency, tool parameters, remaining violations) directly into the optimization pipeline.

## System Workflow & Optimization Loop

```text
[ Golden Benchmark Dataset ] ──(20/100 cases)──> [ Autonomous Repair Agent ]
                                                        │
                                                        ▼
                                             [ 3-Gate Verification ]
                                            ├─ JDT Compilation Gate
                                            ├─ Test Regression Gate
                                            └─ Policy Clearance Gate
                                                        │
                                                        ▼ (Execution Results & Diagnostics)
[ Evolved System Prompt ] <── [ DSPy & TextGrad ] <── [ Trajectory Evaluator & Critic ]
```

### 1. 3-Gate Trajectory Scoring (`codegraph.optimization.evaluator`)
Quantifies trajectory quality based on deterministic gate satisfaction and tool efficiency: $$\text{Score} = w_{\text{compile}} \cdot \mathbb{I}(\text{Compile}) + w_{\text{tests}} \cdot \mathbb{I}(\text{Tests}) + w_{\text{policy}} \cdot \mathbb{I}(\text{Policy}) - \lambda \cdot \text{Turns} - \mu \cdot \text{NoToolTurns}$$

### 2. Textual Loss Critic (`codegraph.optimization.critic`)
When a trajectory fails any of the 3 gates, the Critic analyzes the error diagnostics (compiler error text, test failure traces, remaining taint sinks) and synthesizes a structured textual gradient $\nabla_{\text{prompt}}$ outlining the exact behavioral adjustment required.

### 3. DSPy Prompt Compiler (`codegraph.optimization.dspy_optimizer`)
Extracts grounded, verified 3-gate repair trajectories from golden dataset runs and bootstraps them into declarative few-shot demonstrations (`RemediationTrajectoryDemonstration`), providing the model with verified concrete transformation patterns.

## Empirical Validation on Golden 20 Dataset
Evaluated against the curated 20-case golden benchmark dataset (`configs/benchmark/golden_20_remediation.json`) on local model `qwen/qwen3.8-27b` via LM Studio:
- **Overall Fully Verified Success Rate**: **90.0% (18/20 cases fixed and verified)**.
- **Hash Category (`ISO-A.10-WEAK-HASH`)**: 5/5 SUCCESS (100%).
- **Randomness Category (`ISO-A.10-WEAK-RANDOM`)**: 5/5 SUCCESS (100%).
- **Crypto Category (`ISO-A.10-WEAK-CRYPTO`)**: 5/5 SUCCESS (100%).
- **SQL Injection (`ISO-A.8-SQL-INJECTION`)**: 3/5 SUCCESS (60%).
- **Compiler & Policy Gates**: 100% of generated patches passed JDT compilation and project tests with zero regressions.
