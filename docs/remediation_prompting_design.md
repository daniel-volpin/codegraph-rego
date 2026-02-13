# Remediation Prompting Design (Thesis)

## Current State
The backend remediation flow (`codegraph/remediation/service.py`) selects a rule strategy by `rule_id` and constructs an LLM prompt for a "virtual fix" preview and an "apply+verify" loop.

Today:
- Prompt roles: `system` + `user` (no `developer` role).
- A rule-specific `objective` is injected into the **system prompt**.
- The user message includes the violation + evidence (source snippet, graph context, vector context, control metadata).
- Unsupported rules return `status=INVALID` with `error=unsupported_rule_for_auto_fix` without calling the LLM.
- The agent can return `NO_FIX: <reason>` to refuse unsafe remediations.

## Decision
Use a **single, stable "Remediation Agent" system prompt** across supported rules, and provide a per-rule **TASK_SPEC** as a deterministic JSON block in the user message.

This corresponds to: "one agent, bounded capability set" where rule IDs select a small objective/constraints payload.

## Why This Fits the Thesis
- Clarity: one agent prompt and one output contract; the per-rule logic is transparent and minimal.
- Reproducibility: the system prompt is stable; the task spec is deterministic JSON with fixed delimiters.
- Evaluation fairness: improvements are attributable to (a) detector coverage and (b) apply+verify correctness gates, not per-rule prompt engineering.

## Invariants
- The system prompt is rule-agnostic and must not encode rule-specific details (e.g., no MD5/SHA-256 strings).
- Unsupported rule IDs never call the LLM and return `INVALID`.
- SQL injection remediation remains unsupported.
- Output contract is strict:
  - Either a full replacement method only (signature + body braces), or
  - `NO_FIX: <reason>`
  - No markdown / code fences / JSON / commentary in the output.

