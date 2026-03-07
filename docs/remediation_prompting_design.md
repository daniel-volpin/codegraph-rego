# Remediation Prompting Design (Thesis)

## Current State

The backend remediation flow (`codegraph/remediation/service.py`) selects a rule strategy by `rule_id` and constructs an LLM prompt for a "virtual fix" preview and an "apply+verify" loop.

- Prompt roles: `system` + `user` (no `developer` role).
- A rule-specific `objective` is injected into the **system prompt**.
- The user message includes the violation + evidence (source snippet, graph context, vector context, control metadata).
- Unsupported rules return `status=INVALID` with `error=unsupported_rule_for_auto_fix` without calling the LLM.
- Guarded rules may return `NO_FIX: <reason>` to refuse unsafe remediations.

## Production-Minded Support Matrix

The thesis/demo surface now uses a bounded remediation matrix:

- Full support:
  - `ISO-A.10-WEAK-HASH`
  - `ISO-A.10-WEAK-RANDOM`
- Guarded support:
  - `ISO-A.10-WEAK-CRYPTO`
- Manual review only:
  - `ISO-A.8-SQL-INJECTION`
  - access-control findings such as `ISO-A.9.4.1`

This is intentional. "Production-ready" in this repo means deterministic support boundaries, auditable refusal behavior, and dry-run verification gates, not universal autonomous repair.

## Decision

Use a **single, stable "Remediation Agent" system prompt** across supported rules, and provide a per-rule **TASK_SPEC** as a deterministic JSON block in the user message.

This corresponds to: "one agent, bounded capability set" where rule IDs select a small objective/constraints payload.

## Why This Fits the Thesis

- **Clarity:** one agent prompt and one output contract; the per-rule logic is transparent and minimal.
- **Reproducibility:** the system prompt is stable; the task spec is deterministic JSON with fixed delimiters.
- **Evaluation fairness:** improvements are attributable to (a) detector coverage and (b) apply+verify correctness gates, not per-rule prompt engineering.

## Invariants

- The system prompt is rule-agnostic and must not encode rule-specific details (e.g., no MD5/SHA-256 strings).
- Unsupported rule IDs never call the LLM and return `INVALID`.
- SQL injection remediation remains unsupported.
- Guarded weak-crypto remediation is allowed only for explicit literal weak-cipher subcases with enough method-local context to support a safe minimal change.
- Weak-random remediation is allowed only for narrow local transformations such as `Random` to `SecureRandom`, `Math.random()` replacement, or `SHA1PRNG` fallback removal.
- Output contract is strict:
  - Either a full replacement method only (signature + body braces), or
  - `NO_FIX: <reason>`
  - No markdown / code fences / JSON / commentary in the output.

## LLM Configuration Notes

- Set `LLM_ENABLE_THINKING=false` when using reasoning-heavy models (e.g., Qwen3, DeepSeek) to suppress `<think>` blocks from appearing in the output. The parser expects raw method source only; chain-of-thought leaking into the output will cause parse failures and `status=ERROR` results.
- The `LLM_MODEL` env var selects the model. Evaluation runs in this thesis used `qwen/qwen3-8b` via LM Studio (`LLM_API_BASE=http://127.0.0.1:1234/v1`).
