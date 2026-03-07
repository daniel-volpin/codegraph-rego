# Remediation Prompting Design (Thesis)

## Current State

The backend remediation flow (`codegraph/remediation/service.py`) selects a rule strategy by `rule_id` and constructs an LLM prompt for a "virtual fix" preview and an "apply+verify" loop.

- Prompt roles: `system` + `user` (no `developer` role).
- The system prompt is stable and rule-agnostic; rule-specific objectives are passed through a deterministic `TASK_SPEC` JSON block in the user message.
- The user message includes the violation + evidence (source snippet, graph context, vector context, control metadata).
- Unsupported rules return `status=INVALID` with `error=unsupported_rule_for_auto_fix` without calling the LLM.
- Guarded rules may return structured `decision="no_fix"` with a reason to refuse unsafe remediations.

## Production-Minded Support Matrix

The thesis/demo surface now uses a bounded remediation matrix:

- Full support:
  - `ISO-A.10-WEAK-HASH`
  - `ISO-A.10-WEAK-RANDOM`
- Guarded support:
  - `ISO-A.10-WEAK-CRYPTO`
- Manual review only:
  - `ISO-A.8-SQL-INJECTION`
  - `ISO-A.8-PATH-TRAVERSAL`
  - `ISO-A.8-CMD-INJECTION`
  - `ISO-A.8-LDAP-INJECTION`
  - `ISO-A.8-XPATH-INJECTION`
  - access-control findings such as `ISO-A.9.4.1`

This is intentional. "Production-ready" in this repo means deterministic support boundaries, auditable refusal behavior, and dry-run verification gates, not universal autonomous repair.

## Decision

Use a **single, stable "Remediation Agent" system prompt** across supported rules, and provide a per-rule **TASK_SPEC** as a deterministic JSON block in the user message.

This corresponds to: "one agent, bounded capability set" where rule IDs select a small objective/constraints payload.

## Why This Fits the Thesis

- **Clarity:** one agent prompt and one output contract; the per-rule logic is transparent and minimal.
- **Reproducibility:** the system prompt is stable; the task spec is deterministic JSON with fixed delimiters.
- **Evaluation fairness:** improvements are attributable to (a) detector coverage and (b) apply+verify correctness gates, not per-rule prompt engineering.

## Structured Output Contract

Remediation generation now uses an OpenAI-compatible `json_schema` response format with `strict: true`.

Required fields:
- `decision: "replace_method" | "no_fix"`
- `replacement_method_lines: string[] | null`
- derived `replacement_method_code: string | null`
- `reason: string | null`

Rules:
- `replace_method` requires a non-empty `replacement_method_lines`
- `no_fix` requires a non-empty `reason`
- extra fields are rejected

The service converts that schema into the additive API payload:
- `generation.decision`
- `generation.replacement_method_lines`
- `generation.replacement_method_code` is reconstructed server-side for compatibility
- `generation.reason`
- `generation.raw_response_valid`
- `generation.schema_error`

## Invariants

- The system prompt is rule-agnostic and must not encode rule-specific details (e.g., no MD5/SHA-256 strings).
- Unsupported rule IDs never call the LLM and return `INVALID`.
- SQL injection remediation remains unsupported.
- Guarded weak-crypto remediation is allowed only for explicit literal weak-cipher subcases with enough method-local context to support a safe minimal change.
- Weak-random remediation is allowed only for narrow local transformations such as `Random` to `SecureRandom`, `Math.random()` replacement, or `SHA1PRNG` fallback removal.
- Output contract is strict JSON only. Free-form method text is no longer the primary protocol.

## LLM Configuration Notes

- Set `LLM_ENABLE_THINKING=false` when using reasoning-heavy models (e.g., Qwen3, DeepSeek). The correctness mechanism is the structured schema, not heuristic stripping of `<think>` blocks.
- The shared `LLM_MODEL` env var still works, but remediation can now use dedicated overrides:
  - `REMEDIATION_LLM_MODEL`
  - `REMEDIATION_LLM_MAX_TOKENS`
  - `REMEDIATION_LLM_TEMPERATURE`
- A code-editing model is preferred for remediation over a lighter explanation model.
