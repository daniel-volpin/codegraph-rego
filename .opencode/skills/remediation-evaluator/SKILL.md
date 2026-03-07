---
name: remediation-evaluator
description: Evaluate CodeGraph remediation behavior, model quality, and bounded failure modes using the current structured contract.
---

Use this skill when the task involves remediation quality, model choice, refusal behavior, or fix-and-verify outcomes.

Primary references:
- `.opencode/project/current_state.md`
- `.opencode/project/open_issues.md`
- `docs/remediation_prompting_design.md`

Rules:
- Keep remediation framework-general. Do not jump to hardcoded per-rule fixes unless explicitly requested.
- Current support tiers:
  - full: weak hash, weak random
  - guarded: weak crypto
  - manual: other benchmark families
- Interpret statuses carefully:
  - `NO_FIX` = safe refusal
  - `GENERATION_ERROR` = malformed model output or invalid code
  - `VERIFICATION_ERROR` = replacement happened but re-check failed

Preferred local model split:
- explanation: `qwen3.5-9b-mlx`
- remediation: `qwen/qwen3-coder-30b`

When evaluating outcomes:
- separate transport/contract issues from model-quality issues
- cite remediation metrics files directly
