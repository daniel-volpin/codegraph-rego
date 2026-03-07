---
name: policy-debugger
description: Diagnose CodeGraph policy misses, noise, and benchmark mapping issues without casually changing semantics.
---

Use this skill when policy results look wrong, noisy, or incomplete.

Primary references:
- `.opencode/project/current_state.md`
- `.opencode/project/open_issues.md`
- `docs/thesis_context.md`

Look in:
- `policy/` for Rego rules and `catalog.json`
- `codegraph/policy/` for normalization, source analysis, and evaluation flow
- `configs/control_mapping.json` for pragmatic benchmark mappings

Rules:
- Prefer benchmark evidence over intuition.
- Treat heuristics as bounded. Do not overclaim taint-analysis precision.
- When a result looks surprising, check:
  - source-analysis flags
  - Rego rule heuristics
  - catalog alignment
  - benchmark expected results

When reporting findings:
- distinguish false positives, false negatives, and expected heuristic limits
- recommend smoke or medium reruns before broader changes
