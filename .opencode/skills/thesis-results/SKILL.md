---
name: thesis-results
description: Summarize CodeGraph benchmark results accurately for thesis writing, PRs, and supervisor updates.
---

Use this skill when the task is to summarize or interpret thesis-grade benchmark outputs.

Primary references:
- `.opencode/project/benchmark_latest.md`
- `.opencode/project/current_state.md`
- `.opencode/project/open_issues.md`
- `outputs/reporting/baseline_freeze_v0_2_0/report.md`

Rules:
- Use benchmark outputs, not memory, as the authoritative source.
- Prefer the consolidated baseline report when it covers the question, then drill into raw output folders only if needed.
- Separate:
  - detection breadth
  - explanation quality
  - bounded remediation performance
- Do not overclaim:
  - universal remediation
  - compile-backed verification when `build_attempted=0`
  - full taint-analysis precision

Preferred summary style:
- one compact headline result block
- then the main caveats
- then the next recommended improvement
