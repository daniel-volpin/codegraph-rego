---
name: benchmark-runner
description: Run CodeGraph benchmark workflows with canonical configs, expected runtimes, and output locations.
---

Use this skill when the task is to run, rerun, or summarize benchmark evaluation workflows.

Primary references:
- `.opencode/project/runbook.md`
- `.opencode/project/current_state.md`
- `.opencode/project/benchmark_latest.md`
- `outputs/reporting/baseline_freeze_v0_2_0/report.md`

Rules:
- Prefer canonical configs under `configs/benchmark/`.
- Use smoke configs for quick validation, medium configs for calibration, and full configs for thesis-grade runs.
- Preserve benchmark semantics. Do not silently switch config families.
- Report output paths under `outputs/`.

Default operating order:
1. detection
2. explanation
3. supported remediation

When summarizing results:
- cite the output files
- distinguish authoritative baselines from later regression/reference runs
- include runtime expectations if the user is planning a run
- separate benchmark evidence from qualitative app demos
