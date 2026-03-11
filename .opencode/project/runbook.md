# Runbook

## What To Run

### Detection full
```bash
OWASP_BENCHMARK_ROOT="/abs/path/to/BenchmarkJava" \
.venv/bin/python3 run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --output-dir outputs/detection_calibration_path_precision_v4 \
  --table-format md
```

### Explanation full
```bash
OWASP_BENCHMARK_ROOT="/abs/path/to/BenchmarkJava" \
LLM_API_BASE="http://localhost:1234/v1" \
LLM_API_KEY="lm-studio" \
LLM_MODEL="qwen3.5-9b-mlx" \
LLM_ENABLE_THINKING=false \
.venv/bin/python3 run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --output-dir outputs/thesis_final_explanation_full \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --table-format md
```

### Supported remediation medium
```bash
OWASP_BENCHMARK_ROOT="/abs/path/to/BenchmarkJava" \
REMEDIATION_LLM_MODEL="qwen/qwen3-coder-30b" \
LLM_ENABLE_THINKING=false \
.venv/bin/python3 run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --output-dir outputs/repro_supported_medium_branch_benchmarktest01017_fix \
  --sample-size 60
```

## Expected Runtime

- Detection full: about 1 minute
- Explanation full: about 45 to 90 minutes
- Supported remediation medium: about 1.5 to 3 hours

## Output Locations

- Detection: `outputs/detection_calibration_path_precision_v4/`
- Explanation: `outputs/thesis_final_explanation_full/`
- Remediation: `outputs/repro_supported_medium_branch_benchmarktest01017_fix/`
  - current-main regression reference: `outputs/final_full_remediation_current_main/`

## Reporting Summary

Generate a compact thesis/PR/supervisor report from existing artifacts:

```bash
.venv/bin/python3 scripts/evaluation/report_benchmark_results.py \
  --outputs-root outputs \
  --output-dir outputs/reporting/baseline_freeze_v0_2_0
```

This writes:

- `outputs/reporting/baseline_freeze_v0_2_0/report.json`
- `outputs/reporting/baseline_freeze_v0_2_0/report.md`

The default report compares:

- authoritative detection baseline
- authoritative explanation baseline
- authoritative compile-backed supported remediation
- current-main remediation regression reference
- current compile-backed bounded remediation

## Which Results To Cite

- For benchmark-backed baseline claims, cite:
  - `outputs/detection_calibration_path_precision_v4/`
  - `outputs/thesis_final_explanation_full/`
  - `outputs/repro_supported_medium_branch_benchmarktest01017_fix/`
- Treat `outputs/final_full_remediation_current_main/` as a regression/reference run, not the headline remediation baseline.

## Real-World Case Studies

Case-study packaging and acquisition instructions live under `demo/case-studies/`.

Keep case-study outputs separate from benchmark evidence:

- `outputs/case_study_spring_petclinic/`
- `outputs/case_study_gs_securing_web/`
- consolidated benchmark + case-study report:
  - `outputs/reporting/baseline_freeze_v0_2_0/`

## Done Means

- Detection:
  - `metrics.json`, `metrics.csv`, `table.md`
- Explanation:
  - `citation_metrics.json`, `citation_metrics.csv`, `table.md`
- Remediation:
  - `remediation_metrics.json`, `remediation_metrics.csv`
  - live-progress artifacts during the run: `progress.json`, `results.jsonl`, `cases/<case-id>/`
  - for product-gate evidence also check `summary.md`

## Skill / Agent Usage

- Use `benchmark-runner` or `@benchmark-operator` for running and interpreting benchmark workflows.
- Use `policy-debugger` when detection results look wrong or noisy.
- Use `remediation-evaluator` for supported remediation quality checks.
- Use `thesis-results` for paper-ready summaries.
