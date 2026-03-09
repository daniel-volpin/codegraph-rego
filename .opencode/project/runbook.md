# Runbook

## What To Run

### Detection full
```bash
OWASP_BENCHMARK_ROOT="/abs/path/to/BenchmarkJava" \
.venv/bin/python3 run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --output-dir outputs/thesis_final_detection_full \
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
  --output-dir outputs/span_edit_supported_medium_v2 \
  --sample-size 60
```

## Expected Runtime

- Detection full: about 1 minute
- Explanation full: about 45 to 90 minutes
- Supported remediation medium: about 1.5 to 3 hours

## Output Locations

- Detection: `outputs/thesis_final_detection_full/`
- Explanation: `outputs/thesis_final_explanation_full/`
- Remediation: `outputs/thesis_final_remediation_supported_medium/`
  - current best compile-backed reference: `outputs/repro_supported_medium_main_2026-03-09_13-04-38/`

## Reporting Summary

Generate a compact thesis/PR/supervisor report from existing artifacts:

```bash
.venv/bin/python3 scripts/evaluation/report_benchmark_results.py \
  --outputs-root outputs \
  --output-dir outputs/reporting/latest
```

This writes:

- `outputs/reporting/latest/report.json`
- `outputs/reporting/latest/report.md`

The default report compares:

- thesis-final detection
- thesis-final explanation
- thesis-final remediation
- current compile-backed supported remediation
- current compile-backed bounded remediation

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
