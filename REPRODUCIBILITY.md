# Reproducibility Guide

This file is the shortest path to rerun the thesis evaluation pipeline on this branch.

## 1. Prerequisites
- Python 3.10+
- Neo4j 5.x
- OPA on `PATH`
- Java + Maven
- local checkout of `BenchmarkJava`
- LM Studio or another OpenAI-compatible LLM endpoint for explanation/remediation runs

## 2. Environment
```bash
uv sync
source .venv/bin/activate

export NEO4J_URI=bolt://127.0.0.1:7687
export NEO4J_USER=neo4j
export NEO4J_PASS=your_password
export OWASP_BENCHMARK_ROOT="$HOME/path/to/BenchmarkJava"

export LLM_PROVIDER=openai
export LLM_API_BASE=http://localhost:1234/v1
export LLM_API_KEY=lm-studio
export LLM_MODEL=qwen/qwen3-8b
export LLM_ENABLE_THINKING=false
```

## 3. Recommended Explanation-Eval Defaults
Use these settings for local Qwen/LM Studio runs:
- `LLM_CONCURRENCY=1`
- `--evidence-mode lean`
- `--llm-max-tokens-eval 192`

The runner already enables:
- structured JSON-schema output
- explicit stop sequences for local completions
- live progress and request-level metrics

## 4. Choose a Config
- small smoke: `configs/benchmark_selection.smoke_mixed.json`
- medium thesis check: `configs/benchmark_selection.multicat_medium.json`
- full selected-category run: `configs/benchmark_selection.multicat_full.json`
- remediation smoke: `configs/benchmark_selection.remediation_cwe328_smoke.json`

## 5. Run Detection
```bash
python run_benchmark_eval.py \
  --config configs/benchmark_selection.multicat_medium.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/benchmark_eval_multicat_medium \
  --reset-neo4j
```

## 6. Run Explanation Evaluation
```bash
LLM_CONCURRENCY=1 \
python run_explanation_eval.py \
  --config configs/benchmark_selection.multicat_medium.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/explanation_eval_multicat_medium \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j
```

## 7. Run Remediation Evaluation
```bash
python run_remediation_eval.py \
  --config configs/benchmark_selection.remediation_cwe328_smoke.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/remediation_eval_cwe328_smoke \
  --sample-size 5 \
  --reset-neo4j
```

## 8. Expected Outputs

### Detection
- `metrics.json`
- `metrics.csv`
- `table.md` or `table.tex`

### Explanation
- `citation_metrics.json`
- `citation_metrics.csv`
- `table.md` or `table.tex`
- `explanation_samples.jsonl`
- `progress.json`
- `partial_metrics.json`
- `request_metrics.jsonl`

### Remediation
- `remediation_metrics.json`
- `remediation_metrics.csv`
- `table.md` or `table.tex`

## 9. Interpretation
- Detection is the baseline validity check.
- Explanation evaluation is mainly about citation grounding, not prose quality.
- Remediation is judged by fix success and re-verification, not just patch text.

## 10. Notes
- Use `--reset-neo4j` for reproducible runs.
- Keep separate output directories for separate experiments.
- Secondary operator utilities now live under `scripts/`:
  - `scripts/ingestion/codebase_to_neo4j.py`
  - `scripts/ingestion/build_code_embeddings.py`
  - `scripts/search/hybrid_code_search.py`
  - `scripts/policy/policy_eval_cli.py`
  - `scripts/evaluation/inspect_benchmark_schema.py`
  - `scripts/evaluation/run_experiments.py`
- If the local LLM behaves badly, first inspect:
  - `progress.json`
  - `request_metrics.jsonl`
  - LM Studio logs (`finish_reason`, completion tokens, stop behavior)
