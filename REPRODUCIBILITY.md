# Reproducibility Guide

This document describes how to run the evaluation pipeline for the thesis prototype.

## Prerequisites
- Python 3.10+
- Neo4j 5.x running and reachable at `NEO4J_URI`
- OPA CLI on `PATH`
- Java + Maven (for remediation build checks)
- OWASP Benchmark Java dataset checked out locally
- Optional LLM access via LiteLLM (for explanation/remediation)

## Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export NEO4J_URI=bolt://127.0.0.1:7687
export NEO4J_USER=neo4j
export NEO4J_PASS=your_password
```

## Configure the Benchmark
Edit these files:
- `configs/benchmark_selection.json`
  - `benchmark_root`: absolute path to OWASP Benchmark
  - For the `BenchmarkJava` repo, set `ground_truth_path` to `expectedresults-1.2.csv`
  - `categories`: subset of category ids to evaluate
  - `max_cases_per_category`: keep scope small (2–4 categories recommended)
  - `build_command`: command for remediation build checks
- `configs/control_mapping.json`
  - map ISO/ASVS controls → CWE → Rego rule ids
  - for OWASP BenchmarkJava, consider `crypto` (CWE-327) and `hash` (CWE-328)
- `debug_fn_analysis` (in selection config)
  - when true, writes `fn_analysis.jsonl` with per-testcase context

Optional schema check:
```bash
python inspect_benchmark_schema.py --config configs/benchmark_selection.json
```

## Run the Evaluation Pipelines

### 1) Benchmark Evaluation (Precision/Recall/F1)
```bash
python run_benchmark_eval.py --config configs/benchmark_selection.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/benchmark_eval \
  --reset-neo4j
```

Outputs:
- `outputs/benchmark_eval/metrics.json`
- `outputs/benchmark_eval/metrics.csv`
- `outputs/benchmark_eval/table.md` (or `table.tex`)

### 2) Explanation Citation Success (Ablation)
```bash
python run_explanation_eval.py --config configs/benchmark_selection.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/explanation_eval \
  --reset-neo4j
```

Outputs:
- `outputs/explanation_eval/citation_metrics.json`
- `outputs/explanation_eval/citation_metrics.csv`
- `outputs/explanation_eval/table.md` (or `table.tex`)
- `outputs/explanation_eval/explanation_samples.jsonl`

### 3) Remediation Success Metrics
```bash
python run_remediation_eval.py --config configs/benchmark_selection.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/remediation_eval \
  --sample-size 10 \
  --reset-neo4j
```

Outputs:
- `outputs/remediation_eval/remediation_metrics.json`
- `outputs/remediation_eval/remediation_metrics.csv`
- `outputs/remediation_eval/table.md` (or `table.tex`)

## Embedding Cache (Performance)
Embedding builds now reuse cached vectors to avoid re-encoding unchanged methods.
- Cache location: `index/embedding_cache.json` (`EMBEDDING_CACHE_PATH`)
- Force a full rebuild:
```bash
python build_code_embeddings.py --rebuild-index
```

## Notes
- `--reset-neo4j` is recommended for deterministic metrics (clears the graph).
- Explanation/remediation runs require LLM access; without it, output will contain fallback text.
- Keep category scope small (2–4) to keep runs reproducible and fast.
