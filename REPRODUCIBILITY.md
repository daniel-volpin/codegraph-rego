# Reproducibility Guide

This document describes how to run the evaluation pipeline for the thesis prototype.

## Prerequisites
- Python 3.10+
- Neo4j 5.x running and reachable at `NEO4J_URI`
- OPA CLI on `PATH`
- Java + Maven (for remediation build checks)
- OWASP Benchmark Java dataset checked out locally
- LLM access via LiteLLM — evaluation runs used **qwen/qwen3-8b** loaded in [LM Studio](https://lmstudio.ai) (OpenAI-compatible endpoint). Any OpenAI-compatible model works; set `LLM_ENABLE_THINKING=false` for Qwen3/DeepSeek to suppress `<think>` blocks.

## Environment Setup
```bash
# Install backend deps via uv (do NOT use pip install -r requirements.txt)
pip install uv          # once, if uv is not yet installed
uv sync
source .venv/bin/activate

export NEO4J_URI=bolt://127.0.0.1:7687
export NEO4J_USER=neo4j
export NEO4J_PASS=your_password
export OWASP_BENCHMARK_ROOT="$HOME/path/to/BenchmarkJava"

# LLM config (for explanation and remediation evaluation)
export LLM_PROVIDER=openai              # keep "openai" for LM Studio (OpenAI-compatible)
export LLM_API_BASE=http://127.0.0.1:1234/v1
export LLM_API_KEY=lm-studio           # any non-empty string; LM Studio ignores it
export LLM_MODEL=qwen/qwen3-8b         # model used in thesis evaluation runs
export LLM_ENABLE_THINKING=false       # suppress <think> blocks from Qwen3/DeepSeek models

# Optional: capture raw LLM output on JSON parse failures (default OFF)
export REMEDIATION_RAW_CAPTURE_ENABLED=0
```

## Configure the Benchmark
Use `configs/benchmark_selection.example.json` as the starting template:
```bash
cp configs/benchmark_selection.example.json configs/benchmark_selection.json
```

To evaluate multiple CWE categories (detection + explanation), you can use `configs/benchmark_selection.multicat.json`
directly (or copy it and pin `testcase_ids` for smaller smoke runs).

To evaluate **full oracle coverage** for the selected CWE set (no sampling limit), use:
- `configs/benchmark_selection.multicat_full.json`

Pinned smoke sets (explicit testcase IDs, fast and deterministic):
- `configs/benchmark_selection.pinned_33089.json` (CWE-330 + CWE-89)
- `configs/benchmark_selection.remediation_cwe328_smoke.json` (CWE-328 only; suitable for remediation smoke)

Edit these files as needed:
- `configs/benchmark_selection.json`
  - `benchmark_root`: defaults to `${OWASP_BENCHMARK_ROOT}`
  - For the `BenchmarkJava` repo, `ground_truth_path` should point to `expectedresults-1.2.csv`
  - `categories`: subset of category ids to evaluate
  - `max_cases_per_category`: keep scope small (2–4 categories recommended)
- `configs/control_mapping.json`
  - maps ISO controls → CWE → Rego rule ids
  - includes split A.10 rule ids (`ISO-A.10-WEAK-HASH`, `ISO-A.10-WEAK-CRYPTO`)
  - adds evaluation-only categories for `CWE-330` (`ISO-A.10-WEAK-RANDOM`) and `CWE-89` (`ISO-A.8-SQL-INJECTION`)
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

Full-coverage (selected CWEs only):
```bash
python run_benchmark_eval.py --config configs/benchmark_selection.multicat_full.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/benchmark_eval_multicat_full \
  --reset-neo4j
```

Pinned smoke (CWE-330 + CWE-89):
```bash
python run_benchmark_eval.py --config configs/benchmark_selection.pinned_33089.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/benchmark_eval_pinned33089 \
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

Full-coverage (selected CWEs only):
```bash
python run_explanation_eval.py --config configs/benchmark_selection.multicat_full.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/explanation_eval_multicat_full \
  --reset-neo4j
```

Pinned smoke (CWE-330 + CWE-89):
```bash
python run_explanation_eval.py --config configs/benchmark_selection.pinned_33089.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/explanation_eval_pinned33089 \
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

Pinned smoke (CWE-328 only):
```bash
python run_remediation_eval.py --config configs/benchmark_selection.remediation_cwe328_smoke.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/remediation_eval_cwe328_smoke \
  --sample-size 5 \
  --reset-neo4j
```

Notes:
- This runner reuses the same remediation apply/verify service flow as `/remediation/apply`.
- Default mode is `dry_run` (no persistent source changes).

Outputs:
- `outputs/remediation_eval/remediation_metrics.json`
- `outputs/remediation_eval/remediation_metrics.csv`
- `outputs/remediation_eval/table.md` (or `table.tex`)

## One-Command Experiment Runner (Manifest)
This runs detection, explanation, and (where supported) remediation in sequence and writes a manifest tying outputs to a git SHA:
```bash
python run_experiments.py --config configs/benchmark_selection.multicat_full.json \
  --mapping configs/control_mapping.json \
  --output-root outputs \
  --reset-neo4j
```

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

---

## Results Reference

The following output directories in `outputs/` correspond to recorded evaluation runs:

| Output Directory | Eval Type | Categories | Git SHA | LLM Model | Notes |
|---|---|---|---|---|---|
| `benchmark_eval_pinned33089` | Detection P/R/F1 | CWE-330, CWE-89 | `a4c578f` | — | 6 pinned positive-only test cases |
| `explanation_eval_pinned33089` | Citation success | CWE-330, CWE-89 | `a4c578f` | `qwen/qwen3-8b` | With vs. without graph context |
| `remediation_eval_postcleanup` | Fix success rate | CWE-328 | `a4c578f` | `qwen/qwen3-8b` | 5/5 OPA PASS, dry_run mode |
| `benchmark_eval_smoke33089` | Detection P/R/F1 | CWE-330, CWE-89 | `a4c578f` | — | Smoke subset |

To reproduce the detection run:
```bash
python run_benchmark_eval.py \
  --config configs/benchmark_selection.pinned_33089.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/benchmark_eval_pinned33089 \
  --reset-neo4j
```

To run a mixed positive/negative smoke (new config with FP/TN):
```bash
python run_benchmark_eval.py \
  --config configs/benchmark_selection.smoke_mixed.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/benchmark_eval_smoke_mixed \
  --reset-neo4j
```
