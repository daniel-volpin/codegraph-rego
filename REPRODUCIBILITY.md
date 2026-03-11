# Reproducibility Guide

This file is the shortest path to rerun the thesis-final evaluation pipeline on this branch.

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
export LLM_MODEL=qwen3.5-9b-mlx
export LLM_ENABLE_THINKING=false
export LLM_MODEL_TTL_SECONDS=180

# Optional remediation-specific overrides
export REMEDIATION_LLM_MODEL=qwen/qwen3-coder-30b
export REMEDIATION_LLM_MAX_TOKENS=2048
export REMEDIATION_LLM_TEMPERATURE=0.0
export REMEDIATION_LLM_MODEL_TTL_SECONDS=300
```

If you are using LM Studio with different explanation/remediation models, enable LM Studio's `Auto-Evict` setting. CodeGraph now sends per-request TTL hints so idle models can be unloaded automatically.

## 3. Recommended Explanation-Eval Defaults
Use these settings for local Qwen/LM Studio runs:
- `LLM_CONCURRENCY=1`
- `--evidence-mode lean`
- `--llm-max-tokens-eval 192`

The runner already enables:
- structured JSON-schema output
- explicit stop sequences for local completions
- live progress and request-level metrics

Interactive UI explains now use the same structured `citation` / `why` / `fix` response shape, so the frontend no longer depends on freeform model prose behaving well.

## 4. Choose a Config
- thesis-final detection/explanation: `configs/benchmark/multicat_full.json`
- thesis-final supported remediation: `configs/benchmark/remediation_supported_medium.json`
- small smoke: `configs/benchmark/smoke_mixed.json`
- medium calibration check: `configs/benchmark/multicat_medium.json`
- remediation smoke: `configs/benchmark/remediation_hash_smoke.json`
- bounded remediation refresh: `configs/benchmark/remediation_bounded_smoke.json`
- benchmark demo upload prep: `configs/benchmark/framework_demo.json`
- expanded benchmark evaluation: `configs/benchmark/expanded_eval.json`

Canonical benchmark configs live under `configs/benchmark/`.

## 4a. Build the Recommended Demo Upload
For the live thesis/demo UI flow, use the curated OWASP Benchmark pack instead of a generic sample app:

```bash
python3 scripts/evaluation/build_benchmark_demo_pack.py \
  --benchmark-root "$OWASP_BENCHMARK_ROOT" \
  --output-dir demo/benchmark-framework-demo/build
```

This creates:
- `demo/benchmark-framework-demo/build/benchmark-framework-demo/`
- `demo/benchmark-framework-demo/build/benchmark-framework-demo.zip`

The selected benchmark cases cover:
- full remediation: `ISO-A.10-WEAK-HASH`, `ISO-A.10-WEAK-RANDOM`
- guarded remediation: `ISO-A.10-WEAK-CRYPTO`
- explanation/manual-only: `ISO-A.8-SQL-INJECTION`, `ISO-A.8-PATH-TRAVERSAL`, `ISO-A.8-CMD-INJECTION`, `ISO-A.8-LDAP-INJECTION`, `ISO-A.8-XPATH-INJECTION`

For the UI thesis/demo, use the Policy page's `Framework demo focus` preset after upload. That preset sends an explicit `rule_ids` filter to the backend so the grouped table reflects the benchmark-aligned categories rather than the full servlet-heavy policy surface.

## 5. Run Thesis-Final Detection
```bash
python run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/detection_calibration_path_precision_v4 \
  --reset-neo4j
```

## 6. Run Thesis-Final Explanation Evaluation
```bash
LLM_CONCURRENCY=1 \
python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/thesis_final_explanation_full \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j
```

## 7. Run Thesis-Final Supported Remediation
```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/repro_supported_medium_branch_benchmarktest01017_fix \
  --sample-size 60 \
  --reset-neo4j
```

## 8. Optional Smaller Validation Runs

For a bounded remediation refresh across full and guarded support tiers:

```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/control_mapping.json \
  --output-dir outputs/remediation_eval_bounded_smoke \
  --sample-size 3 \
  --reset-neo4j
```

To compare local remediation models on the same bounded subset:

```bash
python scripts/evaluation/run_remediation_model_bakeoff.py \
  --models qwen/qwen3-coder-30b qwen3.5-27b \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --output-dir outputs/remediation_model_bakeoff \
  --sample-size 3 \
  --reset-neo4j
```

## 9. Expected Outputs

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

## 10. Interpretation
- Detection is the baseline validity check.
- Explanation evaluation is mainly about citation grounding, not prose quality.
- Remediation is judged by fix success and re-verification, not just patch text.
- Production-minded remediation is intentionally bounded:
  - full support for weak hash and weak randomness
  - guarded support for weak crypto
  - explanation/manual-only for SQL injection, path traversal, command injection, LDAP injection, XPath injection, and broad access-control/logging findings
- `NO_FIX` is an expected safe outcome for guarded remediation, not a crash.
- Remediation preview/apply now use a strict structured generation contract:
  - `decision`
  - `replacement_method_lines`
  - derived `replacement_method_code`
  - `reason`
  malformed generation payloads surface as `GENERATION_ERROR` rather than ambiguous parser failures.

## 11. Notes
- Use `--reset-neo4j` for reproducible runs.
- Keep separate output directories for separate experiments.
- Policy evaluation excludes Java sources under `src/test/**` to keep findings focused on production-risk code.
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
