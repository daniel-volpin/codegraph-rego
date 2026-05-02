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

### Environment Variable Reference

Every variable consumed by `codegraph.config.Settings`, the upload pipeline, the
remediation gate, and the OpenTelemetry layer. `.env.example` ships matching
defaults — keep it in sync when adding new variables.

| Variable | Default | Effect |
| --- | --- | --- |
| `NEO4J_URI` | `bolt://127.0.0.1:7687` | Neo4j Bolt endpoint. Required at runtime. |
| `NEO4J_USER` | `neo4j` | Neo4j auth user. Required. |
| `NEO4J_PASS` | _unset_ | Neo4j auth password. Required (no default). |
| `OWASP_BENCHMARK_ROOT` | _unset_ | Absolute path to the local `BenchmarkJava` checkout. Required for benchmark eval scripts. |
| `LLM_PROVIDER` | `openai` | LLM transport family (currently OpenAI-compatible only). |
| `LLM_API_BASE` | `http://localhost:1234/v1` | OpenAI-compatible base URL (LM Studio, vLLM, etc.). |
| `LLM_API_KEY` | _unset_ | API key sent to the LLM endpoint. Use `lm-studio` for LM Studio. |
| `LLM_MODEL` | `qwen3.5-9b-mlx` | Default explanation model. |
| `LLM_TEMPERATURE` | `0.2` | Sampling temperature for explanation. Note: not zero; outputs are not bitwise reproducible. |
| `LLM_ENABLE_THINKING` | `false` | Disable extended thinking on supported models. |
| `LLM_CONCURRENCY` | `2` | Max parallel LLM requests during eval. |
| `LLM_MAX_TOKENS_EXPLANATION` | `512` | Generation cap for the explanation task. |
| `LLM_MAX_TOKENS_REMEDIATION` | `1024` | Generation cap for the remediation task. |
| `LLM_MODEL_TTL_SECONDS` | `180` | Per-request TTL hint sent to LM Studio for auto-eviction. |
| `REMEDIATION_LLM_MODEL` | `qwen/qwen3-coder-30b` | Override model for remediation generation. |
| `REMEDIATION_LLM_MAX_TOKENS` | `2048` | Override max tokens for remediation. |
| `REMEDIATION_LLM_TEMPERATURE` | `0.0` | Remediation sampling temperature. Lower than explanation; not strictly deterministic. |
| `REMEDIATION_LLM_MODEL_TTL_SECONDS` | `300` | LM Studio TTL hint for the remediation model. |
| `REMEDIATION_RAW_CAPTURE_ENABLED` | `0` | Persist raw LLM outputs alongside structured ones (audit aid). |
| `REMEDIATION_CONFIDENCE_GATE_ENABLED` | `1` | Enforce the confidence gate on `mode="apply"`. **Disabling this allows low-confidence patches to apply.** |
| `REMEDIATION_CONFIDENCE_THRESHOLD_APPLY` | `0.75` | Sigmoid threshold above which `apply_edits` proceeds. |
| `REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW` | `0.50` | Threshold for `review` band; below this falls to `abstain`. |
| `REMEDIATION_CONFIDENCE_TEMPERATURE` | `1.0` | Sigmoid temperature scaling for confidence calibration. |
| `REMEDIATION_TRACE_PROMPT_ENABLED` | `0` | Persist remediation prompt + trace context for audit. |
| `UI_REVIEW_STORE_PATH` | `outputs/policy_ui_reviews/reviews.jsonl` | JSONL append target for human review feedback from the UI. |
| `UPLOAD_MAX_ARCHIVE_SIZE_BYTES` | `104857600` | Max total upload archive size (100 MB). |
| `UPLOAD_MAX_MEMBER_SIZE_BYTES` | `52428800` | Max single-file size inside an archive (50 MB). |
| `UPLOAD_MAX_EXTRACTED_SIZE_BYTES` | `524288000` | Max total extracted size (500 MB). Bomb defence. |
| `UPLOAD_MAX_ARCHIVE_ENTRIES` | `10000` | Max archive entry count. |
| `UPLOAD_MAX_COMPRESSION_RATIO` | `100.0` | Max per-entry compression ratio. Bomb defence. |
| `OTEL_SDK_DISABLED` | _unset_ | Set to `true` to silence all OpenTelemetry tracing. |
| `OTEL_TRACE_FILE` | _unset_ | If set, write spans to this JSONL file instead of stdout. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _unset_ | OTLP endpoint URL for an external collector (Grafana Tempo, etc.). |

## 3. Branch Verification Contract

Use these commands as the baseline-recovery gate on this branch:

```bash
.venv/bin/ruff check .
UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q
cd frontend && yarn build
```

For branch-local smoke evidence, write new outputs under `outputs/branch_baseline_recovery/`:

```bash
python run_benchmark_eval.py \
  --config configs/benchmark/smoke_mixed.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/branch_baseline_recovery/detection_smoke \
  --reset-neo4j

python run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/branch_baseline_recovery/remediation_bounded_smoke \
  --sample-size 3 \
  --reset-neo4j
```

Thesis-final authoritative outputs are under `outputs/thesis_final_detection_full/`, `outputs/thesis_final_explanation_full/`, and `outputs/thesis_final_remediation_v2/` (all produced on `main` on 2026-03-22). The earlier runs under `outputs/detection_calibration_path_precision_v4/` and `outputs/repro_supported_medium_branch_benchmarktest01017_fix/` are preserved as historical reference only.

## 4. Recommended Explanation-Eval Defaults

Use these settings for local Qwen/LM Studio runs:

- `LLM_CONCURRENCY=1`
- `--evidence-mode lean`
- `--llm-max-tokens-eval 192`

The runner already enables:

- structured JSON-schema output
- explicit stop sequences for local completions
- live progress and request-level metrics

Interactive UI explains now use the same structured `citation` / `why` / `fix` response shape, so the frontend no longer depends on freeform model prose behaving well.

## 5. Choose a Config

- thesis-final detection/explanation: `configs/benchmark/multicat_full.json`
- thesis-final supported remediation: `configs/benchmark/remediation_supported_medium.json`
- small smoke: `configs/benchmark/smoke_mixed.json`
- medium calibration check: `configs/benchmark/multicat_medium.json`
- remediation smoke: `configs/benchmark/remediation_hash_smoke.json`
- bounded remediation refresh: `configs/benchmark/remediation_bounded_smoke.json`
- benchmark demo upload prep: `configs/benchmark/framework_demo.json`
- expanded benchmark evaluation: `configs/benchmark/expanded_eval.json`

Canonical benchmark configs live under `configs/benchmark/`.

## 5a. Build the Recommended Demo Upload

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

## 6. Run Thesis-Final Detection

```bash
python run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_detection_full \
  --reset-neo4j
```

## 7. Run Thesis-Final Explanation Evaluation

```bash
LLM_CONCURRENCY=1 \
python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_explanation_full \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j
```

## 8. Run Thesis-Final Supported Remediation

```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_remediation_v2 \
  --sample-size 60 \
  --reset-neo4j
```

For the baseline-recovery branch, prefer this branch-local output directory for the supported-medium rerun:

```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/branch_baseline_recovery/remediation_supported_medium \
  --sample-size 60 \
  --reset-neo4j
```

## 9. Optional Smaller Validation Runs

For a bounded remediation refresh across full and guarded support tiers:

```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/benchmark/policy_registry.json \
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

## 10. Expected Outputs

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

## 11. Interpretation

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

## 12. Notes

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

## 13. Determinism and Reproducibility Caveats

The eval pipeline is **as deterministic as the underlying components allow**.
Read this section before treating any single re-run as canonical.

**Deterministic by construction.**

- Benchmark testcase selection is seeded (`seed` field in every config under
  `configs/benchmark/`; `select_testcases()` is idempotent for a given seed).
- Remediation sampling is seeded via `--seed` (default 11).
- OPA / Rego evaluation is purely functional given an input bundle.
- Confidence band computation in `codegraph/remediation/confidence.py` is a
  closed-form sigmoid with no stochastic component.
- Detection metrics, Brier, and ECE are deterministic given the same inputs.

**Not deterministic across re-runs.**

- LLM outputs depend on the model server (LM Studio / vLLM / etc.), the model
  weights, the quantization, the runtime version, and the host hardware. Even
  with `temperature=0.0` and a fixed seed, identical prompts can produce
  different completions across server restarts and model versions.
- This means `Citation@Context`, `Citation@TP`, and remediation `fix_success`
  may shift by small amounts on re-run. Treat the headline values as a single
  draw, not as point estimates of a fixed distribution.
- Model TTL eviction in LM Studio (`LLM_MODEL_TTL_SECONDS`) reloads the model
  on demand; immediately after a reload, the first few completions can differ
  from later steady-state ones depending on backend-side caches.

**Recommended practice.**

- For headline numbers, run each eval **N=3 times** with different LLM seeds
  (or restarts) and report mean ± standard deviation. The detection numbers
  are deterministic and need no repetition.
- Pin the model version explicitly in `LLM_MODEL` and
  `REMEDIATION_LLM_MODEL`. Record the resolved model and runtime in the
  artifact's `provenance.json` (written by every `run_*_eval.py` script).
- For statistical claims (P, R, F1, Citation@*), prefer the bootstrap and
  Wilson confidence intervals emitted next to the point estimates over
  individual point values.
- When citing thesis-final numbers, cite the artifact directory
  (`outputs/thesis_final_*/`) plus the git tag (`thesis-final-v1`) — not the
  README prose.
