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

The current repo-tracked thesis evidence outputs are `outputs/thesis_final_detection_full_v2/`, `outputs/thesis_final_explanation_full_v2/`, and `outputs/thesis_final_remediation_v2/`. The follow-up provenance-backed reruns are under `outputs/thesis_final_remediation_v3/` and `outputs/thesis_final_remediation_v4/`; cite the artifact directory plus the SHA recorded in each `provenance.json`. Earlier runs under `outputs/detection_calibration_path_precision_v4/` and `outputs/repro_supported_medium_branch_benchmarktest01017_fix/` are preserved as historical reference only.

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

The tracked detection artifact set is
`outputs/thesis_final_detection_full_v2/`. It carries bootstrap CIs and a
per-run `provenance.json`:

```bash
python run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_detection_full_v2 \
  --reset-neo4j
```

## 7. Run Thesis-Final Explanation Evaluation

The v1 baseline measured `Citation@Context` on the TP cohort only. The v2
run additionally evaluates the FP cohort (citation grounding on the
detector's false positives) and emits Wilson 95% CIs on every rate.
Re-run into a fresh directory:

```bash
LLM_CONCURRENCY=1 \
python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_explanation_full_v2 \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j
```

### Resuming a crashed or interrupted explanation run

The explanation eval (~90 min wall-clock) is the longest leg of the
pipeline. If it is interrupted, pass `--resume` on the next invocation
with the same `--output-dir`: the runner reads `request_metrics.jsonl`,
treats every violation whose `with_context` and `without_context` rows
are both already on disk as complete (no LLM calls), and appends to
the existing artifacts rather than truncating them.

```bash
# First run is interrupted after, say, 4 of 8 categories.
LLM_CONCURRENCY=1 \
python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_explanation_full_v2 \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j \
  --resume
```

Notes:

- Violations with a partially-complete pair (only one context mode on disk)
  are redone so the with/without semantics stay symmetric.
- `--reset-neo4j` is still safe with `--resume`: the graph is rebuilt
  from the same staged subset deterministically, and the OPA evaluation
  is a pure function of the bundle.
- Per-category sample budget (`--sample-per-category`) applies only to
  newly-executed violations on the resume run; samples written by the
  prior run remain untouched.

## 8. Run Thesis-Final Supported Remediation

The v2 baseline at `outputs/thesis_final_remediation_v2/` is preserved.
The defensibility pass splits the calibration into three populations
(full / attempted_only / no_fix_only). The provenance-backed fallback is
preserved under `outputs/thesis_final_remediation_v3/`:

```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_remediation_v3 \
  --sample-size 60 \
  --reset-neo4j
```

After the raw-source evidence preservation fix, promote the clean
supported-medium remediation artifact under `outputs/thesis_final_remediation_v4/`:

```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_remediation_v4 \
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

Every eval run also writes a `provenance.json` with the git SHA, OPA
version, model id, seed, config sha256, uv.lock hash, and pyproject hash.
This is the canonical per-run manifest; cite it alongside any number you
quote from the artifact.

Latest PR #107 rerun snapshot (2026-05-03):

- detection v2 (`outputs/thesis_final_detection_full_v2/`): precision
  `0.9528` (95% bootstrap CI `[0.9253, 0.9780]`), recall `0.9528`
  (`[0.9253, 0.9774]`), F1 `0.9528` (`[0.9314, 0.9709]`);
  provenance SHA `7ad90a2`.
- explanation v2 (`outputs/thesis_final_explanation_full_v2/`):
  `Citation@TP=1.000` (`222/222`), `Citation@TP@NoContext=0.009`
  (`2/222`), `Citation@FP=1.000` (`9/9`),
  `Citation@FP@NoContext=0.000` (`0/9`); provenance SHA `701d051`.
- remediation v3 (`outputs/thesis_final_remediation_v3/`): fully verified
  success rate `0.72` (`18/25`), build success rate `0.90` (`18/20`
  attempted builds), full-population Brier `0.095431` / ECE `0.095705`,
  attempted-only Brier `0.094698` / ECE `0.083900`, no-fix-only Brier
  `0.110091` / ECE `0.331800`; provenance SHA `7ad90a2`.
- remediation v4 (`outputs/thesis_final_remediation_v4/`): raw-source
  evidence preservation fix applied; fully verified success rate `1.00`
  (`25/25`), build success rate `1.00` (`25/25` attempted builds).

### Detection

- `metrics.json` — per-category `tp/fp/fn/precision/recall/f1` and overall.
  v2 adds `precision_ci`, `recall_ci`, `f1_ci` (percentile bootstrap, 2000
  resamples by default, deterministic given the selection seed) and
  `precision_ci_wilson`, `recall_ci_wilson` (closed-form sanity checks).
- `metrics.csv` — point estimates only (CSV stays backward-compatible;
  CIs live in JSON).
- `table.md` or `table.tex`
- `provenance.json`

### Explanation

- `citation_metrics.json` — per-category and overall metrics.
  - **Legacy top-level fields** (`count`, `with_context`, `without_context`,
    `rate_with_context`, `rate_without_context`) preserve their prior
    meaning: they refer to the **TP cohort**.
  - v2 adds `tp.*` and `fp.*` blocks with the same shape; each carries
    Wilson 95% CIs as `rate_with_context_ci` and `rate_without_context_ci`.
  - v2 adds a `metric_definitions` block that documents `Citation@TP`,
    `Citation@FP`, `Citation@NoContext`, and the legacy alias.
- `citation_metrics.csv` — v2 has columns
  `tp_count, citation_at_tp_with_context, citation_at_tp_without_context,
  fp_count, citation_at_fp_with_context, citation_at_fp_without_context`.
- `table.md` or `table.tex` — v2 columns:
  `Category, TP Count, Citation@TP (ctx), Citation@TP (no-ctx), FP Count,
  Citation@FP (ctx), Citation@FP (no-ctx)`.
- `explanation_samples.jsonl` — v2 entries carry a new `cohort` field
  (`"tp"` or `"fp"`).
- `request_metrics.jsonl` — v2 entries carry the same `cohort` field.
- `progress.json`, `partial_metrics.json`
- `provenance.json`

### Remediation

- `remediation_metrics.json`
- `remediation_metrics.csv`
- `confidence_calibration.json` / `remediation_calibration.json`
  - **Legacy top-level fields** (`count`, `brier_score`, `ece`,
    `reliability_bins`, `risk_coverage`, `cases`) preserve their prior
    meaning: they refer to the **full population**.
  - v3 adds a `populations` block with three sub-blocks: `full`,
    `attempted_only` (status in `OK / GENERATION_ERROR / REPLACEMENT_ERROR
    / BUILD_ERROR / VERIFICATION_ERROR`), and `no_fix_only` (status
    `NO_FIX`). Each has its own `count`, `brier_score`, `ece`,
    `reliability_bins`, `risk_coverage`, `cases`.
- `remediation_calibration.md` — v3 includes a "Calibration by Population"
  table.
- `table.md` or `table.tex`
- `summary.md`
- `provenance.json`

## 11. Interpretation

- Detection is the baseline validity check.
  - v2 adds bootstrap CIs alongside the point estimates. Quote both when
    reporting per-category numbers; the per-category sample sizes (60 by
    default) make the intervals informative.
- Explanation evaluation is mainly about citation grounding, not prose quality.
  - **Citation@TP** is the v1 metric (renamed for clarity): with-context
    citation rate over violations on positive testcases.
  - **Citation@FP** (new in v2) measures the same grounding behavior on
    the detector's false positives. A high Citation@FP means the model
    grounds its answer correctly even when the underlying detection is
    wrong; a low Citation@FP means the model wanders off-evidence on the
    detector's mistakes. Both are useful — Citation@TP is the headline,
    Citation@FP is the defensibility check.
  - **Citation@NoContext** is reported per cohort. It measures the
    model's behavior under a stricter, no-evidence-card schema with
    zeroed graph + vector context, **not** the model's ability to recover
    a path it has never seen (the violation's `file_path` and line range
    are still part of the prompt assembly inputs). See
    `docs/thesis_context.md` § "Ablation Semantics".
- Remediation is judged by fix success and re-verification, not just patch text.
- Production-minded remediation is intentionally bounded:
  - full support for weak hash and weak randomness
  - guarded support for weak crypto
  - explanation/manual-only for SQL injection, path traversal, command injection, LDAP injection, XPath injection, and broad access-control/logging findings
- `NO_FIX` is an expected safe outcome for guarded remediation, not a crash.
  - v3 reports calibration over **three populations**:
    - `full` — every result with a confidence score (legacy headline).
    - `attempted_only` — calibrated success probability on cases the
      system actually tried to fix. This is the right number for
      "is the confidence score predictive of fix success?".
    - `no_fix_only` — knew-when-to-abstain calibration on declared
      abstentions. Treat low confidence on `NO_FIX` cases as
      well-calibrated abstention, not as failure.
  - Cite the population explicitly when quoting Brier/ECE; the legacy
    top-level Brier/ECE is the full-population alias.
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
