# Reproducibility Guide

This file describes the evaluation workflow for the current source baseline. Published thesis-final results retain their original commit, dependencies, and OPA 1.15.1 provenance. Reproducing those exact results requires that recorded revision; runs of this modernized branch are new evidence, not historical reruns.

## 1. Prerequisites

- Python 3.14+ (the pinned development and CI runtime is 3.14.7)
- uv 0.12.13+
- Neo4j 5.x
- OPA `v1.20.2` on `PATH` (required for `make policy-check` and OPA policy evaluation)
- OpenGrep `v1.30.0+` on `PATH` (required for the injection controls; without it those rules are skipped and detection recall drops silently)
- JDK 21+ and Maven for the JDT adapter; the analyzed project's build may require its own configured Java release
- local checkout of `BenchmarkJava` (as a sibling directory `../BenchmarkJava`, or
  anywhere with `OWASP_BENCHMARK_ROOT` pointing at it)
- LM Studio, OpenAI, or another OpenAI-compatible LLM endpoint for explanation/remediation runs

## 2. Environment

```bash
uv sync
source .venv/bin/activate

export NEO4J_URI=bolt://127.0.0.1:7687
export NEO4J_USER=neo4j
export NEO4J_PASS=your_password
# Optional: only needed if BenchmarkJava is not a sibling of this repo.
# export OWASP_BENCHMARK_ROOT="$HOME/path/to/BenchmarkJava"

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

The operator-facing variables consumed by `codegraph.config.Settings`, the upload pipeline, the remediation gate, and the OpenTelemetry layer (internal path/index overrides live in `codegraph/config.py`). The Default column is the value `Settings` falls back to with nothing set, which is what you are debugging against; `.env.example` sets several of them to local-MLX values instead, so check both.

| Variable | Default | Effect |
| --- | --- | --- |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt endpoint. Required at runtime. |
| `NEO4J_USER` | `neo4j` | Neo4j auth user. Required. |
| `NEO4J_PASS` | _unset_ | Neo4j auth password. Required (no default). |
| `OWASP_BENCHMARK_ROOT` | auto-discovered | Absolute path to the local `BenchmarkJava` checkout. Resolved automatically when the clone sits beside this repository (`../BenchmarkJava`), in it, or at `~/BenchmarkJava`; set it only for a non-standard location. |
| `CODEGRAPH_HOST` | `127.0.0.1` | Bind host for the backend service. Loopback by default for safe local-only operation. |
| `CODEGRAPH_OPA_TIMEOUT` | `120.0` | Per-invocation timeout in seconds for OPA eval subprocesses. |
| `CODEGRAPH_OPENGREP_TIMEOUT` | `120.0` | Per-invocation timeout in seconds for OpenGrep taint subprocesses. |
| `CODEGRAPH_OPENGREP_RULES_DIR` | `policy/opengrep` | Directory of auto-discovered OpenGrep taint rule files. |
| `CODEGRAPH_DETECTION_ENGINES_ENABLED` | `true` | Master switch for non-OPA engines. Disabling drops the rules they own, so coverage falls. |
| `JAVA_PARSER_JAR` | `tools/java-parser/target/codegraph-java-parser.jar` | Explicit path to the Eclipse JDT parser fat jar. Build with `make java-parser-build`; the Python adapter never downloads or builds it at runtime. |
| `JAVA_PARSER_TIMEOUT_SECONDS` | `30.0` | Per-request deadline for the fresh JVM parser process. |
| `JAVA_PARSER_HEAP_MB` | `384` | Heap cap passed as `-Xmx` to each parser JVM. |
| `JAVA_PARSER_MAX_CONCURRENT_REQUESTS` | `4` | Process-local Java parser admission cap (`1..32`); a fresh JVM and AST per request. |
| `JAVA_PARSER_QUEUE_TIMEOUT_SECONDS` | `5.0` | Maximum wait for Java parser admission before failing fast. |
| `JAVA_PARSER_MAX_SOURCE_BYTES` | `4194304` | Maximum UTF-8 Java source payload accepted by the Python adapter. |
| `JAVA_PARSER_MAX_OUTPUT_BYTES` | `16777216` | Maximum stdout JSON payload accepted from the parser process. |
| `JAVA_PARSER_LANGUAGE_LEVEL` | `25` | Default JDT language level sent in parser requests. |
| `LLM_API_BASE` | _unset_ | OpenAI-compatible base URL (LM Studio, vLLM, etc.). Unset means the SDK's own default endpoint. |
| `LLM_API_KEY` | _unset_ | API key sent to the LLM endpoint. Use `lm-studio` for LM Studio. |
| `LLM_MODEL` | `gpt-4o-mini` | Default explanation model. |
| `LLM_API_MODE` | `auto` | Endpoint mode selection (`auto`, `responses`, `chat_completions`). |
| `LLM_TIMEOUT_SECONDS` | `180.0` | Per SDK HTTP operation timeout for model calls (not a total agent-run deadline). |
| `LLM_MAX_CONCURRENT_REQUESTS` | `1` | Process-local cap on active provider SDK/client generation calls, shared by OpenAI-compatible transports. Not global across processes and not a durable run/token budget. |
| `LLM_MAX_PENDING_REQUESTS` | `4` | Process-local cap on provider generation calls waiting for admission before client construction. |
| `LLM_QUEUE_TIMEOUT_SECONDS` | `60.0` | Maximum provider admission queue wait in seconds; separate from `LLM_TIMEOUT_SECONDS`, which applies after SDK/client operation starts. |
| `LLM_MAX_RETRIES` | `0` | SDK transport retries per generation attempt (allowed range `0..2`). |
| `LLM_SEND_TEMPERATURE` | `1` | When `0`, suppresses temperature for providers/models that reject it. |
| `LLM_TEMPERATURE` | `0.2` | Sampling temperature for explanation. Note: not zero; outputs are not bitwise reproducible. |
| `LLM_ENABLE_THINKING` | `true` | Set to `false` to suppress `<think>` blocks on models that emit them (Qwen3, DeepSeek). |
| `LLM_CONCURRENCY` | `1` | Max parallel LLM requests during eval. Keep at 1 for local models. |
| `LLM_MAX_TOKENS_EXPLANATION` | `512` | Generation cap for the explanation task. |
| `LLM_MAX_TOKENS_REMEDIATION` | `1024` | Generation cap for the remediation task. |
| `LLM_MODEL_TTL_SECONDS` | _unset_ | Per-request TTL hint sent to LM Studio for auto-eviction. No hint when unset. |
| `REMEDIATION_LLM_MODEL` | _unset_ | Override model for remediation generation. Falls back to `LLM_MODEL`. |
| `REMEDIATION_LLM_MAX_TOKENS` | _unset_ | Override the remediation generation cap. Falls back to `LLM_MAX_TOKENS_REMEDIATION`. |
| `REMEDIATION_LLM_TEMPERATURE` | _unset_ | Override remediation sampling temperature. Falls back to `LLM_TEMPERATURE`; not strictly deterministic either way. |
| `REMEDIATION_LLM_MODEL_TTL_SECONDS` | _unset_ | LM Studio TTL hint for the remediation model. Falls back to `LLM_MODEL_TTL_SECONDS`. |
| `REMEDIATION_RAW_CAPTURE_ENABLED` | `0` | Persist raw LLM outputs alongside structured ones (audit aid). |
| `REMEDIATION_CONFIDENCE_GATE_ENABLED` | `1` | Enforce the confidence gate on `mode="apply"`. **Disabling this allows low-confidence patches to apply.** |
| `REMEDIATION_CONFIDENCE_THRESHOLD_APPLY` | `0.75` | Sigmoid threshold above which `apply_edits` proceeds. |
| `REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW` | `0.50` | Threshold for `review` band; below this falls to `abstain`. |
| `REMEDIATION_CONFIDENCE_TEMPERATURE` | `1.0` | Sigmoid temperature scaling for confidence calibration. |
| `REMEDIATION_TRACE_PROMPT_ENABLED` | `0` | Persist remediation prompt + trace context for audit. |
| `POLICY_WORKERS` | `2` | OPA/evidence workers per scan; bounded submission caps in-flight+queued tasks at `<= 2 * POLICY_WORKERS`. |
| `UI_REVIEW_STORE_PATH` | `outputs/policy_ui_reviews/reviews.jsonl` | JSONL append target for human review feedback from the UI. |
| `UPLOAD_MAX_ARCHIVE_SIZE_BYTES` | `104857600` | Max total upload archive size (100 MB). |
| `UPLOAD_MAX_MEMBER_SIZE_BYTES` | `52428800` | Max single-file size inside an archive (50 MB). |
| `UPLOAD_MAX_EXTRACTED_SIZE_BYTES` | `524288000` | Max total extracted size (500 MB). Bomb defence. |
| `UPLOAD_MAX_ARCHIVE_ENTRIES` | `10000` | Max archive entry count. |
| `UPLOAD_MAX_COMPRESSION_RATIO` | `100.0` | Max per-entry compression ratio. Bomb defence. |
| `OTEL_SDK_DISABLED` | _unset_ | Set to `true` to silence all OpenTelemetry tracing. |
| `OTEL_TRACE_FILE` | _unset_ | If set, write spans to this JSONL file instead of stdout. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _unset_ | OTLP endpoint URL for an external collector (Grafana Tempo, etc.). |

## 3. Verification Contract

Use these commands as the local verification gate:

```bash
uv run ruff check .
UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q
PATH="$(pwd)/.venv/bin:$PATH" make policy-check
make opengrep-test
cd frontend && yarn lint && yarn test && yarn build
```

Write local smoke evidence under `outputs/local_smoke/`:

```bash
uv run python run_benchmark_eval.py \
  --config configs/benchmark/smoke_mixed.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/local_smoke/detection \
  --reset-neo4j

uv run python run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/local_smoke/remediation \
  --sample-size 3 \
  --reset-neo4j
```

### Model consumption and cost

Every provider call is recorded once, in the shared transport, so hosted and locally served models are accounted for identically. Consumption is emitted as OpenTelemetry metrics under the GenAI semantic conventions (`gen_ai.client.token.usage` partitioned by `gen_ai.token.type`, plus `gen_ai.client.operation.duration`) and also kept in a process-local ledger, which remediation runs write to `model_usage.json` beside their metrics.

Those conventions are still in Development upstream, and a migration to counters named `gen_ai.client.inference.tokens` is proposed, so treat the metric names as liable to change.

Cost is opt-in and never guessed. Set per-model rates to have an estimate computed:

```bash
export LLM_PRICE_PER_MILLION='{"gpt-5.4": {"input": 1.25, "output": 10.0, "cached_input": 0.125}}'
```

Rates are per million units and must come from the provider's current price list; nothing is hardcoded. A model with no configured rate reports its units with no cost rather than a fabricated one, and a partial total always names the unpriced models so it cannot be mistaken for complete. Configuring `cached_input` matters where a provider discounts cached input: without it the cached portion is charged at the full input rate, which overstates rather than understates, and the artifact records that it did in a `cost_note`.

Metrics export nowhere by default. Set `OTEL_EXPORTER_OTLP_ENDPOINT` for a collector, or `OTEL_METRICS_CONSOLE=1` to print them locally.

### Detection evaluation by policy group

A whole-corpus run ingests every category into one graph, so a failure anywhere discards the run. Evaluate one group at a time and merge the outputs; a failed group is then re-run on its own in seconds rather than re-running 2115 files.

```bash
for group in hash-md5 crypto-md5 rng-insecure sql-injection \
             path-traversal command-injection ldap-injection xpath-injection; do
  uv run python run_benchmark_eval.py \
    --config configs/benchmark/multicat_all_available.json \
    --mapping configs/benchmark/policy_registry.json \
    --categories "$group" \
    --output-dir "outputs/local_smoke/group_$group" \
    --reset-neo4j
done

uv run python compose_benchmark_eval.py \
  outputs/local_smoke/group_* \
  --output-dir outputs/local_smoke/detection_composed
```

Compose recomputes the Overall row from each run's `case_outcomes.jsonl` under the union any-rule definition. Never sum the per-category rows: a case selected under one category can fire an off-target rule from another. Compose refuses to merge groups that disagree about a testcase, which means they came from different code or configuration.

Group runs omit cross-file graph edges between categories. That is safe for OWASP Benchmark, whose cases are standalone and whose helpers are staged into every group, but it is a property of that corpus rather than a general guarantee. Verified equivalent on this corpus: run per group, every category reproduces the whole-corpus figures exactly.

Current detection baseline, full corpus (2092 cases, all available per category, seed 7): precision `0.7966`, recall `0.9324`, F1 `0.8591` (`TP/FP/FN = 979/250/71`), artifact `outputs/local_smoke/detection_composed_final/`. On the 454-case `multicat_full.json` sample the same engines measured F1 `0.838` (`207/54/26`, `outputs/local_smoke/detection_matched/`) before configuration-backed crypto and hash detection.

A detection figure is a property of the engine configuration as well as the corpus, so state which engines a run used, and whether configuration facts were available. Crypto and hash controls decide on values declared in the analysed workspace's `*.properties` files, so a corpus without them scores those categories differently; see `docs/architecture/2026-09-13-configuration-facts.md`.

`outputs/README.md` indexes every artifact directory: what it holds, whether it is tracked, and which commit its provenance names. Cite the artifact directory plus the SHA recorded in its `provenance.json`, with the exceptions that index records — `thesis_final_remediation_v2/` has no provenance file, and a composed detection directory carries its provenance in the per-group runs named by `composed_from`. Earlier historical runs (`detection_calibration_path_precision_v4`, `repro_supported_medium_branch_benchmarktest01017_fix`) are no longer tracked in the repository.

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
uv run python scripts/evaluation/build_benchmark_demo_pack.py \
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

## 6. Reproduce the Reported Detection Result

The reported figure comes from the full corpus, evaluated one policy group at a time and composed. Use the procedure in "Detection evaluation by policy group" above; it writes `outputs/local_smoke/detection_composed_final/`.

`outputs/thesis_final_detection_full_v2/` is a historical artifact and is **not reproducible** on this baseline: it predates audit POLICY-C1's removal of a corpus fingerprint. Running its original config (`multicat_full.json`) gives neither that artifact's figure nor the reported one, so do not treat it as a reproduction step. `docs/thesis_context.md` records what it was and why it is retained.

## 7. Reproduce Thesis-Final Explanation Evaluation

The recorded cohort of 222 true-positive and 9 false-positive findings comes from the detection configuration in use when that run was made. Detection has since changed, so the same command now yields a larger cohort; the recorded artifact is the reference for the reported figures.

The v1 baseline measured `Citation@Context` on the TP cohort only. The v2 run additionally evaluates the FP cohort (citation grounding on the detector's false positives) and emits Wilson 95% CIs on every rate. Re-run into a fresh directory:

```bash
LLM_CONCURRENCY=1 \
uv run python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/reproduction/explanation_full_v2 \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j
```

### Resuming a crashed or interrupted explanation run

The explanation eval (~90 min wall-clock) is the longest leg of the pipeline. If it is interrupted, pass `--resume` on the next invocation with the same `--output-dir`: the runner reads `request_metrics.jsonl`, treats every violation whose `with_context` and `without_context` rows are both already on disk as complete (no LLM calls), and appends to the existing artifacts rather than truncating them.

```bash
# First run is interrupted after, say, 4 of 8 categories.
LLM_CONCURRENCY=1 \
uv run python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/reproduction/explanation_full_v2 \
  --evidence-mode lean \
  --llm-max-tokens-eval 192 \
  --reset-neo4j \
  --resume
```

Notes:

- Violations with a partially-complete pair (only one context mode on disk)
  are redone so the with/without semantics stay symmetric.
- `--reset-neo4j` is still safe with `--resume`: the graph is rebuilt
  from the same staged subset deterministically, and the OPA evaluation is a pure function of the bundle.
- Per-category sample budget (`--sample-per-category`) applies only to
  newly-executed violations on the resume run; samples written by the prior run remain untouched.

## 8. Rerun Supported Remediation

The v2 baseline and provenance-backed v3/v4 follow-ups under `outputs/thesis_final_remediation_*` are protected canonical evidence. Do not rerun directly into those directories unless intentionally regenerating the canonical artifact set and checksum manifest.

For a local supported-medium rerun, use a non-canonical output directory:

```bash
uv run python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/local_smoke/remediation_supported_medium \
  --sample-size 60 \
  --reset-neo4j
```

## 9. Optional Smaller Validation Runs

For a bounded remediation refresh across full and guarded support tiers:

```bash
uv run python run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/remediation_eval_bounded_smoke \
  --sample-size 3 \
  --reset-neo4j
```

To compare local remediation models on the same bounded subset:

```bash
uv run python scripts/evaluation/run_remediation_model_bakeoff.py \
  --models qwen/qwen3-coder-30b qwen3.5-27b \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --output-dir outputs/remediation_model_bakeoff \
  --sample-size 3 \
  --reset-neo4j
```

## 10. Expected Outputs

Every eval run also writes a `provenance.json` with the git SHA, OPA version, model id, seed, config sha256, uv.lock hash, and pyproject hash. This is the canonical per-run manifest; cite it alongside any number you quote from the artifact.

Canonical artifact snapshot (generated 2026-05-03):

- detection v2 (`outputs/thesis_final_detection_full_v2/`): qualified evidence
  that does not reproduce on the current baseline. The figure, its bootstrap intervals, and the reason it does not reproduce are recorded in `docs/thesis_context.md`; provenance SHA `7ad90a2`.
- explanation v2 (`outputs/thesis_final_explanation_full_v2/`):
  `Citation@TP=1.000` (`222/222`), `Citation@TP@NoContext=0.009` (`2/222`), `Citation@FP=1.000` (`9/9`), `Citation@FP@NoContext=0.000` (`0/9`); provenance SHA `701d051`.
- remediation v3 (`outputs/thesis_final_remediation_v3/`): fully verified
  success rate `0.72` (`18/25`), build success rate `0.90` (`18/20` attempted builds), full-population Brier `0.095431` / ECE `0.095705`, attempted-only Brier `0.094698` / ECE `0.083900`, no-fix-only Brier `0.110091` / ECE `0.331800`; provenance SHA `7ad90a2`.
- remediation v4 (`outputs/thesis_final_remediation_v4/`): raw-source
  evidence preservation fix applied; fully verified success rate `1.00` (`25/25`), build success rate `1.00` (`25/25` attempted builds).

### Detection

- `metrics.json` — per-category `tp/fp/fn/precision/recall/f1` and overall.
  v2 adds `precision_ci`, `recall_ci`, `f1_ci` (percentile bootstrap, 2000 resamples by default, deterministic given the selection seed) and `precision_ci_wilson`, `recall_ci_wilson` (closed-form sanity checks).
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
  `tp_count, citation_at_tp_with_context, citation_at_tp_without_context, fp_count, citation_at_fp_with_context, citation_at_fp_without_context`.
- `table.md` or `table.tex` — v2 columns:
  `Category, TP Count, Citation@TP (ctx), Citation@TP (no-ctx), FP Count, Citation@FP (ctx), Citation@FP (no-ctx)`.
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
  - The reported run covers every available case in each evaluated family, so
    it carries no sampling variance and needs no interval to account for case
    selection. Quote the per-family rows alongside the aggregate: family sizes
    are unequal, so the aggregate is weighted towards the larger families.
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

The eval pipeline is **as deterministic as the underlying components allow**. Read this section before treating any single re-run as canonical.

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
  weights, the quantization, the runtime version, and the host hardware. Even with `temperature=0.0` and a fixed seed, identical prompts can produce different completions across server restarts and model versions.
- This means `Citation@Context`, `Citation@TP`, and remediation `fix_success`
  may shift by small amounts on re-run. Treat the headline values as a single draw, not as point estimates of a fixed distribution.
- Model TTL eviction in LM Studio (`LLM_MODEL_TTL_SECONDS`) reloads the model
  on demand; immediately after a reload, the first few completions can differ from later steady-state ones depending on backend-side caches.

**Recommended practice.**

- For headline numbers, run each eval **N=3 times** with different LLM seeds
  (or restarts) and report mean ± standard deviation. The detection numbers are deterministic and need no repetition.
- Pin the model version explicitly in `LLM_MODEL` and
  `REMEDIATION_LLM_MODEL`. Record the resolved model and runtime in the artifact's `provenance.json` (written by every `run_*_eval.py` script).
- For statistical claims (P, R, F1, Citation@*), prefer the bootstrap and
  Wilson confidence intervals emitted next to the point estimates over individual point values.
- When citing thesis-final numbers, cite the artifact directory
  (`outputs/thesis_final_*/`) plus the `thesis-evidence-2026-05-31` git tag — not the README prose.
