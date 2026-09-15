# Reproducibility

This file owns the current setup, validation, and evaluation workflow. Historical thesis evidence and claim limits live in [`docs/thesis_context.md`](./docs/thesis_context.md). Tracked artifact provenance is indexed in [`outputs/README.md`](./outputs/README.md).

## Requirements

- macOS or Linux
- Python 3.14.7 (`.python-version`) and uv 0.12.13+
- Node.js 24+ and Yarn 1.22+
- JDK 21+ and Maven
- Docker Compose, or Podman with a compatible Compose provider
- OpenGrep 1.30.0+ for injection-rule evaluation
- An OpenAI-compatible endpoint only for model-backed explanation/remediation runs

`make install` builds the Eclipse JDT adapter, syncs the locked Python environment, installs OPA v1.20.2 into `.venv/bin`, and installs frontend dependencies.

## Setup

```bash
make install
cp .env.example .env
```

Set `NEO4J_PASS` and any LLM provider values required by your run. `.env.example` is the maintained operator template; runtime defaults and validation live in `codegraph/config.py`.

Start the local application:

```bash
make dev
```

Or run the stack in containers:

```bash
make docker-up
```

A fresh workspace is intentionally degraded until Java source has been ingested and its retrieval generation built.

## Validation

Run the gates relevant to the changed surface:

```bash
uv run ruff check .
uv run python -m pytest -q
PATH="$(pwd)/.venv/bin:$PATH" make policy-check
make opengrep-test
make docs-check
(cd frontend && yarn lint && yarn test && yarn build)
```

For Java-adapter changes also run:

```bash
make java-parser-build
```

Live end-to-end tests require their external services and are separate from unit/integration success.

## Benchmark Corpus

The OWASP Benchmark corpus is needed only for benchmark evaluation:

```bash
make benchmark-corpus
```

The Makefile pins the corpus revision used by recorded evaluation evidence. `OWASP_BENCHMARK_ROOT` may point to another local checkout when needed.

## Smoke Evaluation

Start Neo4j before benchmark runs:

```bash
make neo4j-up
```

Detection smoke:

```bash
uv run python scripts/evaluation/run_benchmark_eval.py \
  --config configs/benchmark/smoke_mixed.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/local_smoke/detection \
  --reset-neo4j
```

Bounded remediation smoke:

```bash
uv run python scripts/evaluation/run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/local_smoke/remediation \
  --sample-size 3 \
  --reset-neo4j
```

`outputs/local_smoke/` is disposable local evidence, not canonical thesis evidence.

## Full Detection Evaluation

Run each benchmark group independently so failures are resumable:

```bash
for group in hash-md5 crypto-md5 rng-insecure sql-injection \
             path-traversal command-injection ldap-injection xpath-injection; do
  uv run python scripts/evaluation/run_benchmark_eval.py \
    --config configs/benchmark/multicat_all_available.json \
    --mapping configs/benchmark/policy_registry.json \
    --categories "$group" \
    --output-dir "outputs/$(date +%Y-%m-%d)-detection-full/group_$group" \
    --reset-neo4j
done

uv run python scripts/evaluation/compose_benchmark_eval.py \
  outputs/$(date +%Y-%m-%d)-detection-full/group_* \
  --output-dir outputs/$(date +%Y-%m-%d)-detection-full/detection_composed
```

The composed `Overall` row is recomputed from per-case outcomes under union-any-rule semantics. Do not sum category rows because a case may fire an off-target rule from another family.

The current recorded full-corpus baseline is `outputs/2026-09-14-detection-full/detection_composed/`: 2092 cases, precision `0.7966`, recall `0.9324`, F1 `0.8591`, and `TP/FP/FN = 979/250/71`. Its eight source group runs record commit `1dd1510` with a clean tree. This is evidence for that exact corpus, configuration, and engine set—not a guarantee for arbitrary applications.

Configuration-backed crypto/hash findings mean the analysed workspace declares an unsafe configured value. They do not prove that deployment-time overrides preserve that value.

## Agentic Remediation Evaluation

Use the same group-scoped pattern:

```bash
uv run python scripts/evaluation/run_remediation_eval.py \
  --mode agentic \
  --config <benchmark-config> \
  --mapping configs/benchmark/policy_registry.json \
  --categories <group> \
  --output-dir <group-output> \
  --reset-neo4j
```

Compose completed groups with:

```bash
uv run python scripts/evaluation/compose_agentic_eval.py \
  <group-output>... \
  --output-dir <combined-output>
```

Model-backed runs are not bitwise reproducible. Record the provider/model, temperature, token budget, source revision, configuration hash, and generated provenance.

## Provenance and Claims

Evaluation runs write `provenance.json` with the source revision, dirty state, runtime information, configuration/policy hashes, corpus revision when applicable, seed, and model settings when applicable. Composed detection outputs identify their source group runs instead of creating synthetic provenance.

When citing a result, cite the artifact directory and the revision recorded by its provenance. Do not overwrite canonical thesis artifacts with a newer run. [`outputs/README.md`](./outputs/README.md) is the artifact index and [`docs/architecture/artifact-policy.md`](./docs/architecture/artifact-policy.md) defines what belongs in version control.

Important scope limits:

- OpenGrep is required for the injection controls it owns; missing required engine evidence must not be reported as equivalent coverage.
- Grouped benchmark execution is justified for the standalone OWASP Benchmark cases used here; it is not a general guarantee for arbitrary multi-module applications.
- Candidate-local remediation verification has no graph access. A finding that depends on graph-only configuration evidence must refuse rather than be reported as fixed.
- Policy clearance, taint-flow evidence, successful compilation, and model confidence are each evidence within a bounded scope; none alone proves production safety or behavioral equivalence.
