# CodeGraph

[![CI](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/daniel-volpin/codegraph-rego)](https://github.com/daniel-volpin/codegraph-rego/releases/latest)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue)](./pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Citation](https://img.shields.io/badge/citation-CITATION.cff-orange)](./CITATION.cff)

**Benchmark-backed security and compliance analysis for Java applications.**

CodeGraph turns Java source code into a queryable knowledge graph, evaluates
ISO-aligned OPA/Rego policies, produces evidence-grounded explanations, and
attempts bounded remediation with compilation and policy re-verification.

It is a master thesis research artifact evaluated primarily against
[OWASP Benchmark](https://owasp.org/www-project-benchmark/). It is not a
production security scanner, full taint-analysis engine, or autonomous repair
system.

## Why CodeGraph?

- **Graph-structured analysis:** represents Java declarations and relationships
  in Neo4j using an Eclipse JDT parser.
- **Policy as code:** evaluates versioned OPA/Rego rules mapped to ISO-aligned
  controls. Detection engines are pluggable behind a SARIF contract: injection
  controls use dataflow taint analysis rather than lexical matching.
- **Grounded explanations:** returns structured `Citation / Why / Fix` output
  backed by source, graph, and retrieval evidence.
- **Bounded remediation:** supports automatic fixes only where deterministic
  validation can constrain the result; safe refusal is an expected outcome.
- **Reproducible research:** ships benchmark configurations, provenance
  manifests, confidence intervals, and tracked evaluation artifacts.
- **Usable interface:** includes a FastAPI backend and React frontend for
  upload, search, policy review, explanation, and remediation workflows.

## Quick Start

### Prerequisites

- macOS or Linux
- [uv](https://docs.astral.sh/uv/) 0.12.13+
- Python 3.14+ (the project pins 3.14.7)
- Node.js 24 LTS and Yarn 1.22+
- OPA `v1.20.2` (installed into `.venv/bin` by `make install`)
- OpenGrep `v1.30.0+` on `PATH` (intra-file taint analysis for the injection controls;
  install with `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash`)
- JDK 21+ and Maven
- Docker Compose, or Podman with a compatible Compose provider

### Install and run

```bash
git clone https://github.com/daniel-volpin/codegraph-rego.git
cd codegraph-rego

make install
cp .env.example .env
```

Set `NEO4J_PASS` in `.env`, then start the backend, frontend, and local Neo4j
service:

```bash
make dev
```

Open:

- Web application: <http://127.0.0.1:5173>
- Backend API: <http://127.0.0.1:8000>
- Health check: <http://127.0.0.1:8000/health>

`make install` builds the required Eclipse JDT adapter, installs locked Python
and frontend dependencies, and installs the pinned OPA binary into `.venv/bin`.
CodeGraph does not download or substitute a Java parser at request time.

For benchmark datasets, model configuration, and exact rerun commands, continue
with [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).

### Distribution

The supported installation path is a source checkout using `make install`.
GitHub releases identify source revisions; CodeGraph is not currently published
as a PyPI package or supported production container image. Pre-1.0 APIs and
configuration may evolve between minor releases.

## Workflow

```text
Java project
    |
    v
Eclipse JDT parsing -----> Neo4j knowledge graph
                              |
                              +-----> hybrid code search
                              |
                              v
                       OPA/Rego policies
                              |
                              v
                    findings with evidence
                              |
                    +---------+---------+
                    |                   |
                    v                   v
             LLM explanation     bounded remediation
                                        |
                                        v
                              compile + re-evaluate
```

The web workflow is:

1. Upload a ZIP containing one or more `src/main/java` roots.
2. Explore the indexed code and evaluate policies.
3. Review findings and request an evidence-grounded explanation.
4. Preview supported remediation.
5. Compile and re-evaluate the exact candidate before accepting it.

## Benchmark Scope

The primary evaluation covers eight OWASP Benchmark categories:

| CWE | Policy control | Remediation tier |
| --- | --- | --- |
| CWE-22 Path Traversal | `ISO-A.8-PATH-TRAVERSAL` | Guarded |
| CWE-78 Command Injection | `ISO-A.8-CMD-INJECTION` | Guarded |
| CWE-89 SQL Injection | `ISO-A.8-SQL-INJECTION` | Guarded |
| CWE-90 LDAP Injection | `ISO-A.8-LDAP-INJECTION` | Guarded |
| CWE-327 Weak Cryptography | `ISO-A.10-WEAK-CRYPTO` | Guarded |
| CWE-328 Weak Hash | `ISO-A.10-WEAK-HASH` | Full |
| CWE-330 Weak Randomness | `ISO-A.10-WEAK-RANDOM` | Full |
| CWE-643 XPath Injection | `ISO-A.8-XPATH-INJECTION` | Guarded |

`full` means a bounded automatic fix path is available. `guarded` means the
agent may propose a candidate but must refuse when evidence or any verification
gate is unavailable. These current runtime tiers are broader than the recorded
thesis remediation experiment; they do not extend its `25/25` result to the
guarded categories or to arbitrary applications.

## Research Results

Repository-tracked thesis artifacts report:

| Evaluation | Result | Evidence |
| --- | --- | --- |
| Detection | Precision, recall, and F1: `0.953` | [`outputs/thesis_final_detection_full_v2/`](./outputs/thesis_final_detection_full_v2/) |
| Explanation grounding | `Citation@TP=1.000`; `Citation@FP=1.000` | [`outputs/thesis_final_explanation_full_v2/`](./outputs/thesis_final_explanation_full_v2/) |
| Bounded remediation | `25/25` fully verified | [`outputs/thesis_final_remediation_v4/`](./outputs/thesis_final_remediation_v4/) |

These values describe specific recorded runs, not guaranteed performance on
arbitrary applications. Cite the artifact's `provenance.json`, recorded commit,
and confidence intervals rather than this summary. See
[`copilot-context/benchmark.md`](./copilot-context/benchmark.md) and
[`docs/thesis_context.md`](./docs/thesis_context.md) for interpretation limits.

## Architecture

| Path | Responsibility |
| --- | --- |
| [`app.py`](./app.py) | FastAPI application entrypoint |
| [`api/`](./api) | Thin HTTP routers and request/response models |
| [`codegraph/`](./codegraph) | Ingestion, graph, search, policy, LLM, and remediation logic |
| [`tools/java-parser/`](./tools/java-parser) | Eclipse JDT analysis adapter |
| [`policy/`](./policy) | OPA/Rego rules and policy catalog |
| [`configs/benchmark/`](./configs/benchmark) | Canonical benchmark configurations and mappings |
| [`frontend/`](./frontend) | React, TypeScript, and Vite single-page application |
| [`scripts/`](./scripts) | Ingestion, search, policy, and evaluation utilities |
| [`outputs/`](./outputs) | Tracked research evidence and provenance |

Further reading:

- [Repository layout](./docs/architecture/repo-layout.md)
- [Frontend/backend contract](./docs/frontend_backend_contract.md)
- [Architecture roadmap](./docs/architecture/2026-09-11-backend-modernization-roadmap.md)
- [Artifact and evidence policy](./docs/architecture/artifact-policy.md)
- [Detection engine plugin contract](./docs/architecture/2026-09-12-detection-engine-plugin-contract.md)
- [Code property graph evaluation (not adopted)](./docs/architecture/2026-09-13-cpg-engine-evaluation.md)

## Configuration

CodeGraph loads validated settings through `codegraph.config`. Start from
[`.env.example`](./.env.example).

| Area | Key variables |
| --- | --- |
| Neo4j | `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASS` |
| LLM provider | `LLM_API_BASE`, `LLM_API_KEY`, `LLM_MODEL`, `LLM_API_MODE` |
| Java parser | `JAVA_PARSER_JAR`, `JAVA_PARSER_LANGUAGE_LEVEL` |
| Taint analysis | `CODEGRAPH_OPENGREP_RULES_DIR`, `CODEGRAPH_OPENGREP_TIMEOUT` |
| Engine control | `CODEGRAPH_DETECTION_ENGINES_ENABLED` |
| Concurrency | `POLICY_WORKERS`, `LLM_MAX_CONCURRENT_REQUESTS` |
| Remediation | `REMEDIATION_CONFIDENCE_THRESHOLD_APPLY`, `REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW` |
| Observability | `OTEL_TRACE_FILE`, `OTEL_EXPORTER_OTLP_ENDPOINT` |

The complete operator reference is in
[`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md#environment-variable-reference).

## Development

Run the local quality gates:

```bash
uv run ruff check .
uv run python -m pytest -q
PATH="$(pwd)/.venv/bin:$PATH" make policy-check
(cd frontend && yarn lint && yarn test && yarn build)
```

Useful targets:

```bash
make help
make backend-dev
make opengrep-test
make java-parser-build
make neo4j-up
make neo4j-down
```

Benchmark-sensitive changes should also run the focused smoke evaluations
documented in [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md#verification-contract).

## Safety

CodeGraph is designed for **single-user, loopback-only research use**:

- The API has no authentication or rate limiting.
- Uploaded projects share a local workspace.
- Verification may execute `javac`, Maven, or Gradle against uploaded code.
- Source and graph context may be sent to the configured LLM provider.
- Remediation apply mode can modify the active workspace.

Keep the service bound to `127.0.0.1`, treat uploads as untrusted, and sandbox
build verification when analyzing third-party code. See
[`SECURITY.md`](./SECURITY.md) for the full trust boundary and private
vulnerability reporting instructions.

## Contributing

Contributions are welcome. Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md)
and the [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) before opening a pull
request. Usage and reproducibility guidance is in [`SUPPORT.md`](./SUPPORT.md).

Changes must preserve benchmark provenance, policy mappings, parser source
ranges, graph revision integrity, and frontend/backend schema alignment.

## Reproducibility, Citation, and License

- Reproduce evaluations with [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).
- Review versioning and publication expectations in the
  [release policy](./docs/release_policy.md).
- Cite CodeGraph using [`CITATION.cff`](./CITATION.cff).
- Original CodeGraph source is available under the [MIT License](./LICENSE).
- Benchmark-derived artifacts remain subject to applicable upstream terms; see
  [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
- Before making the repository public, complete the
  [public release checklist](./docs/public_release_checklist.md).
