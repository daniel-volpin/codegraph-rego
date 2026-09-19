# CodeGraph

[![CI](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml) [![GitHub release](https://img.shields.io/github/v/release/daniel-volpin/codegraph-rego)](https://github.com/daniel-volpin/codegraph-rego/releases/latest) [![Python](https://img.shields.io/badge/python-3.14%2B-blue)](./pyproject.toml) [![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE) [![Citation](https://img.shields.io/badge/citation-CITATION.cff-orange)](./CITATION.cff)

**Benchmark-backed security and compliance analysis framework for Java applications.**

CodeGraph converts Java codebases into a queryable knowledge graph, evaluates pluggable OPA/Rego policies and OpenGrep taint rules across compliance standards (ISO-27001, PCI-DSS 4.0, NIST SP 800-53, OWASP Top 10), generates grounded LLM explanations, and performs autonomous 3-gate remediation.

## Core Capabilities

- **Graph AST Analysis**: Parses Java source via Eclipse JDT into Neo4j with exact native byte ranges and immutable graph revisions.
- **Pluggable Policy Engine**: Evaluates versioned OPA/Rego compliance rules and OpenGrep semantic dataflow taint rules with SARIF v2.1.0 interoperability.
- **Grounded Explanations**: Produces structured `Citation / Why / Fix` explanations grounded in AST, graph context, and FAISS vector embeddings.
- **Autonomous 3-Gate Remediation**: Fixes vulnerabilities with iterative self-correction in isolated worktrees, strictly verified across JDT Compilation, Test Regression, and Policy Clearance gates.
- **OpenTelemetry & Observability**: Integrated OpenTelemetry and OpenInference tracing across policy scans, LLM token usage, and agent repair turns.

## Architecture

```text
Java Codebase ──> Eclipse JDT Parser ──> Neo4j Knowledge Graph + FAISS Embeddings
                                                │
                                                ▼
                                    Pluggable Policy Engine
                                 (OPA / Rego + OpenGrep Taint)
                                                │
                                                ▼
                                  Security Findings (SARIF v2.1.0)
                                                │
                                 ┌──────────────┴──────────────┐
                                 ▼                             ▼
                        LLM Explanations            Autonomous 3-Gate Repair
                       (Citation/Why/Fix)           ├─ 1. JDT Compilation Gate
                                                    ├─ 2. Test Regression Gate
                                                    └─ 3. Policy Clearance Gate
```

## Quick Start

### Prerequisites
- macOS or Linux
- [uv](https://docs.astral.sh/uv/) 0.12+, Python 3.14+ (pinned 3.14.7), Node.js 24+, Yarn 1.22+
- OPA `v1.20.2` (installed via `make install`), OpenGrep `v1.30.0+`
- JDK 21+ and Maven
- Docker Compose or Podman

### Installation & Run

```bash
git clone https://github.com/daniel-volpin/codegraph-rego.git
cd codegraph-rego

make install
cp .env.example .env
# Set NEO4J_PASS in .env, then start all services:
make dev
```

Endpoints:
- **Web UI**: <http://127.0.0.1:5173>
- **Backend API**: <http://127.0.0.1:8000>
- **Health Check**: <http://127.0.0.1:8000/health>

### Containerized Deployment

```bash
make docker-up    # Starts neo4j, backend, and frontend containers
make docker-down  # Stops containers
```

## Supported Scope & Benchmark Tiers

| CWE | Policy Control | Remediation Tier |
| --- | --- | --- |
| CWE-22 Path Traversal | `ISO-A.8-PATH-TRAVERSAL` | Guarded |
| CWE-78 Command Injection | `ISO-A.8-CMD-INJECTION` | Guarded |
| CWE-89 SQL Injection | `ISO-A.8-SQL-INJECTION` | Guarded |
| CWE-90 LDAP Injection | `ISO-A.8-LDAP-INJECTION` | Guarded |
| CWE-327 Weak Cryptography | `ISO-A.10-WEAK-CRYPTO` | Guarded |
| CWE-328 Weak Hash | `ISO-A.10-WEAK-HASH` | Full |
| CWE-330 Weak Randomness | `ISO-A.10-WEAK-RANDOM` | Full |
| CWE-643 XPath Injection | `ISO-A.8-XPATH-INJECTION` | Guarded |

## Repository Layout

| Path | Description |
| --- | --- |
| [`app.py`](./app.py) | FastAPI application entrypoint |
| [`api/`](./api) | Modular HTTP routers (health, policy, remediation, search, upload) |
| [`codegraph/`](./codegraph) | Ingestion, graph persistence, search, policy evaluation, LLM transport, and agentic repair |
| [`tools/java-parser/`](./tools/java-parser) | Eclipse JDT Java AST parser adapter |
| [`policy/`](./policy) | OPA/Rego compliance rules, OpenGrep taint rules, and multi-standard policy packs |
| [`configs/benchmark/`](./configs/benchmark) | Canonical benchmark datasets and evaluation manifests |
| [`frontend/`](./frontend) | Vite + React + TypeScript single-page application |
| [`scripts/`](./scripts) | Evaluation, ingestion, and benchmark automation scripts |
| [`outputs/`](./outputs) | Tracked evaluation artifacts, provenance receipts, and metrics |

## Quality & Verification

```bash
uv run ruff check .               # Python linter & formatter check
uv run python -m pytest -q        # Backend test suite (1,167 tests)
make policy-check                 # OPA/Rego format and syntax validation
make opengrep-test                # OpenGrep taint rules validation
make docs-check                   # Markdown single-line paragraph enforcement
(cd frontend && yarn lint && yarn test && yarn build)  # Frontend validation
```

## Security & Research Notice

CodeGraph is a research artifact evaluated on [OWASP Benchmark](https://owasp.org/www-project-benchmark/). It is designed for single-user, loopback-only local execution. Keep services bound to `127.0.0.1` and treat untrusted code accordingly. See [`SECURITY.md`](./SECURITY.md) and [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for provenance, reproducibility, and citation details.

## License

CodeGraph is open-source under the [MIT License](./LICENSE).
