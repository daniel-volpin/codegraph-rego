# Contributing to CodeGraph

Thank you for your interest in contributing to CodeGraph! CodeGraph is a benchmark-backed JVM security and compliance framework for graph-based code understanding, ISO-aligned policy evaluation, grounded LLM explanations, and bounded remediation.

---

## Code of Conduct

All contributors are expected to uphold the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md).

---

## Scientific & Architectural Boundaries

CodeGraph is a **benchmark-backed research artifact**. To preserve scientific reproducibility and thesis evaluation validity:

1. **Protect Canonical Evidence**: Do not modify or overwrite tracked evidence outputs under `outputs/thesis_final_*` or `outputs/canonical_manifest.sha256`.
2. **Protect Benchmark Mappings**: Do not silently alter control mappings or testcase selections in `configs/benchmark/`.
3. **Protect Policy & Remediation Semantics**: Do not change Rego policy logic in `policy/` or confidence gating/disposition contracts in `codegraph/remediation/` without explicit rationale and updated tests.
4. **Keep Architecture Layers Clean**: Keep HTTP routers thin (`api/routers/`) and business logic encapsulated under `codegraph/`.
5. **Contract Alignment**: Avoid frontend/backend contract drift. When modifying API models in `api/models/validation.py`, update `frontend/src/lib/schemas.ts` (Zod schemas).

---

## Development Setup

### Prerequisites

- Python 3.10+
- Node.js 22+ and Yarn 1.22+
- OPA `v1.15.1` (installed into `.venv/bin` by `make install`)
- Java JDK (8+ or newer) and Maven for remediation build re-verification (release validation was performed with OpenJDK 26.0.1)
- Neo4j 5.x through a Docker- or Podman-compatible Compose runtime

### Environment Preparation

```bash
# Clone repository
git clone https://github.com/daniel-volpin/codegraph-rego.git
cd codegraph-rego

# Install Python and frontend dependencies
make install

# Copy environment template
cp .env.example .env
```

---

## Local Validation Suite

Before opening a pull request, run the full validation suite locally to ensure all quality gates pass:

```bash
# 1. Python Linting Check
uv run ruff check .

# 2. Pytest Backend Test Suite
CODEGRAPH_ENV_FILE=.env NEO4J_PASS=password uv run python -m pytest -q

# 3. OPA Policy Check and Formatting Gate
PATH="$(pwd)/.venv/bin:$PATH" make policy-check

# 4. Frontend Linting, Unit Tests, and Build
cd frontend
yarn lint
yarn test
yarn build
yarn test:e2e
cd ..

# 5. Git Formatting Check
git diff --check
```

---

## Submitting Pull Requests

- **Small & Focused**: Keep pull requests atomic and focused on a single maintainability, fix, or enhancement goal.
- **Include Tests**: Add regression or unit tests for any bug fix or clean-up.
- **Clear Commit Messages**: Use clear conventional commit prefixes (e.g., `feat:`, `fix:`, `docs:`, `chore:`, `test:`).
