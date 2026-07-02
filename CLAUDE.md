# CodeGraph — Claude Project Context

## What This Is

MSc Software Engineering thesis project (UvA, Daniel Volpin). CodeGraph is a benchmark-backed JVM security/compliance framework that:

1. Ingests JVM code into Neo4j for graph-based code understanding.
2. Evaluates ISO 27001 controls via OPA/Rego policy rules.
3. Generates grounded LLM explanations with structured evidence citations.
4. Performs bounded, confidence-gated remediation with build re-verification.

Primary proof surface: **OWASP Benchmark v1.2**.
Real-world apps are secondary workflow case studies, not the primary evidence surface.

## Working Rules

- Treat `main` as the baseline branch for new promoted benchmark outputs.
- Prefer canonical benchmark configs under `configs/benchmark/`.
- Keep benchmark evidence and qualitative case-study evidence separate.
- Cite `outputs/` artifacts, not prose summaries.

## Thesis Language Constraints

- Say **"graph-based code understanding"** or **"graph-structured evidence"**.
- Do not describe the implementation as a code property graph, control-flow graph, or full taint analysis.
- Describe remediation as bounded and `dry_run` verified, not autonomous production repair.
- Treat `Citation@NoContext=0.000` or `Citation@FP (no-ctx)=0.000` as expected ablation floors, not failures.

## Stable Architecture Anchors

- `codegraph/policy/runtime/opa.py` builds the authoritative violation response shape.
- `codegraph/policy/runtime/bundles.py` builds the evidence bundle.
- `codegraph/remediation/apply_flow.py` handles remediation apply/verify flow.
- `codegraph/remediation/confidence.py` owns remediation confidence scoring.
- `codegraph/evaluation/remediation_runtime.py` writes remediation calibration artifacts.
- `policy/catalog.json` and `configs/benchmark/` must stay aligned with benchmark semantics.

## Validation Defaults

These mirror what CI enforces (`.github/workflows/ci.yml`):

```bash
.venv/bin/ruff check .
UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q
make policy-check   # opa check --strict + format-drift gate; needs OPA on PATH
cd frontend && yarn lint && yarn test && yarn build
```

Use `.venv/bin/python -m pytest`, not system `python3`.
`make policy-check` is check-only; use `make policy-fmt` to rewrite Rego formatting.

## Important Docs

- `REPRODUCIBILITY.md` — commands, environment setup, and rerun flow.
- `copilot-context/benchmark.md` — benchmark scope, evidence anchors, and claim guardrails.
- `docs/thesis_context.md` — thesis framing and terminology constraints.
