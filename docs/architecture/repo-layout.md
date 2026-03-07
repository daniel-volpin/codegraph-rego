# Repository Layout

This repository keeps two explicit backend boundaries:

- `api/` contains the FastAPI HTTP surface: routers plus request/response DTOs.
- `codegraph/` contains domain logic: ingestion, policy evaluation, search, LLM integration, remediation, and evaluation orchestration.

The root folder is intentionally small. It should contain only stable entrypoints and core project metadata:

- `app.py` for `uvicorn app:app`
- the three validated evaluation runners
- repository metadata such as `README.md`, `REPRODUCIBILITY.md`, `pyproject.toml`, and `Makefile`

Operational utilities that are useful but not part of the stable thesis entrypoint surface live under `scripts/`:

- `scripts/ingestion/` for graph and embedding preparation helpers
- `scripts/search/` for CLI search helpers
- `scripts/policy/` for policy CLI helpers
- `scripts/evaluation/` for auxiliary benchmark/evaluation tooling

This split is intentional:

- reviewers can quickly identify the stable entrypoints
- HTTP concerns stay separate from domain orchestration
- package code remains importable without depending on ad hoc root scripts

Compatibility rules for this branch:

- keep `app.py` at the root
- keep `run_benchmark_eval.py`, `run_explanation_eval.py`, and `run_remediation_eval.py` at the root
- avoid introducing new top-level utility scripts when equivalent functionality belongs under `scripts/`
