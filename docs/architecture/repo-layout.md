# Repository Layout

This repository keeps two explicit backend boundaries:

- `api/` contains the FastAPI HTTP surface: routers plus request/response DTOs.
- `codegraph/` contains domain logic: ingestion, policy evaluation, search, LLM integration, remediation, and evaluation orchestration.

The root folder is intentionally clean and focused. It contains only the application entrypoint and core project metadata:

- `app.py` for `uvicorn app:app`
- repository metadata such as `README.md`, `REPRODUCIBILITY.md`, `pyproject.toml`, and `Makefile`

Evaluation runners and CLI operational utilities live under `scripts/`:

- `scripts/evaluation/` for benchmark evaluation runners (`run_*_eval.py`, `compose_benchmark_eval.py`) and reporting tooling
- `scripts/ingestion/` for graph and embedding preparation helpers
- `scripts/search/` for CLI search helpers
- `scripts/policy/` for policy CLI helpers

This split is intentional:

- reviewers can quickly identify the stable application entrypoint
- HTTP concerns stay separate from domain orchestration
- evaluation scripts remain centralized under `scripts/evaluation/`

Repository compatibility rules:

- keep `app.py` at the root
- place evaluation scripts under `scripts/evaluation/`
