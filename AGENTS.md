# AGENTS

This repository hosts a FastAPI + Pydantic backend for Java code ingestion/search (Neo4j, FAISS, OPA/Rego, LiteLLM) and a Vite + React (TypeScript) frontend. Follow these conventions for any change in this repo.

## Backend (Python)
- Target Python 3.10+. Prefer `pathlib.Path`, type hints, and small helpers over inline path/string juggling.
- Use structured logging via the standard `logging` module; avoid `print` for runtime diagnostics.
- Reuse shared config in `codegraph.config.settings` instead of reading environment variables directly.
- Keep Neo4j access centralized through `codegraph.db`; if you need new constraints/indexes, add them there idempotently.
- When expanding policy logic, keep `policy/` Rego rules and `policy/catalog.json` aligned so API responses stay traceable.

## Frontend (React + Vite)
- Use functional React components with hooks; colocate shared UI in `frontend/src/components` and feature pages in `frontend/src/pages`.
- Keep API interactions within `frontend/src/lib` and prefer React Query for async workflows.
- Read the API base URL from `VITE_API_BASE_URL`; avoid hardcoding backend hosts.

## Testing expectations
- Backend: run `python -m compileall codegraph api` when touching Python code to catch syntax errors.
- Frontend: run `npm run build` inside `frontend/` when modifying TypeScript/React code.
- If changes span both stacks, note the executed commands in the final summary.

## Documentation and responses
- Keep README files in sync with user-facing behavior when adding endpoints, CLI scripts, or env vars.
- In PR summaries, enumerate touched areas and list any tests/checks that were run (or explain why none were needed).
