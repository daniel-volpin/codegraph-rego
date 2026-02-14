# AGENTS

This repository hosts **CodeGraph** — a FastAPI + Pydantic backend that turns a Java/Spring codebase into a queryable knowledge graph, semantic search index, and ISO 27001 compliance checker, paired with a Vite + React (TypeScript) frontend. Follow these conventions for any change in this repo.

## Project layout

```
app.py                          # FastAPI entrypoint
codegraph/                      # Core Python package
  config.py                     #   Pydantic BaseSettings – all env vars
  db.py                         #   Neo4j driver + idempotent constraints
  api/                          #   Pydantic request/response models
  embedding/                    #   FAISS index builder
  ingestion/                    #   Java parser → Neo4j
  llm/                          #   LiteLLM-based explanations
  policy/                       #   OPA/Rego evaluation, catalog, bundle runner
  remediation/                  #   Agentic fix-and-verify service
  search/                       #   Hybrid semantic + graph search
  common/                       #   Shared utilities (snippets, progress)
  evaluation/                   #   Benchmark evaluation helpers
api/routers/                    # FastAPI routers (health, upload, search, policy, remediation)
api/models/                     # Shared validation models
policy/                         # OPA Rego rules + catalog.json
frontend/                       # Vite + React + TypeScript SPA
  src/components/               #   Reusable UI components
  src/pages/                    #   Route-level pages
  src/lib/                      #   API client (api.ts) and shared types (types.ts)
  src/context/                  #   React context providers
configs/                        # Benchmark evaluation configs
tests/                          # pytest test suite
docs/                           # Design docs (frontend_backend_contract, remediation_prompting_design)
copilot-context/                # Copilot-specific context anchors
index/                          # FAISS index + signature maps (generated)
uploaded_code/                  # Workspace for uploaded Java projects
```

## Tooling & workflow

| Task | Command | Notes |
|------|---------|-------|
| Install all deps | `make install` | Backend via `uv`, frontend via `yarn` |
| Dev servers | `make dev` | Backend on `:8000`, frontend on `:5173` |
| Backend lint | `make lint` | Runs `ruff check .` + `yarn lint` |
| Backend format | `make format` | Runs `ruff format .` + `prettier` |
| Backend tests | `make test` | Runs `pytest` via `uv run` |
| Frontend build check | `cd frontend && yarn build` | Runs `tsc && vite build` |
| Docker | `make docker-up` / `make docker-down` | |

- **Package manager (backend):** `uv` with `pyproject.toml` — do NOT use `pip install -r requirements.txt`.
- **Package manager (frontend):** `yarn` — prefer `yarn add` over `npm install`.
- **Linter (backend):** `ruff` (line-length 120, target Python 3.10).
- **Linter (frontend):** `eslint` with TypeScript + React plugins.
- **Formatter:** `ruff format` (backend), `prettier` (frontend).

## Backend (Python)

- Target **Python 3.10+**. Prefer `pathlib.Path`, type hints, and small helpers over inline path/string juggling.
- Use structured logging via the standard `logging` module; avoid `print` for runtime diagnostics.
- **Configuration:** Reuse `codegraph.config.settings` (a `Pydantic BaseSettings` instance in `codegraph/config.py`). It auto-loads `.env`. Do NOT read environment variables directly with `os.getenv()`.
- **Database:** Keep Neo4j access centralized through `codegraph.db`. Add new constraints/indexes there idempotently.
- **Policy:** Keep `policy/` Rego rules and `policy/catalog.json` aligned. When adding a new control, add both the Rego rule AND a catalog entry so API responses stay traceable.
- **Remediation:** The remediation service in `codegraph/remediation/service.py` uses full method replacement (not unified diffs). It exposes two flows:
  - `preview_virtual_fix()` — virtual-only, no filesystem edits.
  - `apply_fix()` — temp workspace: apply → compile → re-ingest → OPA verify.
  - Unsupported rule IDs return `status=INVALID` without calling the LLM.
- **API routers** live in `api/routers/`. Current endpoints: `/health`, `/upload`, `/upload/status`, `/search`, `/policy/evaluate`, `/policy/evaluate_with_llm`, `/policy/catalog`, `/policy/explain_one`, `/policy/reviews` (GET + POST), `/remediation/preview`, `/remediation/apply`.

## Frontend (React + Vite)

- Use **functional React components** with hooks; colocate shared UI in `frontend/src/components/` and feature pages in `frontend/src/pages/`.
- **Routing:** `react-router-dom` v6 for client-side routing.
- **API layer:** Keep API interactions in `frontend/src/lib/api.ts`. Use `@tanstack/react-query` for async workflows.
- **Styling:** Vanilla CSS only (`App.css` for component styles, `index.css` for design tokens/resets). No Tailwind.
- **Icons:** `lucide-react` — do not add other icon libraries.
- **Code highlighting:** `prismjs` for syntax-highlighted code blocks.
- **Graph visualization:** `react-force-graph-2d` for interactive graph rendering.
- **Notifications:** `react-hot-toast` for toast messages.
- Read the API base URL from `VITE_API_BASE_URL`; avoid hardcoding backend hosts.

## Testing expectations

- **Backend:** run `make lint` (ruff) and `make test` (pytest) when touching Python code.
- **Frontend:** run `cd frontend && yarn build` (tsc + vite build) when modifying TypeScript/React code.
- If changes span both stacks, note the executed commands in the final summary.
- Use `python -m compileall codegraph api` as a quick syntax-only check when pytest is not needed.

## Documentation and responses

- Keep `README.md` in sync with user-facing behavior when adding endpoints, CLI scripts, or env vars.
- Update `copilot-context/` files when architecture changes significantly.
- In PR summaries, enumerate touched areas and list any tests/checks that were run (or explain why none were needed).
