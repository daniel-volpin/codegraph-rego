# Copilot Agent Instructions

This repository uses Copilot Agent with context-based reference files for improved code suggestions and architectural reasoning.

---

## Context Anchors
- Read the canonical source directly; there is no separate context copy to keep in sync.
  - `docs/benchmark_context.md` — thesis benchmark scope, evidence anchors, and citation guardrails.
  - `docs/thesis_context.md` — claim limits, the provenance manifest, and the canonical runs.
  - `README.md` and `REPRODUCIBILITY.md` — setup, architecture, and runnable evaluation commands.
  - `outputs/README.md` — which artifact holds which result and how to cite it.
  - `docs/frontend_backend_contract.md` — API and SPA contracts.

---

## Usage
- Avoid re-analyzing the entire codebase if relevant context exists.
- For benchmark, thesis, or evaluation questions, read `docs/benchmark_context.md` first.
- For architecture questions, read `README.md` and `docs/frontend_backend_contract.md`.
- For configuration and secrets, read the environment variable reference in `REPRODUCIBILITY.md`; never hardcode values.
- For refactoring, check `docs/architecture/` for the decision record covering the area.

---

## Project Summary
- Converts Java/Spring codebases into a queryable knowledge graph and ISO-aligned compliance checker.
- Core modules: ingestion, embedding, search, policy evaluation, LLM explanations, and agentic remediation.
- Integrates Neo4j, FAISS, OPA/Rego, an OpenAI-compatible LLM client, bounded remediation, and FastAPI.
- Frontend: Vite + React + TypeScript SPA with react-router-dom, TanStack Query, Zod, Radix UI, and Tailwind.

---

## Best Practices
- Keep code modular and maintain separation of concerns.
- Use environment variables for configuration and secrets (via `codegraph/config.py` Pydantic BaseSettings).
- Add or update tests for new features.
- Update the canonical doc when architecture changes; do not add a parallel summary.
- Do not invent or infer architecture beyond documented context.

---

## Context Refresh
- After significant changes, update the canonical docs listed under Context Anchors.
