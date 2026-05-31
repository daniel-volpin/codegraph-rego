# Copilot Agent Instructions

This repository uses Copilot Agent with context-based reference files for improved code suggestions and architectural reasoning.

---

## Context Anchors
- Reference context from `/copilot-context/` before analyzing the entire codebase.
- Use the following context files for fast and accurate reasoning:
  - `benchmark.md` — Thesis benchmark scope, evidence anchors, and citation guardrails.
  - `architecture.md` — System design and module interactions.
  - `dependencies.md` — External libraries, APIs, and frameworks.
  - `services.md` — Service roles, functions, and dependencies.
  - `configuration.md` — Environment variables and configuration settings.
  - `improvements.md` — Technical debt and refactoring recommendations.

---

## Usage
- Prefer `/copilot-context/` for completions, summaries, and PR reviews.
- Avoid re-analyzing the entire codebase if relevant context exists.
- For benchmark, thesis, or evaluation questions, read `benchmark.md` first.
- For architecture-related questions, read from `architecture.md` and `services.md`.
- For configuration and secrets, use `configuration.md`; avoid hardcoding values.
- For refactoring, check `improvements.md` before suggesting new changes.

---

## Project Summary
- Converts Java/Spring codebases into a queryable knowledge graph and ISO 27001 compliance checker.
- Core modules: ingestion, embedding, search, policy evaluation, LLM explanations, and agentic remediation.
- Integrates Neo4j, FAISS, OPA/Rego, LiteLLM, and FastAPI.
- Frontend: Vite + React + TypeScript SPA with react-router-dom, react-query, lucide-react, prismjs.

---

## Best Practices
- Keep code modular and maintain separation of concerns.
- Use environment variables for configuration and secrets (via `codegraph/config.py` Pydantic BaseSettings).
- Add or update tests for new features.
- Update `/copilot-context/` when architecture changes.
- Do not invent or infer architecture beyond documented context.

---

## Context Refresh
- Regenerate `/copilot-context/` files after significant codebase changes.