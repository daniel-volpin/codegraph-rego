# Copilot Agent Instructions

This repository uses Copilot Agent with context-based reference files for improved code suggestions and architectural reasoning.

---

## Context Anchors
- Reference context from `/copilot-context/` before analyzing the entire codebase.
- Use the following context files for fast and accurate reasoning:
  - `benchmark.md` — Thesis benchmark scope, evidence anchors, and citation guardrails (the substantive context file).
  - `architecture.md`, `dependencies.md`, `services.md`, `configuration.md`, `improvements.md` — pointer files only; each redirects to the canonical source (`README.md`, `REPRODUCIBILITY.md`, `docs/`, manifests) so facts do not drift across documents.

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
- Converts Java/Spring codebases into a queryable knowledge graph and ISO-aligned compliance checker.
- Core modules: ingestion, embedding, search, policy evaluation, LLM explanations, and agentic remediation.
- Integrates Neo4j, FAISS, OPA/Rego, an OpenAI-compatible LLM client, bounded remediation, and FastAPI.
- Frontend: Vite + React + TypeScript SPA with react-router-dom, TanStack Query, Zod, Radix UI, and Tailwind.

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
