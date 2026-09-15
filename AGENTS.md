# Agent Guide — CodeGraph

CodeGraph is a benchmark-backed Java security and compliance research system. This file contains active engineering invariants only. Setup and evaluation commands live in `REPRODUCIBILITY.md`; research claims and historical evidence live in `docs/thesis_context.md`.

## Read First

- `README.md` — project purpose and entry points.
- `REPRODUCIBILITY.md` — supported runtimes, configuration, validation, and evaluation commands.
- `docs/architecture/current-baseline.md` — current architecture and ownership boundaries.
- `docs/frontend_backend_contract.md` — backend/frontend contract.
- `docs/benchmark_context.md` — benchmark mappings and remediation tiers.

## Architecture Invariants

- Keep HTTP adapters in `api/` thin. Domain logic belongs in `codegraph/`.
- Eclipse JDT is the sole Java parser. Its Python contract lives in `codegraph/java/`; its adapter source lives in `tools/java-parser/`. Surface diagnostics and fail explicitly; never add a fallback parser or guessed source ranges.
- Preserve original source bytes, verified byte ranges, canonical `method_key` identities, and source hashes. Missing, stale, or ambiguous provenance must refuse an edit rather than fall back to text matching.
- Graph revisions are immutable. Read the active revision and publish complete successor revisions. Incompatible graph or retrieval generations require an explicit rebuild.
- Generated retrieval artifacts are local build products. Validate them against their generation metadata before use; do not treat `index/` as portable source-controlled state.
- Keep backend DTOs and `frontend/src/lib/schemas.ts` aligned. Frontend types are derived from schemas rather than duplicated manually.

## Policy and Evidence

- Detection engines are registry-routed. Every rule in `configs/benchmark/policy_registry.json` declares an `evidence_source`; re-evaluation must use that rule's owning engine.
- OPA/Rego owns graph/configuration-backed policy evaluation. OpenGrep owns the injection controls that require intra-file dataflow taint analysis. A missing engine is an error, not reduced coverage reported as success.
- Injection controls use dataflow taint analysis, not lexical co-occurrence heuristics. Known limits such as cross-file propagation or collection index sensitivity must remain explicit rather than being hidden with pattern matching.
- Configuration is evidence captured from the analysed workspace and stored in the graph revision. Python assembles facts; policy decides whether a value is unsafe. Conflicting or unresolved declarations remain explicit.
- Keep `policy/catalog.json`, policy implementations, OpenGrep rules, and `configs/benchmark/policy_registry.json` aligned. Do not silently change control IDs, evidence ownership, benchmark semantics, or remediation tiers.
- Every OpenGrep rule needs a matching annotated fixture under `tests/fixtures/opengrep/` that asserts both detection and non-detection behavior.

## Remediation

- CodeGraph supports bounded method replacement and multi-turn agentic remediation. Both operate in isolated scratch workspaces and must fail closed.
- Candidate acceptance is deterministic. Required compilation, regression tests when present, and rule re-evaluation must succeed before live apply; model confidence or policy clearance alone is not proof of behavioral safety.
- Candidate-local policy verification has no graph access. A finding that depends on graph-only configuration evidence cannot be proven fixed there and must refuse rather than disappear as false success.
- Re-verification must include relevant edits outside the target method, such as imports, when reconstructing the candidate file.
- Agent guidance should explain the policy gate and general security objective, not hardcode a library-specific answer for each rule.
- Structured model output is a contract. Malformed or truncated output is an explicit failure, not an invitation to repair it with parsing heuristics.

## LLM Transport

- Tool calls use typed OpenAI-compatible envelopes. Echoed `function.arguments` must be valid JSON strings.
- Provider admission, queue limits, retries, timeouts, and token budgets are configuration concerns; read current defaults from `codegraph/config.py` and `.env.example` rather than old notes.
- Local models may spend token budget on reasoning even when thinking is suppressed. Preserve explicit remediation budgets and log empty/truncated turns rather than guessing at missing tool calls.

## Imports and Module Boundaries

- Keep imports explicit, sorted, and at module scope unless a documented lazy import is required.
- Submodules import concrete source modules rather than parent-package barrels.
- Package barrels use the repository's existing lazy-export pattern when needed to avoid initialization cycles.
- Do not introduce duplicate helpers for identities, hashes, source ranges, engine routing, or configuration resolution when a canonical helper already exists.

## Workflow

- Inspect branch/worktree state before editing and preserve unrelated work.
- Use a focused feature branch and reviewable PR for substantial changes; do not push substantial work directly to `main`.
- Keep changes scoped to the stated task. Prefer small explicit interfaces over speculative abstractions.
- Reuse existing evidence when its source and runtime scope are unchanged. Rerun affected callers after contract changes rather than unrelated expensive suites after every edit.
- Never overwrite historical evaluation artifacts under `outputs/` for an incidental rerun.

## Validation

Choose the smallest relevant gate first, then broaden when the changed contract warrants it.

```bash
uv run python -m pytest -q <affected tests>
uv run ruff check .
```

For Java adapter changes:

```bash
make java-parser-build
```

For policy changes:

```bash
PATH="$(pwd)/.venv/bin:$PATH" make policy-check
make opengrep-test
```

For documentation:

```bash
make docs-check
```

For frontend changes:

```bash
cd frontend
yarn lint
yarn test
yarn build
```

Benchmark-sensitive changes require the focused smoke/evaluation commands in `REPRODUCIBILITY.md`. Report unavailable prerequisites honestly; do not replace a missing real gate with a mock and call it equivalent.

## Safety and Evidence

- Never inspect, print, or commit real credentials, `.env` files, private keys, or unrelated user data.
- Treat uploaded projects as untrusted. Build execution is a separate trust boundary from parsing; a parser timeout is not a sandbox.
- Preserve benchmark provenance and claim scope. Cite the artifact plus its recorded source revision when reporting a result.
- Do not describe graph evidence as a full code property graph, full interprocedural taint engine, or proof of production safety unless the implementation and evidence support that claim.
- Push, merge, deployment, live graph mutation, and paid model calls require the user's authorization.
