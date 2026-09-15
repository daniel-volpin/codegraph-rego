# Current Architecture

CodeGraph is a local-first Java security and compliance research system. The backend is Python/FastAPI, Java analysis is delegated to a bounded Eclipse JDT adapter, durable program state is stored in Neo4j, retrieval uses generated FAISS artifacts, policy evaluation is engine-routed, and the React frontend consumes typed HTTP contracts.

## Data Flow

```text
Java source
    |
    v
Eclipse JDT adapter
    |
    v
immutable Neo4j workspace revision
    |                  \
    |                   -> generated retrieval artifacts
    v
policy engine registry
    |-- OPA/Rego
    `-- OpenGrep taint rules
    |
    v
findings + evidence
    |             \
    |              -> grounded LLM explanation
    v
bounded or agentic remediation
    |
    v
isolated candidate verification
```

## Ownership Boundaries

- `api/` contains thin HTTP adapters. Domain behavior belongs in `codegraph/`.
- `tools/java-parser/` is the sole Java parser. Python sends source bytes and analysis inputs through the typed contract in `codegraph/java/`; there is no fallback Java parser.
- `codegraph/ingestion/` extracts JDT facts and publishes complete immutable graph revisions. Reads use the active revision; incompatible state requires a rebuild rather than a compatibility guess.
- `codegraph/search/` and `codegraph/embedding/` own retrieval artifacts. Generated index files are local build products and are validated against their generation metadata before use.
- `codegraph/policy/` owns policy evaluation. Each rule declares its `evidence_source` in `configs/benchmark/policy_registry.json`; re-evaluation must use the same registered engine.
- `codegraph/remediation/` owns candidate construction and verification. Original source bytes, exact ranges, identities, and hashes are authoritative; stale or ambiguous candidates fail closed.
- `frontend/` consumes backend DTOs through `frontend/src/lib/schemas.ts`; backend and frontend schema changes must land together.

## Detection

OPA/Rego evaluates graph and configuration evidence. OpenGrep owns the injection controls that require intra-file dataflow taint analysis. A missing configured engine is an error, not a silent reduction in coverage.

Configuration values are evidence captured from the analysed workspace and stored with the graph revision. Python assembles facts; policy rules decide whether a resolved value is unsafe. Conflicting or unresolved declarations remain explicit rather than being guessed.

## Remediation

CodeGraph supports bounded method replacement and multi-turn agentic remediation. Both operate in isolated scratch workspaces and require deterministic verification before a candidate can be accepted. Compilation, regression tests when present, and rule re-evaluation are independent gates; inability to execute a required gate is a refusal, not success.

Candidate-local policy verification does not have graph access. Findings that depend on graph-only configuration evidence therefore cannot be proven fixed in that scope and must refuse rather than disappear as false success.

## Evidence and Artifacts

Current generated runtime artifacts are rebuildable and are not source-controlled unless explicitly listed as research evidence. Versioned evaluation evidence under `outputs/` is governed by [`outputs/README.md`](../../outputs/README.md) and [`artifact-policy.md`](./artifact-policy.md). Historical thesis claims and their limitations belong in [`../thesis_context.md`](../thesis_context.md), not in runtime architecture docs.

## Canonical References

- Setup and evaluation: [`REPRODUCIBILITY.md`](../../REPRODUCIBILITY.md)
- API/frontend contract: [`../frontend_backend_contract.md`](../frontend_backend_contract.md)
- Benchmark mappings and tiers: [`../benchmark_context.md`](../benchmark_context.md)
- Repository layout: [`repo-layout.md`](./repo-layout.md)
- Engineering invariants: [`AGENTS.md`](../../AGENTS.md)
