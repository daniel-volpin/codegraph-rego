# Repository Layout

| Path | Responsibility |
| --- | --- |
| `app.py` | ASGI development entrypoint |
| `api/` | thin FastAPI routers and HTTP models |
| `codegraph/` | ingestion, graph, search, policy, LLM, remediation, and evaluation domain logic |
| `tools/java-parser/` | bounded Eclipse JDT Java analysis adapter |
| `policy/` | OPA/Rego policies, OpenGrep rules, and policy catalog |
| `configs/benchmark/` | benchmark selections and policy/category registry |
| `frontend/` | React + TypeScript client |
| `scripts/` | operational ingestion, policy, search, and evaluation commands |
| `tests/` | backend, policy, adapter, integration, and evidence-contract tests |
| `outputs/` | intentionally versioned research evidence plus ignored local runs |
| `docs/` | current architecture, contract, benchmark, and research-evidence guidance |

The primary backend boundary is deliberate: `api/` adapts HTTP and `codegraph/` owns behavior. Evaluation and maintenance CLIs belong under `scripts/` rather than the repository root.

Generated retrieval state under `index/` and uploaded workspaces under `uploaded_code/` are local runtime artifacts, not source architecture.
