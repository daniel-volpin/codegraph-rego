# Java Code Graph & Search

This project ingests a Java codebase into Neo4j, builds a semantic search index with Sentence Transformers + FAISS, exposes a FastAPI for hybrid search (semantic + graph context), and evaluates OPA/Rego policies (e.g., ISO 27001 A.9.1.1).

The examples below use the code graph created by `codebase_to_neo4j.py`.

## List all classes

```cypher
MATCH (c:Class)
RETURN c.fqn
LIMIT 20;
```

## List all methods and their parent class

```cypher
MATCH (cls:Class)-[:DECLARES]->(m:Method)
RETURN cls.fqn AS class, m.signature AS method
LIMIT 20;
```

## List all nested class relationships

```cypher
MATCH (child:Class)-[:NESTED_IN]->(parent:Class)
RETURN child.fqn AS child, parent.fqn AS parent
LIMIT 20;
```

## List all EXTENDS relationships

```cypher
MATCH (child:Class)-[:EXTENDS]->(parent:Class)
RETURN child.fqn AS child, parent.fqn AS parent
LIMIT 20;
```

## List all IMPLEMENTS relationships

```cypher
MATCH (cls:Class)-[:IMPLEMENTS]->(iface:Class)
RETURN cls.fqn AS class, iface.fqn AS interface
LIMIT 20;
```

## List all USES relationships (method uses class as parameter)

```cypher
MATCH (m:Method)-[:USES]->(c:Class)
RETURN m.signature AS method, c.fqn AS used_class
LIMIT 20;
```

## List all DEPENDS_ON relationships (class has field of another class)

```cypher
MATCH (c1:Class)-[:DEPENDS_ON]->(c2:Class)
RETURN c1.fqn AS class, c2.fqn AS depends_on
LIMIT 20;
```

## List all CALLS relationships (method calls another method)

```cypher
MATCH (caller:Method)-[:CALLS]->(callee:Method)
RETURN caller.signature AS caller, callee.signature AS callee
LIMIT 20;
```

## Find all methods of a specific class

```cypher
MATCH (cls:Class {fqn: "your.package.YourClass"})-[:DECLARES]->(m:Method)
RETURN m.signature, m.name;
```

## Find all classes nested in a specific class

```cypher
MATCH (child:Class)-[:NESTED_IN]->(parent:Class {fqn: "your.package.OuterClass"})
RETURN child.fqn;
```

## Find all methods with a specific annotation

```cypher
MATCH (m:Method)
WHERE $annotation IN m.annotations
RETURN m.signature, m.annotations;
```

## Find all methods with a specific modifier (e.g., 'public')

```cypher
MATCH (m:Method)
WHERE 'public' IN m.modifiers
RETURN m.signature, m.modifiers;
```

## Find all methods in a file

```cypher
MATCH (m:Method)
WHERE m.file_path CONTAINS "SomeFile.java"
RETURN m.signature, m.file_path;
```

## Policy: Rego/OPA (Optional)

This project can evaluate ISO 27001 access control checks against the code graph using OPA/Rego.

- ISO rule representation example: see `policy/iso_rules.json`.
- Rego policy for A.9.1.1 (public endpoints must be secured): `policy/iso_27001_access.rego`.
- Input facts are generated from Neo4j: method signature, annotations, modifiers, file path.

Run locally with OPA CLI:

- Install OPA: <https://www.openpolicyagent.org/docs/latest/#running-opa>
- Ensure Neo4j contains your code graph (run `codebase_to_neo4j.py` first).
- From the repo root:
  - `python3 policy_integration.py` — prints violations as JSON
  - Or run via API: `GET /policy/evaluate` — returns violations and raw OPA output

Notes:

- The policy flags public HTTP endpoint methods (e.g., `@GetMapping`, `@PostMapping`, `@RequestMapping`) that lack security annotations (e.g., `@PreAuthorize`, `@Secured`, `@RolesAllowed`).
- You can add more Rego rules under `policy/` and OPA will load them automatically during evaluation.

## Setup & Run

Follow these steps to set up the Python environment, ingest your Java code into Neo4j, build embeddings, run the API, and evaluate Rego policies.

### Prerequisites

- Python 3.10+
- Neo4j running locally (Bolt) — default `bolt://127.0.0.1:7687`
- OPA (Rego) CLI installed and on PATH
- Internet access on first run to download models

### Install dependencies

- pip (recommended)
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`

- conda (alternative; helpful on macOS for FAISS/Torch)
  - `conda create -n codegraph python=3.10 -y`
  - `conda activate codegraph`
  - `pip install -r requirements.txt`

### Configure Neo4j and Java Source Path

- Configuration is centralized in `config.py` and can be overridden via `.env` (auto-loaded if `python-dotenv` is installed) or environment variables.
  - `NEO4J_URI` (default `bolt://127.0.0.1:7687`), `NEO4J_USER`, `NEO4J_PASS`
  - `INDEX_DIR`, `EMBEDDING_MODEL_NAME`, `UPLOAD_DIR`
- Point to your Java sources:
  - Preferred: set env var before running ingestion:
    - `export JAVA_ROOT_DIR=/absolute/path/to/your/project/src/main/java`
    - Then run: `python3 codebase_to_neo4j.py`
  - The `/upload` API auto-detects `src/main/java` in the uploaded zip and sets `JAVA_ROOT_DIR` for ingestion.
  - Fallback: the constant default in `codebase_to_neo4j.py` is used if the env var is not set.
  - `build_code_embeddings.py` uses file paths stored in Neo4j; ensure paths are valid after ingestion.

### Ingest → Index → Search (CLI)

- Ingest code graph into Neo4j:
  - `python3 codebase_to_neo4j.py`
- Build FAISS embeddings:
  - `python3 build_code_embeddings.py`
  - Outputs: `index/code_embeddings.index`, `index/embedding_signature_map.json`
  - Uses cosine similarity (normalized embeddings) with `IndexFlatIP`.
- Try hybrid search via CLI:
  - `python3 hybrid_code_search.py`

### Run the API

- Start server:
  - `uvicorn app:app --reload --port 8000`
- Endpoints:
  - Search: `POST /search` with form `query=...`
    - Example: `curl -X POST -F 'query=Where is access control enforced?' http://localhost:8000/search`
    - Returns typed neighbor items: `{type: 'Method'|'Class'|'Node', id: string}`
  - Policy evaluation: `GET /policy/evaluate`
    - Example: `curl http://localhost:8000/policy/evaluate`
  - Policy evaluation + LLM explanation: `POST /policy/evaluate_with_llm`
    - Optional env: set `OPENAI_API_KEY` to enable OpenAI; otherwise returns snippet-only stubs.
    - Example: `curl -X POST 'http://localhost:8000/policy/evaluate_with_llm?limit=5&model=gpt-4o-mini'`
  - Upload (optional): `POST /upload` with a `.zip` of a Java project
    - Note: ingestion scripts currently use a hardcoded `JAVA_ROOT_DIR`. If using upload, adjust `JAVA_ROOT_DIR` to the extracted path to reflect the uploaded project.

### Policy (Rego/OPA)

- Files:
  - Rules: `policy/iso_27001_access.rego` (ISO 27001 A.9.1.1)
  - Rule example JSON: `policy/iso_rules.json`
- Run via CLI:
  - `python3 policy_integration.py`
- Run via API:
  - `GET /policy/evaluate`
  - `POST /policy/evaluate_with_llm` (adds LLM explanations and remediation)
- What it checks now:
  - Public HTTP endpoints (`@GetMapping`, `@PostMapping`, etc.) missing security annotations (`@PreAuthorize`, `@Secured`, `@RolesAllowed`, etc.).

### Neo4j Constraints

On ingestion, the script attempts to create idempotent constraints (Neo4j 5.x):

- Unique: `:Class(fqn)`, `:Method(signature)`
- Index: `:Method(full_signature)`

If duplicate `signature` values already exist (e.g., overloads), the unique constraint may conflict. The script will warn; you can clean duplicates or migrate to using `full_signature` end-to-end.

### Troubleshooting

- FAISS issues on macOS: prefer conda `faiss-cpu` from `conda-forge`.
- Model download failures: ensure internet access on first run.
- Neo4j auth/connectivity: prefer IPv4 `bolt://127.0.0.1:7687` to avoid IPv6 localhost issues. Variables can be set in `.env`.
- OPA not found: install via Homebrew `brew install opa` or from OPA releases.
- LLM disabled: export `OPENAI_API_KEY` to enable, e.g., `export OPENAI_API_KEY=sk-...` and ensure `pip install openai` is installed in your environment.

### Security Notes

- Upload ZIP extraction uses path traversal safeguards.
- CORS is permissive for local dev; restrict in production.
