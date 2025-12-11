# Java Code Graph & Search

FastAPI service that turns a Java/Spring codebase into a queryable knowledge graph, semantic search index, and ISO 27001 compliance checker. It combines:

- **Ingestion** – parses Java sources with `javalang`, stores classes/methods in Neo4j, and links `DECLARES`, `CALLS`, `USES`, `EXTENDS`, `IMPLEMENTS`, and `NESTED_IN` relationships.
- **Semantic search** – embeds method snippets with Sentence Transformers, saves a FAISS index, and performs hybrid search that adds graph context.
- **Policy evaluation** – exports Neo4j facts to OPA/Rego to enforce ISO controls, with optional LiteLLM-powered explanations.
- **Remediation** – agentic “Fix & Verify” loop that proposes patches (LLM), applies them in a temp workspace, compiles, re-ingests, and re-runs OPA to validate fixes.
- **API surface** – `/upload`, `/search`, `/policy/evaluate`, `/policy/evaluate_with_llm`, and `/health`.

---

## Quick Start

1. **Prerequisites**
   - Python 3.10+
   - Neo4j 5.x reachable at `bolt://127.0.0.1:7687`
   - OPA CLI on `PATH` (only needed for policy evaluation)
   - Internet access on first run to download the embedding model

2. **Install dependencies**

   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   # or use conda: conda create -n codegraph python=3.10 -y && conda activate codegraph
   ```

3. **Configure**
   - Copy `.env.example` to `.env` (optional but recommended).
   - Set overrides as needed:
     - `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASS`
     - `JAVA_ROOT_DIR` (defaults to `<repo>/uploaded_code`)
     - `INDEX_DIR`, `EMBEDDING_MODEL_NAME`
     - `LLM_PROVIDER`, `LLM_MODEL`, `LLM_API_KEY`, `LLM_API_BASE` for LiteLLM routing

4. **Ingest & embed (one-time per codebase change)**

   ```bash
   export JAVA_ROOT_DIR=/abs/path/to/project/src/main/java  # optional if using defaults
   python3 codebase_to_neo4j.py           # parses Java, writes graph to Neo4j
   python3 build_code_embeddings.py       # builds FAISS index + signature maps
   ```

5. **Run the API**

   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2
   ```

- `POST /search` (`query=...` form field) → semantic hits + graph neighbours
- `GET /policy/evaluate` → raw ISO control violations (OPA)  
- `GET /policy/catalog` → catalog of controls, evidence requirements, and Rego rule mapping  
- `POST /policy/evaluate_with_llm?limit=5&model=...` → violations + LLM guidance  
- `POST /upload` (zip file) → safe extraction, ingestion, embedding rebuild  
- `GET /health` → readiness check for Neo4j, FAISS, signature map, model, OPA

---

## Configuration Reference

- `config.py` centralises defaults and auto-loads `.env` when `python-dotenv` is available.
- Output artifacts live in `INDEX_DIR` (default `index/`):
  - `code_embeddings.index`, `embedding_full_signature_map.json`, `embedding_signature_map.json` (legacy), `embedding_metadata.json`.
- Neo4j constraints (created idempotently in `db.ensure_constraints()`):
  - `CONSTRAINT class_fqn_unique IF NOT EXISTS FOR (c:Class) REQUIRE c.fqn IS UNIQUE`
  - `CONSTRAINT method_signature_unique IF NOT EXISTS FOR (m:Method) REQUIRE m.signature IS UNIQUE`
  - `INDEX method_full_signature_index IF NOT EXISTS FOR (m:Method) ON (m.full_signature)`

---

## Policy Checks (OPA/Rego)

`policy/iso_27001_access.rego` currently encodes three ISO 27001 controls using Neo4j method facts. Each control is described in `policy/catalog.json`, which records the normative reference, evidence fields, and the Rego rule that enforces it.

- **A.9.1.1 – Access control policy**  
  Flags public HTTP endpoints missing security annotations such as `@PreAuthorize`, `@Secured`, `@RolesAllowed`, or `@DenyAll`.

- **A.9.4.2 – Secure log-on procedures**  
  Flags authentication endpoints (`login`, `signin`, `authenticate`, etc.) that are public but still lack security annotations.

- **A.12.4.1 – Event logging**  
  Flags critical operations (mutation endpoints or verbs like `create`, `update`, `delete`) that show no evidence of logging (no logging/audit annotations and no calls to logger-style methods).

Violations include the control id, method signature, file path, and a short reason.  
Run locally with:

```bash
python3 policy_integration.py                # CLI summary
curl http://localhost:8000/policy/evaluate   # API endpoint
```

Add or adjust rules by editing files under `policy/`; OPA automatically loads every `.rego` file in that directory. Update `policy/catalog.json` alongside any new controls so evaluation responses and documentation stay traceable.

---

## LLM Enrichment

- `llm_integration.py` reads nearby source lines for each violation and asks an LLM model for concise remediation advice.
- Works with OpenAI and LM Studio via environment variables defined in `config.py`.
- Failures return a descriptive placeholder so API responses stay stable during misconfiguration or outages.

---

## Hybrid Search Workflow

1. `codebase_to_neo4j.py` discovers classes, methods, constructors, annotations, modifiers, file paths, and relationships.
2. `build_code_embeddings.py` extracts method snippets, encodes them with `SentenceTransformer`, and builds a cosine FAISS index plus signature maps.
3. `hybrid_code_search.py` lazily reloads the index/signature map on modification, embeds queries, retrieves semantic hits, and enriches results with two-hop Neo4j neighbourhoods.
4. `app.py` exposes `/search`, reusing the cached loaders to keep latency low.

Try it from the CLI:

```bash
python3 hybrid_code_search.py
```

---

## Remediation Preview (Virtual Fix)

- API endpoint:
  - `POST /remediation/preview` with `{"violation_id": "ISO-A.9.4.1"}` → returns a preview-only remediation:
    - LLM-proposed full replacement method (`updated_source_code`)
    - Short explanation
    - OPA verdict for the same rule (`opa_status`: `PASS`/`FAIL`)
- Flow: gather violation context → LLM proposes full method → build virtual graph context in memory → re-run OPA on the virtual bundle.
- No filesystem edits, compilation, or Neo4j mutations; the suggestion is for human review/copy‑paste.
- Requires `opa` on `PATH`, LiteLLM-configured LLM access, and Neo4j reachable for the initial evidence.

---

## Run & Verify Locally

1) **Backend**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 2
```
Verify:
- `curl http://localhost:8000/health` → all subsystems should be `true` (OPA requires binary on PATH).
- `curl http://localhost:8000/policy/evaluate` → returns violations or empty list.
- `curl -X POST http://localhost:8000/remediation/preview -H "Content-Type: application/json" -d '{"violation_id":"<ID>"}'` → returns a virtual fix preview with OPA PASS/FAIL.

2) **Frontend**
```bash
cd frontend
npm install
npm run build
npm run preview -- --host --port 4173
```
Verify:
- Open `http://localhost:4173` (or the preview host) → navigate to Policy page.
- Run “Evaluate Policies”, then click “Fix & Verify” on a violation; the card should update with agent state, diff, and verification result.

---

## Useful Cypher Queries

```cypher
// Classes and declared methods
MATCH (cls:Class)-[:DECLARES]->(m:Method)
RETURN cls.fqn AS class, m.signature AS method
LIMIT 20;

// Call graph fan-out
MATCH (caller:Method)-[:CALLS]->(callee:Method)
RETURN caller.signature AS caller, collect(callee.signature) AS callees
LIMIT 20;

// Public endpoints missing security annotations (matches policy rule)
MATCH (m:Method)
WHERE 'public' IN m.modifiers AND any(ann IN m.annotations WHERE ann ENDS WITH 'Mapping')
  AND none(ann IN m.annotations WHERE ann IN ['PreAuthorize','Secured','RolesAllowed','DenyAll'])
RETURN m.signature, m.file_path;
```

---

## Troubleshooting

- **FAISS / Torch on macOS** – prefer the `conda-forge` build (`conda install faiss-cpu -c conda-forge`) if pip wheels fail.
- **Neo4j connectivity** – ensure the database is running, credentials match `.env`, and use `bolt://127.0.0.1:7687` to avoid IPv6 issues.
- **OPA missing** – install via Homebrew (`brew install opa`) or download from the [OPA releases](https://www.openpolicyagent.org/docs/latest/#running-opa).
- **LLM errors** – verify `LLM_PROVIDER`, `LLM_API_BASE`, and `LLM_API_KEY`; failures fall back to explanatory placeholders in responses.
- **Cold start latency** – the API preloads the FAISS index and embedding model on startup; rebuild embeddings after any new ingestion to keep results fresh.

---

## Security Notes

- ZIP uploads use path traversal guards during extraction.
- CORS is wide open for local development; tighten `allow_origins` before deploying.
