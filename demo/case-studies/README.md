# Real-World Case Studies

These case studies are secondary validation surfaces for CodeGraph. They are not replacements for the benchmark-backed baseline under `outputs/`.

## Selected Targets

- [Spring PetClinic](https://github.com/spring-projects/spring-petclinic)
  - realistic Spring Boot web application
  - use for transferability of ingest, search, policy evaluation, and explanation
- [gs-securing-web](https://github.com/spring-guides/gs-securing-web)
  - smaller Spring Security sample service
  - use for a lighter second JVM validation target

## Workflow

1. Acquire the source with the commands in the per-case-study documents.
2. Create a ZIP archive from the repository root.
3. Upload the archive to CodeGraph.
4. Poll upload status until ingest is complete.
5. Run search, policy evaluation, and structured explanation.
6. Attempt remediation only if a supported rule appears.

## API Flow

Start the backend first:

```bash
cd /path/to/codegraph-rego
make backend-dev   # starts Neo4j via compose, then the API on port 8000
```

Upload a ZIP:

```bash
curl -sS -F "file=@/tmp/<case-study>.zip" http://127.0.0.1:8000/upload
```

Poll status:

```bash
curl -sS http://127.0.0.1:8000/upload/status
```

Search sanity check:

```bash
curl -sS -X POST http://127.0.0.1:8000/search \
  -H "content-type: application/json" \
  -d '{"query":"password"}'
```

Policy evaluation:

```bash
curl -sS "http://127.0.0.1:8000/policy/evaluate"
```

Framework-demo-focus policy evaluation:

```bash
curl -sS "http://127.0.0.1:8000/policy/evaluate?rule_ids=ISO-A.10-WEAK-HASH&rule_ids=ISO-A.10-WEAK-RANDOM&rule_ids=ISO-A.10-WEAK-CRYPTO&rule_ids=ISO-A.8-SQL-INJECTION&rule_ids=ISO-A.8-PATH-TRAVERSAL&rule_ids=ISO-A.8-CMD-INJECTION&rule_ids=ISO-A.8-LDAP-INJECTION&rule_ids=ISO-A.8-XPATH-INJECTION"
```

Explain one finding:

```bash
curl -sS -X POST http://127.0.0.1:8000/policy/explain_one \
  -H "content-type: application/json" \
  -d @/tmp/explain_one_payload.json
```

## Output Convention

Keep case-study artifacts separate from benchmark evidence:

- `outputs/case_study_spring_petclinic/`
- `outputs/case_study_gs_securing_web/`

If no supported remediation finding appears in a case study, record that as a transferability observation rather than forcing remediation.
