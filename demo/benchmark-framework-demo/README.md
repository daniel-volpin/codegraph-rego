# Benchmark Framework Demo Pack

This folder defines the curated OWASP Benchmark subset used to demonstrate the full CodeGraph framework on a single benchmark-rooted upload.

## Why this pack exists

The main thesis story is benchmark-centered:

1. ingest benchmark code
2. build graph evidence
3. detect benchmarked vulnerabilities
4. map them to ISO controls
5. explain them with grounded evidence
6. auto-remediate a bounded safe subset
7. re-verify via the same apply-and-check loop

The realistic Spring sample app remains useful for qualitative browsing and policy triage, but this benchmark pack is the recommended live demo input for the end-to-end framework story.

## Selected OWASP Benchmark cases

- `BenchmarkTest00046`
  - Category: `hash-md5`
  - Rule: `ISO-A.10-WEAK-HASH`
  - Expected tier: `full`
  - Rationale: direct `MessageDigest.getInstance("MD5")` usage

- `BenchmarkTest00083`
  - Category: `rng-insecure`
  - Rule: `ISO-A.10-WEAK-RANDOM`
  - Expected tier: `full`
  - Rationale: direct `new java.util.Random()` usage

- `BenchmarkTest00005`
  - Category: `crypto-md5`
  - Rule: `ISO-A.10-WEAK-CRYPTO`
  - Expected tier: `guarded`
  - Rationale: explicit weak cipher literal (`DES/CBC/PKCS5Padding`)

- `BenchmarkTest00008`
  - Category: `sql-injection`
  - Rule: `ISO-A.8-SQL-INJECTION`
  - Expected tier: `manual`
  - Rationale: explanation-first benchmark positive with no automatic remediation support

- `BenchmarkTest00001`
  - Category: `path-traversal`
  - Rule: `ISO-A.8-PATH-TRAVERSAL`
  - Expected tier: `manual`
  - Rationale: direct file path construction from cookie-derived input

- `BenchmarkTest00006`
  - Category: `command-injection`
  - Rule: `ISO-A.8-CMD-INJECTION`
  - Expected tier: `manual`
  - Rationale: `ProcessBuilder` command assembled from untrusted header input

- `BenchmarkTest00012`
  - Category: `ldap-injection`
  - Rule: `ISO-A.8-LDAP-INJECTION`
  - Expected tier: `manual`
  - Rationale: LDAP filter string concatenates untrusted header input

- `BenchmarkTest00207`
  - Category: `xpath-injection`
  - Rule: `ISO-A.8-XPATH-INJECTION`
  - Expected tier: `manual`
  - Rationale: XPath expression concatenates untrusted header input

## Generate the demo pack

Set `OWASP_BENCHMARK_ROOT` to your local BenchmarkJava checkout, then run:

```bash
python3 scripts/evaluation/build_benchmark_demo_pack.py \
  --benchmark-root "$OWASP_BENCHMARK_ROOT" \
  --output-dir demo/benchmark-framework-demo/build
```

This creates:

- a minimal Maven-rooted benchmark subset under `demo/benchmark-framework-demo/build/benchmark-framework-demo/`
- a zip upload at `demo/benchmark-framework-demo/build/benchmark-framework-demo.zip`

## What gets copied

The generator copies:

- the benchmark `pom.xml`
- Maven wrapper files when available
- `src/main/resources/`
- `src/main/java/org/owasp/benchmark/helpers/`
- the curated testcase Java files listed in `manifest.json`

This keeps the upload small while preserving enough build structure for the remediation apply-and-verify loop to attempt compilation.
