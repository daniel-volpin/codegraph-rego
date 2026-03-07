# Current State

CodeGraph is a benchmark-backed JVM security/compliance framework. The primary proof surface is **OWASP Benchmark**, with realistic apps used only as secondary workflow case studies.

## Active Benchmark Scope

- `CWE-22` -> `ISO-A.8-PATH-TRAVERSAL`
- `CWE-78` -> `ISO-A.8-CMD-INJECTION`
- `CWE-89` -> `ISO-A.8-SQL-INJECTION`
- `CWE-90` -> `ISO-A.8-LDAP-INJECTION`
- `CWE-327` -> `ISO-A.10-WEAK-CRYPTO`
- `CWE-328` -> `ISO-A.10-WEAK-HASH`
- `CWE-330` -> `ISO-A.10-WEAK-RANDOM`
- `CWE-643` -> `ISO-A.8-XPATH-INJECTION`

## Remediation Support Tiers

- `full`
  - `ISO-A.10-WEAK-HASH`
  - `ISO-A.10-WEAK-RANDOM`
- `guarded`
  - `ISO-A.10-WEAK-CRYPTO`
- `manual`
  - SQL injection, path traversal, command injection, LDAP injection, XPath injection
  - access-control/logging rules such as `ISO-A.9.4.1` and `ISO-A.12.4.1`

## Canonical Configs

- Canonical benchmark configs live in `configs/benchmark/`.
- Root-level `configs/benchmark_selection*.json` are compatibility shims only.
- Most important configs:
  - `baseline.json`
  - `multicat_medium.json`
  - `multicat_full.json`
  - `framework_demo.json`
  - `remediation_supported_medium.json`

## Recommended Local Models

- Explanation: `qwen3.5-9b-mlx`
- Remediation: `qwen/qwen3-coder-30b`
- Runtime: LM Studio with `Auto-Evict` enabled and TTL hints from CodeGraph

## Current Architecture Signals

- Explanation uses strict structured output (`Citation / Why / Fix`).
- Remediation uses a structured contract:
  - `decision`
  - `replacement_method_lines`
  - derived `replacement_method_code`
  - `reason`
- Benchmark-first outputs are the authoritative evidence for current capability.
