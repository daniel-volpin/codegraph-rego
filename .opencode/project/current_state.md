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
  - `edits`
  - derived `replacement_method_code`
  - `reason`
- Remediation now operates on the exact target method snippet and applies bounded span edits rather than regenerating whole methods.
- Remediation now adds a small planning layer before generation:
  - classify local transformation shape
  - extract method-local invariants for value-producing invocation chains
  - validate those invariants after span reconstruction
- Remediation evaluation now writes live-progress artifacts during long runs:
  - `progress.json`
  - `results.jsonl`
  - `cases/<case-id>/`
- Compile-backed remediation is proven on the current supported benchmark subset:
  - bounded smoke: `3/3`
  - supported medium: `17/17`
- Detection calibration now uses a more maintainable evidence layer:
  - source analysis split into smaller analyzers under `source_analysis_core.py`
  - one-hop helper-return summaries under `helper_summaries.py`
  - command detection distinguishes payload taint from env-only taint
  - path detection now uses bounded sink-level path semantics with safe constant/resource suppression
  - helper summary resolution now falls back to same-file nested helpers when graph call edges are missing
- Detection calibration improved the current full benchmark baseline:
  - precision: `0.8357`
  - recall: `0.7639`
  - F1: `0.7982`
- Path traversal is no longer a primary weak spot on the sampled full benchmark rerun:
  - precision: `0.8571`
  - recall: `0.8276`
  - F1: `0.8421`
- Benchmark-first outputs are the authoritative evidence for current capability.
- Authoritative benchmark baselines are frozen as:
  - detection: `outputs/detection_calibration_path_precision_v4/`
  - explanation: `outputs/thesis_final_explanation_full/`
  - remediation: `outputs/repro_supported_medium_branch_benchmarktest01017_fix/`
- The later `outputs/final_full_remediation_current_main/` rerun (`9/10`) remains a useful regression reference, not the thesis headline baseline.
- Real-world validation is now cleanly separated from benchmark evidence:
  - `outputs/case_study_spring_petclinic/` validates ingest, policy evaluation, and explanation on a realistic Spring application.
  - `outputs/case_study_gs_securing_web/` validates a second Spring target with a clean upload-scoped graph and no surfaced policy findings.
