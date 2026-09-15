# Benchmark Context

OWASP Benchmark is CodeGraph's primary quantitative evaluation surface. `configs/benchmark/policy_registry.json` is the source of truth for category mappings, detection-engine ownership, and remediation tiers.

## Evaluated Categories

| CWE | Category | Rule | Remediation |
| --- | --- | --- | --- |
| CWE-22 | Path Traversal | `ISO-A.8-PATH-TRAVERSAL` | guarded |
| CWE-78 | Command Injection | `ISO-A.8-CMD-INJECTION` | guarded |
| CWE-89 | SQL Injection | `ISO-A.8-SQL-INJECTION` | guarded |
| CWE-90 | LDAP Injection | `ISO-A.8-LDAP-INJECTION` | guarded |
| CWE-327 | Weak Cryptography | `ISO-A.10-WEAK-CRYPTO` | guarded |
| CWE-328 | Weak Hash | `ISO-A.10-WEAK-HASH` | full |
| CWE-330 | Weak Randomness | `ISO-A.10-WEAK-RANDOM` | full |
| CWE-643 | XPath Injection | `ISO-A.8-XPATH-INJECTION` | guarded |

Access-control (`ISO-A.9.4.1`) and event-logging (`ISO-A.12.4.1`) controls are also registered with guarded remediation but are not part of the eight-category OWASP Benchmark detection table above.

`full` means a bounded automatic fix path is supported for the registered category. `guarded` means remediation may attempt a candidate but must refuse whenever evidence or a required verification gate is unavailable.

## Detection Engines

The five injection rules declare `evidence_source: opengrep` and use OpenGrep intra-file dataflow taint analysis. The remaining registered rules use OPA/Rego over graph/configuration evidence. Engine ownership is part of the policy contract; re-evaluation must use the registered engine rather than silently substituting another detector.

## Evidence

- Current full-corpus detection: `outputs/2026-09-14-detection-full/`
- Historical thesis detection: `outputs/thesis_final_detection_full_v2/` — qualified evidence; see `docs/thesis_context.md`
- Historical explanation evaluation: `outputs/thesis_final_explanation_full_v2/`
- Historical remediation evidence: `outputs/thesis_final_remediation_v4/` with per-case evidence retained in `outputs/thesis_final_remediation_v2/`

Exact commands and the current detection figure belong in [`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md). Artifact provenance belongs in [`../outputs/README.md`](../outputs/README.md). Historical thesis claims and limitations belong in [`thesis_context.md`](./thesis_context.md).

## Claim Limits

- Benchmark results describe the recorded corpus, configuration, source revision, and enabled engines; they are not guaranteed performance on arbitrary applications.
- Configuration-backed crypto/hash findings mean the analysed workspace declares an unsafe value, not that every deployment uses that value.
- OpenGrep taint analysis is intra-file, not a full cross-project or interprocedural whole-program taint engine.
- Bounded remediation evidence does not establish open-ended autonomous repair capability.
- Real-world sample applications are workflow case studies, not substitutes for the benchmark evidence surface.
