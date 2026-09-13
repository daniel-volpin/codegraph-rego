# Configuration as graph-recorded evidence

Status: accepted
Date: 2026-09-13
Relates to: `2026-09-12-detection-engine-plugin-contract.md`

## Problem

Crypto (CWE-327) and hash (CWE-328) detection was precise but incomplete:
precision 1.000 with recall 0.746 and 0.690 on the full corpus. Every one of
the 73 false negatives selected its algorithm through a properties file rather
than a literal:

```java
String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
MessageDigest.getInstance(algorithm);
```

No amount of additional API or alias patterns can decide these, and the
in-source defaults are misleading in *both* directions:

| Key | Source default | Declared value | Ground truth |
| --- | --- | --- | --- |
| `hashAlg1` | `SHA512` (strong) | `MD5` | vulnerable |
| `hashAlg2` | `SHA5` | `SHA-256` | safe |
| `cryptoAlg1` | `DESede/ECB` | `DES/ECB/PKCS5Padding` | vulnerable |
| `cryptoAlg2` | `AES/ECB` (weak) | `AES/CCM/NoPadding` | safe |

Deciding on the source default would have produced 40 false negatives and 27
false positives simultaneously. Only the declared value resolves these cases.

## Decision

Configuration is recorded as evidence in the graph, not resolved ad hoc inside
a rule.

- Ingestion collects `*.properties` declarations from the analysed workspace
  and writes `ConfigProperty` nodes scoped to the workspace revision, beside
  the code facts. Build output (`target/`, `build/`, `out/`) is excluded
  because it mirrors source resources and would invent conflicts.
- Policy evaluation reads those nodes from the graph. It does not read the
  filesystem: the analysed workspace is often temporary and already deleted by
  the time policies run, which is how the first implementation produced a
  silently dead feature.
- A method is linked to a key through the parser's recorded call-site argument
  literal (`ArgumentDTO.source`), not a source-text search. A key computed at
  runtime therefore does not resolve, and the policy stays silent instead of
  guessing.
- Rego owns the decision — which algorithms and modes are weak. Python only
  assembles facts.
- Findings cite the declaring file and line, so the evidence is complete.
- Conflicting declarations for one key are reported, never silently resolved.

## Consequence

| Category | Before | After |
| --- | --- | --- |
| Hash (CWE-328) | 89/0/40 — F1 0.817 | 129/0/0 — F1 1.000 |
| Crypto (CWE-327) | 97/0/33 — F1 0.855 | 130/0/0 — F1 1.000 |
| Overall (2092 cases) | 931/250/119 — F1 0.8346 | 979/250/71 — F1 0.8591 |

False positives did not change. The categories that do not read configuration
reproduced their previous numbers exactly, which is the control showing the
change is specific rather than a loosening.

The per-category gain (+73) exceeds the Overall gain (+48) because the Overall
row is union any-rule: 25 of the recovered cases were already counted through
an off-target rule from another family.

## Scope limit

A finding means **the configured value is weak**, not that a deployed system is
vulnerable. Environment variables, system properties, and profile overlays can
override a declared value at runtime. State this when citing these figures.

## Remediation is deliberately refused, not approximated

A candidate fix is re-evaluated from a virtual snapshot that carries no call
evidence, so a config-backed finding cannot be reproduced there. Both available
shortcuts are wrong: omitting config makes an unfixed candidate read as fixed,
while carrying it forward rejects a correct fix that replaced the property read
with a safe literal. The recheck therefore raises
`candidate_reverification_requires_config_evidence` and fails closed. The
condition is derived from the baseline evidence rather than a rule list, so any
future config-dependent rule is covered without a special case.

Lifting this requires re-deriving the candidate's own property reads from a
re-parsed candidate. That is deferred, and until then these controls are
detection-only.
