# Thesis Evidence Context

This file exists only to preserve the interpretation of recorded thesis evidence. Current architecture belongs in [`architecture/current-baseline.md`](./architecture/current-baseline.md); current evaluation commands belong in [`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md).

## Research Scope

CodeGraph evaluates a neurosymbolic Java security workflow:

1. parse Java and publish graph-structured evidence;
2. evaluate executable security policies;
3. ground model-generated explanations in retrieved evidence;
4. attempt bounded remediation;
5. re-verify candidate code with deterministic gates.

OWASP Benchmark is the primary quantitative detection surface. Real-world applications are secondary workflow case studies and must not be presented as equivalent benchmark evidence.

Use the terms **graph-based code understanding** or **graph-structured evidence**. The Neo4j model is not a full code property graph and CodeGraph does not claim whole-program dataflow coverage.

## Canonical Evidence

| Evaluation | Artifact | Recorded result | Interpretation |
| --- | --- | --- | --- |
| Historical detection v2 | `outputs/thesis_final_detection_full_v2/` | precision/recall/F1 `0.9528` on the 454-case sample | qualified historical evidence; do not present as the current baseline |
| Explanation grounding v2 | `outputs/thesis_final_explanation_full_v2/` | `Citation@TP=1.000`, `Citation@FP=1.000` with context | evidence for the recorded explanation experiment |
| Remediation v4 | `outputs/thesis_final_remediation_v4/` | `25/25` fully verified | strongest provenance-backed recorded remediation result |
| Current detection | `outputs/2026-09-14-detection-full/detection_composed/` | precision `0.7966`, recall `0.9324`, F1 `0.8591` on 2092 cases | current recorded full-corpus baseline |

The per-case bundle for the `25/25` remediation result is retained in `outputs/thesis_final_remediation_v2/`; it has no `provenance.json`, so v4 is the citation anchor when a recorded source revision is required. `outputs/thesis_final_remediation_v3/` records the intermediate `18/25` provenance-backed run.

Exact provenance and tags are indexed in [`../outputs/README.md`](../outputs/README.md).

## Detection v2 Qualification

The historical `0.9528` detection result is not the current baseline and does not reproduce on the modern source baseline. Its source revision included an OWASP-Benchmark class-name fingerprint in weak-random detection that was later removed. The repository now contains a regression test preventing that benchmark-specific fingerprint from returning.

Therefore:

- do not use `0.9528` as evidence of current detector performance;
- do not compare it directly with the current full-corpus row without stating the different source revision and sample;
- use the current detection artifact for claims about present behavior.

## Current Detection Interpretation

The current full-corpus result is composed from eight clean per-group runs that record commit `1dd1510`. The composed directory has no synthetic `provenance.json`; its `metrics.json` names the source runs and each source run carries provenance.

Crypto and hash controls use configuration evidence captured from the analysed workspace. A finding means the analysed configuration declares an unsafe value. It does not prove that a deployed runtime uses the same value after environment, system-property, or profile overrides.

The Overall benchmark row uses union-any-rule semantics. Per-category changes therefore cannot be added to predict the Overall delta because a testcase may already be counted through another rule.

## Taint Scope

The injection controls are owned by OpenGrep and use intra-file dataflow taint analysis. This is stronger than lexical source/sink co-occurrence, but it is not whole-program taint analysis. Cross-file propagation and other unsupported flow shapes remain explicit coverage limits.

OPA/Rego evaluates graph and configuration evidence for the rules it owns. Do not describe those rules as taint analysis unless the registered engine actually provides taint-flow evidence.

## Explanation Evaluation

The recorded explanation experiment compares evidence-grounded and no-context conditions on a fixed violation set. With context, the model selects constrained evidence cards and the server resolves citations from those cards. The no-context condition removes graph/vector evidence and uses a stricter citation contract.

`Citation@TP` measures citation grounding on true-positive findings. `Citation@FP` measures citation grounding on detector false positives. These metrics evaluate whether an explanation cites the supplied evidence correctly; they do not make an incorrect detector finding correct.

## Remediation Evaluation

Recorded remediation success means the candidate passed the experiment's required verification gates for the evaluated cases. It does not establish open-ended autonomous repair, semantic equivalence for arbitrary applications, or production safety.

Confidence calibration must name the evaluated population (`full`, `attempted_only`, or `no_fix_only`) when Brier/ECE values are cited. Abstentions and attempted repairs answer different calibration questions.

Candidate-local policy verification has no graph access. Findings that require graph-only configuration evidence cannot be proven fixed in that scope and must refuse rather than disappear as false success.

## Provenance Rules

Evaluation runs record source revision, dirty state, runtime/configuration information, hashes, corpus revision when applicable, seed, and model settings when applicable. Model-backed runs are not bitwise reproducible.

When citing a result:

- cite the artifact directory and its recorded source revision;
- name the corpus/sample and enabled engine set;
- preserve any qualification attached to that artifact;
- do not overwrite canonical artifacts with a newer run;
- use canonical short control IDs such as `ISO-A.10-WEAK-HASH` in new prose.

Canonical thesis artifacts under `outputs/thesis_final_*` are protected by `outputs/canonical_manifest.sha256` and `tests/test_canonical_artifacts.py`. Regenerate that manifest only for an intentional evidence update.

## Claim Limits

Do not claim that CodeGraph provides:

- a full code property graph;
- whole-program or cross-project taint analysis;
- production-grade multi-tenant isolation;
- proof that a configured unsafe value is active in deployment;
- guaranteed remediation for guarded categories;
- production safety from compilation, policy clearance, or model confidence alone.
