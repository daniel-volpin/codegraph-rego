# Evaluation Artifacts

`outputs/` contains versioned research evidence plus ignored local run output. This file is an index, not a second metrics report. Current commands live in [`../REPRODUCIBILITY.md`](../REPRODUCIBILITY.md); historical claim limits live in [`../docs/thesis_context.md`](../docs/thesis_context.md).

## Versioned Evidence

| Directory | Purpose | Provenance |
| --- | --- | --- |
| `thesis_final_detection_full_v2/` | historical 454-case detection experiment; qualified evidence | SHA `7ad90a2`, tag `thesis-detection-v2-source` |
| `thesis_final_explanation_full_v2/` | explanation citation-grounding experiment | SHA `701d051`, tag `thesis-explanation-v2-source` |
| `thesis_final_remediation_v2/` | per-case evidence for the recorded 25-case remediation experiment | no `provenance.json`; use v4 as the revision anchor |
| `thesis_final_remediation_v3/` | intermediate provenance-backed remediation run | SHA `7ad90a2` |
| `thesis_final_remediation_v4/` | strongest provenance-backed recorded remediation run | SHA `80d0084`, tag `thesis-remediation-v4-source` |
| `2026-09-14-detection-full/group_*/` | eight clean source runs for the current full-corpus detection baseline | SHA `1dd1510`, clean tree |
| `2026-09-14-detection-full/detection_composed/` | composed current detection summary | source runs named by `composed_from` in `metrics.json` |

A composed detection directory is a merge, not an evaluation run, so it does not create its own `provenance.json`. Cite the source group runs it names.

Historical artifacts may contain absolute paths from the machine that produced them. Do not rewrite those records for cosmetic portability; provenance is evidence of the actual run. New provenance generation normalizes repository/corpus paths where possible.

## Canonical Protection

`outputs/canonical_manifest.sha256` and `tests/test_canonical_artifacts.py` protect the canonical `thesis_final_*` evidence. An intentional regeneration must update the artifacts and manifest together with:

```bash
uv run python scripts/evaluation/generate_canonical_manifest.py
```

Do not update the manifest for incidental local reruns.

## Local Output

`.gitignore` ignores ordinary `outputs/*` runs unless they are intentionally re-included as research evidence. Use `outputs/local_smoke/` for disposable smoke runs. Local comparison, UI-review, and ad-hoc evaluation directories are not part of the evidence contract.

## Naming New Runs

Prefer:

```text
outputs/<YYYY-MM-DD>-<evaluation>-<scope>/
```

A run that is proposed as new versioned evidence must have clear provenance, a documented claim it supports, and an explicit reason to be committed rather than regenerated locally. See [`../docs/architecture/artifact-policy.md`](../docs/architecture/artifact-policy.md).
