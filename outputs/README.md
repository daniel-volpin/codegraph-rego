# Evaluation artifacts

This file is the index of evaluation evidence: what each artifact directory holds, whether it is tracked, and which commit its provenance names.

Figures are owned elsewhere and are deliberately not repeated here. `docs/thesis_context.md` owns the qualified historical detection figure and its caveat; `REPRODUCIBILITY.md` owns the current measured figure beside the command that produces it. Link to those rather than copying numbers into this table.

## Naming

New runs use `outputs/<YYYY-MM-DD>-<eval>-<scope>/`, for example `outputs/2026-09-13-detection-full/`. Dates sort, describe themselves, and spare a reader from working out which counter is highest.

The existing `thesis_final_*` and `_vN` directories keep their names. They are published identifiers: `outputs/canonical_manifest.sha256` pins them by path, each `provenance.json` records its own `output_dir`, dated records under `docs/architecture/` and `docs/audit/` cite them, and so does the thesis prose. Renaming them would invalidate all four for a cosmetic gain.

## Tracked artifacts

| Directory | Holds | Status | Provenance SHA | SHA reachable from |
| --- | --- | --- | --- | --- |
| `thesis_final_detection_full_v2/` | detection metrics on the 454-case `multicat_full.json` sample | qualified; does not reproduce on the current baseline | `7ad90a2` | no ref |
| `thesis_final_explanation_full_v2/` | citation-grounding rates, with and without context | canonical | `701d051` | no ref |
| `thesis_final_remediation_v2/` | 181 files: per-case JSON plus 25 `.patch` files | superseded; carries no `provenance.json` | none recorded | — |
| `thesis_final_remediation_v3/` | verified-success rate and confidence calibration | superseded by v4 | `7ad90a2` | no ref |
| `thesis_final_remediation_v4/` | verified-success rate and confidence calibration | canonical | `80d0084` | tag `thesis-remediation-v4-source` |

Three of these recorded SHAs are reachable from no ref. This repository squash-merges, so a feature-branch commit never becomes an ancestor of `main`; those objects exist only in a clone that fetched the branch and will not survive a fresh clone. Pin them with tags before publishing.

`thesis_final_remediation_v2/` is the largest tracked bundle and the only one with no `provenance.json`, so it cannot be cited the way the others are. It is also absent from the canonical-runs list in `docs/thesis_context.md`, while `copilot-context/benchmark.md` still calls it the remediation baseline.

## Untracked

`.gitignore` ignores `outputs/*` and re-includes only canonical files by explicit negation, so everything below is absent from a clone.

| Directory | Holds | Note |
| --- | --- | --- |
| `local_smoke/` | the current detection baseline: `detection_composed_final/` and the eight `group_*` runs it composes | cited as evidence by `README.md` and `REPRODUCIBILITY.md`, but not present in the repository |
| `branch_baseline_recovery/` | local comparison runs | disposable |
| `test_policy_ui_reviews/` | UI review store fixtures | disposable |

`detection_composed_final/` is a merge rather than a run, so nothing writes a `provenance.json` into it. `compose_benchmark_eval.py` records `composed_from` in `metrics.json`, and each `group_*` directory it names carries the provenance; those eight runs all record SHA `6aa9026` with `dirty: true`.

## Adding or changing an artifact

Canonical artifacts under `outputs/thesis_final_*` are protected by `outputs/canonical_manifest.sha256` and the tripwire in `tests/test_canonical_artifacts.py`. A deliberate regeneration updates the manifest with `scripts/evaluation/generate_canonical_manifest.py` in the same commit. `docs/architecture/artifact-policy.md` defines which artifact classes belong in git at all.
