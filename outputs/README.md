# Evaluation artifacts

This file is the index of evaluation evidence: what each artifact directory holds, whether it is tracked, and which commit its provenance names.

Figures are owned elsewhere and are deliberately not repeated here. `docs/thesis_context.md` owns the qualified historical detection figure and its caveat; `REPRODUCIBILITY.md` owns the current measured figure beside the command that produces it. Link to those rather than copying numbers into this table.

## Naming

New runs use `outputs/<YYYY-MM-DD>-<eval>-<scope>/`, for example `outputs/2026-09-13-detection-full/`. Dates sort, describe themselves, and spare a reader from working out which counter is highest.

The existing `thesis_final_*` and `_vN` directories keep their names. They are published identifiers: `outputs/canonical_manifest.sha256` pins them by path, each `provenance.json` records its own `output_dir`, dated records under `docs/architecture/` and `docs/audit/` cite them, and so does the thesis prose. Renaming them would invalidate all four for a cosmetic gain.

## Tracked artifacts

| Directory | Holds | Status | Provenance SHA | SHA reachable from |
| --- | --- | --- | --- | --- |
| `thesis_final_detection_full_v2/` | detection metrics on the 454-case `multicat_full.json` sample | qualified; does not reproduce on the current baseline | `7ad90a2` | tag `thesis-detection-v2-source` |
| `thesis_final_explanation_full_v2/` | citation-grounding rates, with and without context | canonical | `701d051` | tag `thesis-explanation-v2-source` |
| `thesis_final_remediation_v2/` | 181 files: per-case JSON plus 25 `.patch` files | superseded; carries no `provenance.json` | none recorded | — |
| `thesis_final_remediation_v3/` | verified-success rate and confidence calibration | superseded by v4 | `7ad90a2` | tag `thesis-detection-v2-source` |
| `thesis_final_remediation_v4/` | verified-success rate and confidence calibration | canonical | `80d0084` | tag `thesis-remediation-v4-source` |
| `local_smoke/detection_composed_final/` | the current detection baseline, merged from the eight `group_*` runs | current; summary files only | none of its own | via `composed_from` |
| `local_smoke/group_*/` | the eight per-group runs the baseline merges | current; summary and provenance only | `6aa9026`, `dirty: true` | tag `thesis-detection-baseline-2026-09-13-source` |

This repository squash-merges, so a feature-branch commit never becomes an ancestor of `main`. Every recorded SHA is therefore pinned by a tag: `thesis-detection-v2-source`, `thesis-explanation-v2-source`, `thesis-remediation-v4-source`, and `thesis-detection-baseline-2026-09-13-source`. Without those, three of them were reachable from no ref and the fourth only from a feature branch that a prune would remove.

The `local_smoke/` files sit outside the checksum tripwire, which globs `outputs/thesis_final_*`. They are tracked so the current figure has evidence in the repository at all; they are not canonical thesis artifacts, and their provenance records a dirty tree. **Outstanding:** re-run the composed detection evaluation on a clean checkout into a dated directory, so the current figure gains clean-tree provenance under the naming convention above.

`thesis_final_remediation_v2/` is the largest tracked bundle and the only one with no `provenance.json`, so it cannot be cited the way the others are. It is also absent from the canonical-runs list in `docs/thesis_context.md`, while `docs/benchmark_context.md` still calls it the remediation baseline.

## Untracked

`.gitignore` ignores `outputs/*` and re-includes tracked files by explicit negation, so everything below is absent from a clone. Under `local_smoke/` that includes each group's `case_outcomes.jsonl`, the per-case record behind the union any-rule Overall row.

| Directory | Holds | Note |
| --- | --- | --- |
| `branch_baseline_recovery/` | local comparison runs | disposable |
| `test_policy_ui_reviews/` | UI review store fixtures | disposable |

`detection_composed_final/` is a merge rather than a run, so nothing writes a `provenance.json` into it. `compose_benchmark_eval.py` records `composed_from` in `metrics.json`, and each `group_*` directory it names carries the provenance; those eight runs all record SHA `6aa9026` with `dirty: true`.

## Adding or changing an artifact

Canonical artifacts under `outputs/thesis_final_*` are protected by `outputs/canonical_manifest.sha256` and the tripwire in `tests/test_canonical_artifacts.py`. A deliberate regeneration updates the manifest with `scripts/evaluation/generate_canonical_manifest.py` in the same commit. `docs/architecture/artifact-policy.md` defines which artifact classes belong in git at all.
