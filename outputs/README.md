# Evaluation artifacts

Index of evaluation evidence: what each directory holds, whether it is tracked, and which commit its provenance names.

Figures live elsewhere. `docs/thesis_context.md` owns the qualified historical detection figure and its caveat; `REPRODUCIBILITY.md` owns the current measured figure beside the command that produces it. Link to those instead of copying numbers here.

## Naming

New runs use `outputs/<YYYY-MM-DD>-<eval>-<scope>/`, for example `outputs/2026-09-13-detection-full/`.

The existing `thesis_final_*` and `_vN` names stay. `canonical_manifest.sha256` pins them by path, each `provenance.json` records its own `output_dir`, and the dated records under `docs/` and the thesis prose cite them.

## Tracked artifacts

| Directory | Holds | Status | Provenance SHA | Pinned by |
| --- | --- | --- | --- | --- |
| `thesis_final_detection_full_v2/` | detection metrics on the 454-case `multicat_full.json` sample | qualified; does not reproduce | `7ad90a2` | `thesis-detection-v2-source` |
| `thesis_final_explanation_full_v2/` | citation-grounding rates, with and without context | canonical | `701d051` | `thesis-explanation-v2-source` |
| `thesis_final_remediation_v2/` | 181 files: per-case JSON plus 25 `.patch` files | superseded; no `provenance.json` | none recorded | — |
| `thesis_final_remediation_v3/` | verified-success rate and confidence calibration | superseded by v4 | `7ad90a2` | `thesis-detection-v2-source` |
| `thesis_final_remediation_v4/` | verified-success rate and confidence calibration | canonical | `80d0084` | `thesis-remediation-v4-source` |
| `local_smoke/detection_composed_final/` | current detection baseline, merged from the eight `group_*` runs | current; summary files only | none of its own | see `composed_from` |
| `local_smoke/group_*/` | the eight per-group runs it merges | current; summary and provenance only | `6aa9026`, `dirty: true` | `thesis-detection-baseline-2026-09-13-source` |

A composed directory is a merge, not a run, so nothing writes a `provenance.json` into it: `compose_benchmark_eval.py` records `composed_from` in `metrics.json`, and the per-group directories it names carry the provenance.

Tags are load-bearing here. This repository squash-merges, so a feature-branch commit never becomes an ancestor of `main`; without these tags three SHAs were reachable from no ref and the fourth only from a prunable branch.

`local_smoke/` sits outside the checksum tripwire, which globs `outputs/thesis_final_*`. It is tracked so the current figure has evidence in the repository, but it is not canonical and its provenance records a dirty tree. **Outstanding:** re-run the composed evaluation on a clean checkout into a dated directory.

`thesis_final_remediation_v2/` is missing from the canonical-runs list in `docs/thesis_context.md`, while `docs/benchmark_context.md` still calls it the remediation baseline.

## Untracked

`.gitignore` ignores `outputs/*` and re-includes tracked files by explicit negation, so these are absent from a clone — including each group's `case_outcomes.jsonl`, the per-case record behind the union any-rule Overall row.

| Directory | Holds | Note |
| --- | --- | --- |
| `branch_baseline_recovery/` | local comparison runs | disposable |
| `test_policy_ui_reviews/` | UI review store fixtures | disposable |

## Changing an artifact

`outputs/canonical_manifest.sha256` and `tests/test_canonical_artifacts.py` protect everything under `outputs/thesis_final_*`. A deliberate regeneration updates the manifest with `scripts/evaluation/generate_canonical_manifest.py` in the same commit. `docs/architecture/artifact-policy.md` defines which artifact classes belong in git.
