# Canonical Thesis Evidence Bundle (2026-05-31)

This directory contains copied, thesis-citable evidence artifacts. Prefer these paths over older output directories.

## Packaging Metadata

- Branch: `thesis/reproducibility-hardening`
- Evidence source commit at packaging start: `883b1c8b299670902f662373feed727f40391253`
- Local release tag: `thesis-evidence-2026-05-31`
- Checker command:

```bash
.venv/bin/python scripts/evaluation/check_thesis_artifacts.py
.venv/bin/ruff check scripts/evaluation/check_thesis_artifacts.py scripts/evaluation/build_thesis_canonical_bundle.py scripts/evaluation/scan_owasp_comment_tokens.py
.venv/bin/python -m pytest tests/scripts/test_check_thesis_artifacts.py -q
```

- Checksum file: `outputs/thesis_canonical_2026-05-31/SHA256SUMS.txt` (the checksum file excludes itself).

## Do Not Cite Warning

Do not cite stale or historical paths directly unless the relevant manifest row marks them as historical evidence. In particular, do not cite `outputs/thesis_final_remediation_v2/summary.md` for Brier/ECE, and do not cite the absent Appendix-A path `outputs/thesis_final_remediation_supported_calibrated_codex_20260428_122959/`.

The remediation v2 25/25 result is metric-backed but not exact-run-provenance-backed. The canonical remediation reproducibility evidence is the PR verification run at `outputs/thesis_canonical_2026-05-31/remediation/pr_remediation_metrics.json`, which reports 19/25 fully verified with provenance and model `gpt-5.4-mini`.

## Claim Status Summary

Fully provenance-backed claims:

- `detection_headline`
- `detection_sample_basis`
- `explanation_citation_attribution`
- `remediation_pr_reproducibility_19_of_25`
- `f10_lexical_noise_java`
- `f10_owasp_regression`
- `f10_multiseed`
- `f10_comment_scan`

Historical-only or not fully provenance-backed claims:

- `remediation_v2_historical_25_of_25`: metric-backed, no exact-run provenance/model attribution.
- `policy_traceability`: source-audit only.
- `faiss_role`: source-audit only.
- `full_population_detection_attempt`: failed run recorded; no full-population metrics.

| Claim | Status | Action | Artifact examples |
| --- | --- | --- | --- |
| detection_headline | fully_provenance_backed | narrow | outputs/thesis_canonical_2026-05-31/detection/metrics.json; outputs/thesis_canonical_2026-05-31/detection/metrics.csv |
| detection_sample_basis | fully_provenance_backed | narrow | outputs/thesis_canonical_2026-05-31/detection/selection_summary.json |
| explanation_citation_attribution | fully_provenance_backed | replace | outputs/thesis_canonical_2026-05-31/explanation/citation_metrics.json; outputs/thesis_canonical_2026-05-31/explanation/citation_metrics.csv |
| remediation_v2_historical_25_of_25 | metric_backed_no_provenance | narrow | outputs/thesis_canonical_2026-05-31/remediation/v2_remediation_metrics.json; outputs/thesis_canonical_2026-05-31/remediation/v2_confidence_calibration.json |
| remediation_pr_reproducibility_19_of_25 | fully_provenance_backed | replace | outputs/thesis_canonical_2026-05-31/remediation/pr_remediation_metrics.json; outputs/thesis_canonical_2026-05-31/remediation/pr_confidence_calibration.json |
| f10_lexical_noise_java | fully_provenance_backed | replace | outputs/thesis_canonical_2026-05-31/f10_lexical_noise/metrics.json; outputs/thesis_canonical_2026-05-31/f10_lexical_noise/metrics.csv |
| f10_owasp_regression | fully_provenance_backed | keep | outputs/thesis_canonical_2026-05-31/f10_owasp_regression/metrics.json; outputs/thesis_canonical_2026-05-31/f10_owasp_regression/metrics.csv |
| f10_multiseed | fully_provenance_backed | keep | outputs/thesis_canonical_2026-05-31/f10_multiseed/metrics.json; outputs/thesis_canonical_2026-05-31/f10_multiseed/metrics.csv |
| f10_comment_scan | fully_provenance_backed | keep | outputs/thesis_canonical_2026-05-31/f10_comment_scan/summary.json; outputs/thesis_canonical_2026-05-31/f10_comment_scan/provenance.json |
| policy_traceability | source_audit_only | narrow | outputs/thesis_canonical_2026-05-31/policy_traceability/policy_traceability_table_2026-05-31.json; outputs/thesis_canonical_2026-05-31/policy_traceability/policy_traceability_table_2026-05-31.md |
| faiss_role | source_audit_only | narrow | outputs/thesis_canonical_2026-05-31/faiss_role/faiss_role_audit_2026-05-31.md |
| full_population_detection_attempt | failed_run_recorded | narrow | outputs/thesis_full_population_detection_2026-05-31/FAILED_RUN.md; outputs/thesis_full_population_detection_2026-05-31/NO_RETRY_ENV_NOT_FIXED.md |
