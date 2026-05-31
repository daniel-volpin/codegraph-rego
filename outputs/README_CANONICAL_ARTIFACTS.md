# Canonical Artifact Index

| Artifact path | Status | Reason | Replacement path |
| --- | --- | --- | --- |
| outputs/thesis_canonical_2026-05-31/ | canonical | Copied bundle for thesis citation | n/a |
| outputs/thesis_final_detection_full_v2/ | canonical | Detection headline source with provenance and union-any-rule table semantics | outputs/thesis_canonical_2026-05-31/detection/ |
| outputs/thesis_final_detection_full/ | historical | Earlier detection run; replaced by v2 for thesis citation | outputs/thesis_final_detection_full_v2/ |
| outputs/thesis_final_explanation_full/ | historical/stale | Older explanation surface; replaced by PR verification TP/FP attribution run | outputs/pr_full_verification_2026-05-11/explanation_full/ |
| outputs/pr_full_verification_2026-05-11/explanation_full/ | canonical | Provenance-backed explanation citation-attribution evidence | outputs/thesis_canonical_2026-05-31/explanation/ |
| outputs/thesis_final_remediation_v2/ | historical | 25/25 metrics exist, but exact-run provenance/model attribution is missing | outputs/thesis_canonical_2026-05-31/remediation/ |
| outputs/thesis_final_remediation_v2/summary.md | stale/do-not-cite | Brier/ECE conflicts with JSON artifacts | outputs/thesis_final_remediation_v2/remediation_metrics.json |
| outputs/thesis_final_remediation_v3/ | historical | Provenance-backed but weaker 18/25 run; not thesis headline unless chosen | outputs/remediation_canonicality_report_2026-05-31.json |
| outputs/pr_full_verification_2026-05-11/remediation_supported_medium/ | canonical | 19/25 provenance-backed remediation reproducibility run | outputs/thesis_canonical_2026-05-31/remediation/ |
| outputs/thesis_final_remediation_supported_calibrated_codex_20260428_122959/ | do-not-cite | Path is absent in this checkout | outputs/thesis_canonical_2026-05-31/remediation/ |
| outputs/lexical_noise_eval_v1/ | canonical | Regenerated LexicalNoiseJava F10 point metrics/provenance | outputs/thesis_canonical_2026-05-31/f10_lexical_noise/ |
| outputs/owasp_lexical_eval_v1/ | canonical | Regenerated OWASP F10 regression/provenance | outputs/thesis_canonical_2026-05-31/f10_owasp_regression/ |
| outputs/owasp_multiseed_v1/ | canonical | Regenerated OWASP F10 multiseed/provenance | outputs/thesis_canonical_2026-05-31/f10_multiseed/ |
| outputs/owasp_comment_token_scan_v1/ | canonical | Full-corpus comment-token absence scan | outputs/thesis_canonical_2026-05-31/f10_comment_scan/ |
