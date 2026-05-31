# Thesis Evidence Manifest (2026-05-31)

| Claim | Status | Artifacts | Action | Notes |
| --- | --- | --- | --- | --- |
| detection_headline | confirmed | outputs/thesis_final_detection_full_v2/metrics.json<br>outputs/thesis_final_detection_full_v2/table_with_semantics.md | narrow | Overall is recomputed over selected testcase union and is not the arithmetic sum of category rows. |
| detection_sample_basis | confirmed | outputs/thesis_final_detection_full_v2/selection_summary.json | narrow | Directory name _full means full configured eight-family sample, not all available cases. |
| explanation_citation_attribution | confirmed | outputs/pr_full_verification_2026-05-11/explanation_full/citation_metrics.json<br>outputs/pr_full_verification_2026-05-11/explanation_full/explanation_summary_for_thesis.json | replace | This evaluates citation-style attribution, not semantic faithfulness. |
| remediation_v2_25_of_25_metric_artifact | confirmed_without_provenance | outputs/thesis_final_remediation_v2/remediation_metrics.json<br>outputs/thesis_final_remediation_v2/confidence_calibration.json | narrow | summary.md Brier/ECE is stale if STALE_SUMMARY_DO_NOT_CITE.md exists. |
| remediation_provenance_backed_rerun | confirmed | outputs/pr_full_verification_2026-05-11/remediation_supported_medium/remediation_metrics.json<br>outputs/remediation_canonicality_report_2026-05-31.json | replace | Use this as reproducibility evidence unless a new run is completed and chosen. |
| f10_lexical_noise_java | reproduced | outputs/lexical_noise_eval_v1/metrics.json<br>outputs/lexical_noise_eval_v1/provenance.json<br>outputs/f10_reproduction_comparison_2026-05-31.json | replace | Keep the LexicalNoiseJava and OWASP point metrics. Replace the LexicalNoiseJava 95% CI if citing the regenerated artifact: delta FPR CI is [-0.500, -0.154] with seed 42 and 2000 bootstrap resamples, not [-0.478, -0.154]. |
| f10_owasp_lexical_regression | reproduced | outputs/owasp_lexical_eval_v1/metrics.json<br>outputs/owasp_lexical_eval_v1/provenance.json | keep | Expected thesis values must be checked against this artifact. |
| f10_owasp_multi_seed_stability | reproduced | outputs/owasp_multiseed_v1/metrics.json<br>outputs/owasp_multiseed_v1/provenance.json | keep | Uses limit_per_cwe from the multiseed artifact. |
| owasp_comment_token_absence_scan | reproduced | outputs/owasp_comment_token_scan_v1/summary.json<br>outputs/owasp_comment_token_scan_v1/provenance.json | keep | Expected total Java cases is 2740. |
| norm_to_policy_mapping | confirmed | outputs/policy_traceability_table_2026-05-31.json | narrow | The evaluated injection/path families are pragmatic benchmark mappings, not direct ISO clauses. |
| faiss_role | confirmed | outputs/faiss_role_audit_2026-05-31.md | narrow | No FAISS-off detection ablation artifact exists. |
