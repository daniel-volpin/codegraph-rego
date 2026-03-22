# Open Issues

## Highest-Value Current Gaps

- The thesis-final remediation baseline is `outputs/thesis_final_remediation_v2/` (25/25 OK, fix+build success 1.000, confidence calibration populated); the earlier `outputs/repro_supported_medium_branch_benchmarktest01017_fix/` (17/17) is preserved as a historical reference only.
- Detection quality is confirmed at F1=0.953 in `outputs/thesis_final_detection_full/`; a small number of injection families still show concentrated precision noise (command FP=3, path/sql FP=2 each).
- Real-world validation is now cleanly separated and trustworthy, but it currently validates transfer for detection/explanation more strongly than remediation coverage because the chosen case studies surfaced no bounded remediation category.

## Known Bounded Risks

- Weak crypto is guarded and may still need safe refusal (`NO_FIX`) on harder cases.
- Explanation quality is good overall, but some categories remain weaker than others.
- Remediation is still model-sensitive even with the stronger span-edit contract and generic planning layer.
- Remaining detection weak spots are now concentrated rather than global:
  - weak-hash recall
  - command precision on benchmark-safe transforms/helper returns
  - LDAP / XPath transform-sensitivity on benchmark-safe cases

## Current Injection Precision Shape

- SQL precision/recall was materially improved by requiring sink-level taint evidence, yielding `TP=35`, `FP=2`, `FN=0` on the refreshed full run.
- Command injection remains the largest residual injection precision gap (`FP=3` in `outputs/thesis_final_detection_full/`), though full-category recall is confirmed at R=1.000.
- LDAP and XPath are now smaller precision gaps (`FP=1` each) and remain sensitive to transform/sanitization modeling.
- Path traversal precision remains strong but not perfect (`FP=2`).
- The older per-case injection false-positive cluster artifact remains useful as a reference snapshot:
  - `outputs/detection_calibration_multihop_refresh_v3/injection_fp_report.json`

## What Not To Overclaim

- Do not describe remediation as universally production-ready; the validated benchmark claim is the thesis-final compile-backed run (`25/25` on `remediation_supported_medium.json`, `mode=dry_run`), not open-ended autonomous repair.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
