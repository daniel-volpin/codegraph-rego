# Open Issues

## Highest-Value Current Gaps

- The authoritative remediation benchmark gate is the compile-backed `17/17` supported-medium run, but the later current-main rerun reached `9/10`; that later result should be treated as a regression reference until the stronger baseline is re-confirmed on a fresh main rerun.
- Detection quality is now materially stronger on the refreshed full rerun (`outputs/review_multicat_full_fixpass_20260321c/`), but a small number of injection families still show concentrated precision noise.
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
- Command injection remains the largest residual injection precision gap on the refreshed full run (`FP=3`), although full-category recall is restored (`outputs/command_full_debug_20260321d/table.md` -> `TP=126`, `FN=0`).
- LDAP and XPath are now smaller precision gaps (`FP=1` each) and remain sensitive to transform/sanitization modeling.
- Path traversal precision remains strong but not perfect (`FP=2`).
- The older per-case injection false-positive cluster artifact remains useful as a reference snapshot:
  - `outputs/detection_calibration_multihop_refresh_v3/injection_fp_report.json`

## What Not To Overclaim

- Do not describe remediation as universally production-ready; the validated benchmark claim is the authoritative compile-backed rerun (`17/17` on `remediation_supported_medium.json`), not open-ended autonomous repair.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
