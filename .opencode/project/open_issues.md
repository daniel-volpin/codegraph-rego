# Open Issues

## Highest-Value Current Gaps

- The authoritative remediation benchmark gate is the compile-backed `17/17` supported-medium run, but the later current-main rerun reached `9/10`; that later result should be treated as a regression reference until the stronger baseline is re-confirmed on a fresh main rerun.
- Detection quality is materially stronger on the calibrated benchmark rerun, but some benchmark families still use heuristic evidence and can produce noise on broader codebases.
- Real-world validation is now cleanly separated and trustworthy, but it currently validates transfer for detection/explanation more strongly than remediation coverage because the chosen case studies surfaced no bounded remediation category.

## Known Bounded Risks

- Weak crypto is guarded and may still need safe refusal (`NO_FIX`) on harder cases.
- Explanation quality is good overall, but some categories remain weaker than others.
- Remediation is still model-sensitive even with the stronger span-edit contract and generic planning layer.
- Remaining detection weak spots are now concentrated rather than global:
  - weak-hash recall
  - command-injection recall
  - SQL injection precision
  - XPath coverage / balance

## What Not To Overclaim

- Do not describe remediation as universally production-ready; the validated benchmark claim is the authoritative compile-backed rerun (`17/17` on `remediation_supported_medium.json`), not open-ended autonomous repair.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
