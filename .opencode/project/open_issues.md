# Open Issues

## Highest-Value Current Gaps

- The prior supported-medium remediation quality gap is now closed on the current compile-backed benchmark rerun (`17/17`), but the same result still needs to hold across future model swaps and broader rule expansion.
- Some benchmark families still use heuristic detection and can produce noise on broader codebases.

## Known Bounded Risks

- Weak crypto is guarded and may still need safe refusal (`NO_FIX`) on harder cases.
- Explanation quality is good overall, but some categories remain weaker than others.
- Remediation is still model-sensitive even with the stronger span-edit contract and generic planning layer.

## What Not To Overclaim

- Do not describe remediation as universally production-ready; the validated benchmark claim is the current compile-backed rerun (`17/17` on `remediation_supported_medium.json`), not open-ended autonomous repair.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
