# Open Issues

## Highest-Value Current Gaps

- Remediation is now compile-backed, but supported-medium is still not perfect (`9/10`).
- The remaining supported-medium failure is a weak-random semantic edit issue around preserving primitive-producing `Random` terminal calls such as `nextFloat()`.
- Some benchmark families still use heuristic detection and can produce noise on broader codebases.

## Known Bounded Risks

- Weak crypto is guarded and may still need safe refusal (`NO_FIX`) on harder cases.
- Explanation quality is good overall, but some categories remain weaker than others.
- Remediation is still model-sensitive even with the stronger span-edit contract.

## What Not To Overclaim

- Do not describe remediation as universally production-ready or fully solved across supported-medium; the current compile-backed supported-medium result is `9/10`, not `10/10`.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
