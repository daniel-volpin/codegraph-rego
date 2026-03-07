# Open Issues

## Highest-Value Current Gaps

- Remediation success rate is still low on the supported-medium benchmark run (`6/17`).
- Compile-backed remediation verification is not demonstrated in the benchmark outputs (`build_attempted=0`).
- Some benchmark families still use heuristic detection and can produce noise on broader codebases.

## Known Bounded Risks

- Weak crypto is guarded and may still need safe refusal (`NO_FIX`) on harder cases.
- Explanation quality is good overall, but some categories remain weaker than others.

## What Not To Overclaim

- Do not describe remediation as universally production-ready.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
