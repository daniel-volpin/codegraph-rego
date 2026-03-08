# Benchmark Latest

Latest thesis-grade benchmark results on this repository state.

## Detection Full

Source: `outputs/detection_calibration_full_v1/table.md`

- Overall:
  - `TP=125`
  - `FP=97`
  - `FN=108`
  - `Precision=0.5631`
  - `Recall=0.5365`
  - `F1=0.5495`

## Explanation Full

Source: `outputs/thesis_final_explanation_full/table.md`

- Surfaced violations evaluated: `112`
- Overall `Citation@Context`: `0.8125`
- Overall `Citation@NoContext`: `0.8125`

## Remediation Supported Medium (Compile-Backed Product Gate)

Source: `outputs/span_edit_supported_medium_v2/summary.md`

- Attempted supported cases: `10`
- Structured valid: `10`
- Replacement applied: `10`
- Policy fixed: `9`
- Build attempted: `10`
- Build success: `9`
- Fully verified success rate: `90%`

## Remediation Bounded Smoke

Source: `outputs/span_edit_bounded_smoke_v2/summary.md`

- Attempted supported cases: `3`
- Fully verified success rate: `100%`

## Reading The Results

- Detection and explanation are strong enough to support the benchmark-first thesis story.
- Compile-backed remediation is now real on the successful supported cases.
- Remediation remains bounded and still has one known supported-medium failure, so the current supported-medium ceiling is `9/10`.
