# Benchmark Latest

Latest thesis-grade benchmark results on this repository state.

## Detection Full

Source: `outputs/detection_calibration_command_safe_suppressor_v1/table.md`

- Overall:
  - `TP=183`
  - `FP=81`
  - `FN=50`
  - `Precision=0.6932`
  - `Recall=0.7854`
  - `F1=0.7364`

## Explanation Full

Source: `outputs/thesis_final_explanation_full/table.md`

- Surfaced violations evaluated: `112`
- Overall `Citation@Context`: `0.8125`
- Overall `Citation@NoContext`: `0.8125`

## Remediation Supported Medium (Compile-Backed Product Gate)

Source: `outputs/repro_supported_medium_branch_benchmarktest01017_fix/summary.md`

- Attempted supported cases: `17`
- Structured valid: `17`
- Replacement applied: `17`
- Policy fixed: `17`
- Build attempted: `17`
- Build success: `17`
- Fully verified success rate: `100%`

## Remediation Bounded Smoke

Source: `outputs/span_edit_bounded_smoke_v2/summary.md`

- Attempted supported cases: `3`
- Fully verified success rate: `100%`

## Reading The Results

- Detection, explanation, and bounded remediation are now all benchmark-backed at materially stronger levels than the earlier thesis baseline.
- Compile-backed remediation is now real on the successful supported cases.
- Remediation remains bounded, but the current supported-medium compile-backed rerun now reaches `17/17`.
