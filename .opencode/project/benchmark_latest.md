# Benchmark Latest

Latest thesis-grade benchmark results on this repository state.

## Detection Full

Source: `outputs/detection_calibration_path_precision_v4/table.md`

- Overall:
  - `TP=178`
  - `FP=35`
  - `FN=55`
  - `Precision=0.8357`
  - `Recall=0.7639`
  - `F1=0.7982`
- Notable calibrated category:
  - Path traversal: `TP=24`, `FP=4`, `FN=5`
  - Path traversal `Precision=0.8571`, `Recall=0.8276`, `F1=0.8421`

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
- Detection is now stronger because path findings are driven by bounded sink semantics plus one-hop helper summaries instead of broad fallback heuristics.
- Compile-backed remediation is now real on the successful supported cases.
- Remediation remains bounded, but the current supported-medium compile-backed rerun now reaches `17/17`.
