# Benchmark Latest

Latest thesis-grade benchmark results on this repository state.

## Detection Full

Source: `outputs/detection_calibration_multihop_refresh_v1/table.md`

- Overall:
  - `TP=215`
  - `FP=18`
  - `FN=18`
  - `Precision=0.9227`
  - `Recall=0.9227`
  - `F1=0.9227`
- Injection categories after graph-aware multi-hop taint confirmation:
  - SQL injection: `TP=32`, `FP=6`, `FN=3`, `Precision=0.8421`, `Recall=0.9143`, `F1=0.8767`
  - Path traversal: `TP=28`, `FP=3`, `FN=1`, `Precision=0.9032`, `Recall=0.9655`, `F1=0.9333`
  - Command injection: `TP=34`, `FP=3`, `FN=1`, `Precision=0.9189`, `Recall=0.9714`, `F1=0.9444`
  - LDAP injection: `TP=25`, `FP=2`, `FN=2`, `Precision=0.9259`, `Recall=0.9259`, `F1=0.9259`
  - XPath injection: `TP=15`, `FP=2`, `FN=0`, `Precision=0.8824`, `Recall=1.0`, `F1=0.9375`
- Focused FP analysis artifact:
  - `outputs/detection_calibration_multihop_refresh_v1/injection_fp_report.json`

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
- Current-main regression reference: `outputs/final_full_remediation_current_main/summary.md` (`9/10`)

## Authoritative vs Reference Runs

- Cite the following as the current benchmark-backed baseline:
  - detection: `outputs/detection_calibration_multihop_refresh_v1/`
  - explanation: `outputs/thesis_final_explanation_full/`
  - remediation: `outputs/repro_supported_medium_branch_benchmarktest01017_fix/`
- Treat `outputs/final_full_remediation_current_main/` as a later regression/reference run, not the thesis headline remediation result.

## Remediation Bounded Smoke

Source: `outputs/span_edit_bounded_smoke_v2/summary.md`

- Attempted supported cases: `3`
- Fully verified success rate: `100%`

## Reading The Results

- Detection, explanation, and bounded remediation are now all benchmark-backed at materially stronger levels than the earlier thesis baseline.
- Detection is now stronger because graph-aware multi-hop taint confirmation closes major interprocedural recall gaps across the injection families.
- The remaining injection false positives are concentrated rather than diffuse:
  - SQL precision noise from dynamic-query syntax without strong enough taint proof in some benchmark-safe transforms
  - command-injection noise from helper-return taint over-trust in a small cluster of cases
  - smaller LDAP and XPath precision gaps tied to transform/sanitization modeling
- Compile-backed remediation is now real on the successful supported cases.
- Remediation remains bounded, but the current supported-medium compile-backed rerun now reaches `17/17`.

## Real-World Case Studies

Source: `outputs/reporting/baseline_freeze_v0_2_0/report.md`

- `spring_petclinic`
  - ingest, search, policy evaluation, and explanation validated cleanly
  - first surfaced finding comes from the uploaded PetClinic workspace path
  - no bounded remediation category surfaced
- `gs_securing_web`
  - ingest and search validated cleanly
  - upload-scope graph isolation is now correct; no stale PetClinic/benchmark findings remain
  - no policy findings surfaced, which is an acceptable transferability outcome
