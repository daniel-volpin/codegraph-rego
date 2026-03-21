# Benchmark Latest

Latest thesis-grade benchmark results on this repository state.

## Detection Full

Source: `outputs/review_multicat_full_fixpass_20260321c/table.md`

- Overall:
  - `TP=222`
  - `FP=11`
  - `FN=11`
  - `Precision=0.9528`
  - `Recall=0.9528`
  - `F1=0.9528`
- Injection categories after graph-aware multi-hop taint confirmation:
  - SQL injection: `TP=35`, `FP=2`, `FN=0`, `Precision=0.9459`, `Recall=1.0`, `F1=0.9722`
  - Path traversal: `TP=29`, `FP=2`, `FN=0`, `Precision=0.9355`, `Recall=1.0`, `F1=0.9667`
  - Command injection: `TP=35`, `FP=3`, `FN=0`, `Precision=0.9211`, `Recall=1.0`, `F1=0.9589`
  - LDAP injection: `TP=27`, `FP=1`, `FN=0`, `Precision=0.9643`, `Recall=1.0`, `F1=0.9818`
  - XPath injection: `TP=15`, `FP=1`, `FN=0`, `Precision=0.9375`, `Recall=1.0`, `F1=0.9677`
- Full command-category confirmation:
  - `outputs/command_full_debug_20260321d/table.md` -> `TP=126`, `FP=12`, `FN=0`, `Recall=1.0`

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
  - detection: `outputs/review_multicat_full_fixpass_20260321c/`
  - explanation: `outputs/thesis_final_explanation_full/`
  - remediation: `outputs/repro_supported_medium_branch_benchmarktest01017_fix/`
- Treat `outputs/final_full_remediation_current_main/` as a later regression/reference run, not the thesis headline remediation result.

## Remediation Bounded Smoke

Source: `outputs/span_edit_bounded_smoke_v2/summary.md`

- Attempted supported cases: `3`
- Fully verified success rate: `100%`

## Reading The Results

- Detection, explanation, and bounded remediation are now all benchmark-backed at materially stronger levels than the earlier thesis baseline.
- Detection is now stronger because graph-aware multi-hop taint confirmation plus sink-level taint-evidence cleanup recovered command recall while reducing residual injection false positives.
- Remaining precision gaps are concentrated rather than diffuse, led by command injection and smaller path/LDAP/XPath clusters.
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
