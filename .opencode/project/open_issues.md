# Open Issues

## Highest-Value Current Gaps

- The authoritative remediation benchmark gate is the compile-backed `17/17` supported-medium run, but the later current-main rerun reached `9/10`; that later result should be treated as a regression reference until the stronger baseline is re-confirmed on a fresh main rerun.
- Detection quality is now materially stronger on the graph-aware multi-hop rerun, but a small number of injection families still rely on heuristic evidence that creates concentrated false positives.
- Real-world validation is now cleanly separated and trustworthy, but it currently validates transfer for detection/explanation more strongly than remediation coverage because the chosen case studies surfaced no bounded remediation category.

## Known Bounded Risks

- Weak crypto is guarded and may still need safe refusal (`NO_FIX`) on harder cases.
- Explanation quality is good overall, but some categories remain weaker than others.
- Remediation is still model-sensitive even with the stronger span-edit contract and generic planning layer.
- Remaining detection weak spots are now concentrated rather than global:
  - weak-hash recall
  - SQL injection precision
  - command helper-taint precision
  - LDAP / XPath transform-sensitivity on benchmark-safe cases

## Confirmed Injection FP Clusters

- SQL injection false positives are concentrated in six benchmark cases:
  - `BenchmarkTest02363`
  - `BenchmarkTest00931`
  - `BenchmarkTest02739`
  - `BenchmarkTest00599`
  - `BenchmarkTest02633`
  - `BenchmarkTest00936`
- The SQL pattern is usually `sql_dynamic_query_detected` without equally strong taint proof after benchmark-safe transforms.
- Command injection false positives are concentrated in three benchmark cases:
  - `BenchmarkTest01794`
  - `BenchmarkTest01795`
  - `BenchmarkTest01796`
- The command pattern is helper-return taint over-trust reaching a command sink even when direct command taint flags are absent.
- LDAP injection false positives are concentrated in two benchmark cases:
  - `BenchmarkTest01491`
  - `BenchmarkTest01569`
- XPath injection false positives are concentrated in two benchmark cases:
  - `BenchmarkTest00941`
  - `BenchmarkTest01633`
- Authoritative artifact for this focused analysis:
  - `outputs/detection_calibration_multihop_refresh_v1/injection_fp_report.json`

## What Not To Overclaim

- Do not describe remediation as universally production-ready; the validated benchmark claim is the authoritative compile-backed rerun (`17/17` on `remediation_supported_medium.json`), not open-ended autonomous repair.
- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not treat sample-app behavior as the primary scientific evidence surface.
