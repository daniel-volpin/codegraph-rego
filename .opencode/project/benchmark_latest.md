# Benchmark Latest

Latest thesis-grade benchmark results on this repository state.

## Detection Full

Source: `outputs/thesis_final_detection_full/table.md`

- Overall:
  - `TP=123`
  - `FP=96`
  - `FN=110`
  - `Precision=0.5616`
  - `Recall=0.5279`
  - `F1=0.5442`

## Explanation Full

Source: `outputs/thesis_final_explanation_full/table.md`

- Surfaced violations evaluated: `112`
- Overall `Citation@Context`: `0.8125`
- Overall `Citation@NoContext`: `0.8125`

## Remediation Supported Medium

Source: `outputs/thesis_final_remediation_supported_medium/remediation_metrics.json`

- Attempted supported cases: `17`
- Successful: `6`
- Success rate: `35.29%`
- Build attempts: `0`

## Reading The Results

- Detection and explanation are strong enough to support the benchmark-first thesis story.
- Remediation is real and bounded, but still partial rather than universally reliable.
