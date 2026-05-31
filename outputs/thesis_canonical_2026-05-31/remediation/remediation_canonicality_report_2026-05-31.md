# Remediation Canonicality Report

Use the provenance-backed PR verification run as the reproducibility check. Treat v2 25/25 as a historical metric artifact unless it is regenerated with exact-run provenance.

| Run | Attempted | Fully verified | Success rate | Brier | ECE | Provenance | Model | Summary conflict |
|---|---:|---:|---:|---:|---:|---|---|---|
| v2 | 25 | 25 | 1.0 | 0.005723 | 0.069612 | no | None | True |
| v3 | 25 | 18 | 0.72 | 0.095431 | 0.095705 | yes | gpt-5.4-mini | False |
| pr_full_verification_2026_05_11 | 25 | 19 | 0.76 | 0.092872 | 0.100345 | yes | gpt-5.4-mini | False |
| repro_2026_05_31 | failed before metrics | failed before metrics | n/a | n/a | n/a | no | n/a | failed run recorded: /Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/outputs/thesis_final_remediation_repro_2026-05-31/FAILED_RUN.md |
