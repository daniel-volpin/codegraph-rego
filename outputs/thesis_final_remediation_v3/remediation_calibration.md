# Remediation Calibration

Headline numbers below are computed over the **full** population (every result that carries a confidence score, including `NO_FIX` abstentions). F05 (PR thesis/defensibility-pass) adds a per-population breakdown to distinguish calibrated success probability from knew-when-to-abstain behavior.

- Cases with confidence: `21`
- Missing confidence: `4`
- Label: `fully_verified`
- Label definition: `fully_verified := policy_fixed is true and build_success is true`
- Positive labels: `18`
- Negative labels: `3`
- Brier score (full): `0.095431`
- ECE (full): `0.095705`

## Reliability Bins (full population)

| Bin | Count | Avg confidence | Empirical success | Gap |
| --- | --- | --- | --- | --- |
| 0.3-0.4 | 1 | 0.3318 | 0.0 | 0.3318 |
| 0.8-0.9 | 4 | 0.8909 | 1.0 | 0.1091 |
| 0.9-1.0 | 16 | 0.9526 | 0.875 | 0.0776 |

## Calibration by Population (F05)

| Population | Count | Positive | Negative | Brier | ECE |
| --- | --- | --- | --- | --- | --- |
| full | 21 | 18 | 3 | 0.095431 | 0.095705 |
| attempted_only | 20 | 18 | 2 | 0.094698 | 0.0839 |
| no_fix_only | 1 | 0 | 1 | 0.110091 | 0.3318 |

Population definitions:
- `full`: every result with a confidence score (legacy headline).
- `attempted_only`: results where the system attempted to apply a remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR / BUILD_ERROR / VERIFICATION_ERROR).
- `no_fix_only`: declared-abstention cases (status NO_FIX).
