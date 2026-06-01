# Remediation Calibration

Headline numbers below are computed over the **full** population (every result that carries a confidence score, including `NO_FIX` abstentions). The per-population breakdown distinguishes calibrated success probability from knew-when-to-abstain behavior.

- Cases with confidence: `25`
- Missing confidence: `0`
- Label: `fully_verified`
- Label definition: `fully_verified := policy_fixed is true and build_success is true`
- Positive labels: `25`
- Negative labels: `0`
- Brier score (full): `0.005723`
- ECE (full): `0.069612`

## Reliability Bins (full population)

| Bin | Count | Avg confidence | Empirical success | Gap |
| --- | --- | --- | --- | --- |
| 0.8-0.9 | 9 | 0.8909 | 1.0 | 0.1091 |
| 0.9-1.0 | 16 | 0.9526 | 1.0 | 0.0474 |

## Calibration by Population

| Population | Count | Positive | Negative | Brier | ECE |
| --- | --- | --- | --- | --- | --- |
| full | 25 | 25 | 0 | 0.005723 | 0.069612 |
| attempted_only | 25 | 25 | 0 | 0.005723 | 0.069612 |
| no_fix_only | 0 | n/a | n/a | n/a | n/a |

Population definitions:
- `full`: every result with a confidence score (legacy headline).
- `attempted_only`: results where the system attempted to apply a remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR / BUILD_ERROR / VERIFICATION_ERROR).
- `no_fix_only`: declared-abstention cases (status NO_FIX).
