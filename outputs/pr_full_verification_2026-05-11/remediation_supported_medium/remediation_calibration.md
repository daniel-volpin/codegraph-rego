# Remediation Calibration

Headline numbers below are computed over the **full** population (every result that carries a confidence score, including `NO_FIX` abstentions). The per-population breakdown distinguishes calibrated success probability from knew-when-to-abstain behavior.

- Cases with confidence: `22`
- Missing confidence: `3`
- Label: `fully_verified`
- Label definition: `fully_verified := policy_fixed is true and build_success is true`
- Positive labels: `19`
- Negative labels: `3`
- Brier score (full): `0.092872`
- ECE (full): `0.100345`

## Reliability Bins (full population)

| Bin | Count | Avg confidence | Empirical success | Gap |
| --- | --- | --- | --- | --- |
| 0.3-0.4 | 1 | 0.3318 | 0.0 | 0.3318 |
| 0.8-0.9 | 5 | 0.8732 | 1.0 | 0.1268 |
| 0.9-1.0 | 16 | 0.9526 | 0.875 | 0.0776 |

## Calibration by Population

| Population | Count | Positive | Negative | Brier | ECE |
| --- | --- | --- | --- | --- | --- |
| full | 22 | 19 | 3 | 0.092872 | 0.100345 |
| attempted_only | 21 | 19 | 2 | 0.092052 | 0.089324 |
| no_fix_only | 1 | 0 | 1 | 0.110091 | 0.3318 |

Population definitions:
- `full`: every result with a confidence score (legacy headline).
- `attempted_only`: results where the system attempted to apply a remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR / BUILD_ERROR / VERIFICATION_ERROR).
- `no_fix_only`: declared-abstention cases (status NO_FIX).
