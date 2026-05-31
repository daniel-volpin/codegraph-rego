# Remediation Summary

- Status: `completed`
- Attempted: `25` / `25`
- Structured valid: `21`
- Replacement applied: `20`
- Policy fixed: `18`
- Build attempted: `20`
- Build success: `18`
- Fully verified success rate: `0.72`
- Build success rate: `0.9`

## Final Status Counts
- `OK`: `18`
- `NO_FIX`: `1`
- `GENERATION_ERROR`: `4`
- `REPLACEMENT_ERROR`: `0`
- `BUILD_ERROR`: `2`
- `VERIFICATION_ERROR`: `0`

## Recent Cases
- `BenchmarkTest01323_ISO-A.10-WEAK-CRYPTO_b99c67cb12`: `NO_FIX` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest02017_ISO-A.10-WEAK-CRYPTO_c7b784b1df`: `OK` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest01318_ISO-A.10-WEAK-CRYPTO_981a6c8fc6`: `GENERATION_ERROR` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest00521_ISO-A.10-WEAK-CRYPTO_e6864c6526`: `OK` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest01017_ISO-A.10-WEAK-CRYPTO_7e051c5d77`: `OK` (ISO-A.10-WEAK-CRYPTO)

## Confidence Calibration
- `Brier`: `0.095431`
- `ECE`: `0.095705`
- Full reliability bins are in `remediation_calibration.json`.

Interpretation:
- `Policy fixed` means the target rule was removed and no new violations were introduced.
- `Build success` means compilation was attempted and passed.
- `Fully verified` is the current remediation benchmark success metric.