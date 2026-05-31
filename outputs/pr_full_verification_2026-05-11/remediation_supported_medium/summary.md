# Remediation Summary

- Status: `completed`
- Attempted: `25` / `25`
- Structured valid: `22`
- Replacement applied: `21`
- Policy fixed: `19`
- Build attempted: `21`
- Build success: `19`
- Fully verified success rate: `0.76`
- Build success rate: `0.9048`

## Final Status Counts
- `OK`: `19`
- `NO_FIX`: `1`
- `GENERATION_ERROR`: `3`
- `REPLACEMENT_ERROR`: `0`
- `BUILD_ERROR`: `2`
- `VERIFICATION_ERROR`: `0`

## Recent Cases
- `BenchmarkTest01323_ISO-A.10-WEAK-CRYPTO_271fb047c1`: `NO_FIX` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest01318_ISO-A.10-WEAK-CRYPTO_c200b94a58`: `OK` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest00020_ISO-A.10-WEAK-CRYPTO_aa3e269e43`: `OK` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest01480_ISO-A.10-WEAK-CRYPTO_1b327ab301`: `GENERATION_ERROR` (ISO-A.10-WEAK-CRYPTO)
- `BenchmarkTest01017_ISO-A.10-WEAK-CRYPTO_b8731a5f11`: `GENERATION_ERROR` (ISO-A.10-WEAK-CRYPTO)

## Confidence Calibration
- `Brier`: `0.092872`
- `ECE`: `0.100345`
- Full reliability bins are in `remediation_calibration.json`.

Interpretation:
- `Policy fixed` means the target rule was removed and no new violations were introduced.
- `Build success` means compilation was attempted and passed.
- `Fully verified` is the current remediation benchmark success metric.