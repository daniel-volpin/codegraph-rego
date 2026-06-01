# Benchmark Context

## What This Is

CodeGraph is a benchmark-backed JVM security/compliance framework. The primary proof surface is OWASP Benchmark; realistic apps are secondary workflow case studies only.

## Current Benchmark Scope

- `CWE-22` -> `ISO-A.8-PATH-TRAVERSAL`
- `CWE-78` -> `ISO-A.8-CMD-INJECTION`
- `CWE-89` -> `ISO-A.8-SQL-INJECTION`
- `CWE-90` -> `ISO-A.8-LDAP-INJECTION`
- `CWE-327` -> `ISO-A.10-WEAK-CRYPTO`
- `CWE-328` -> `ISO-A.10-WEAK-HASH`
- `CWE-330` -> `ISO-A.10-WEAK-RANDOM`
- `CWE-643` -> `ISO-A.8-XPATH-INJECTION`

Remediation support tiers:

- `full`: weak hash, weak random
- `guarded`: weak crypto
- `manual`: injection families plus access-control/logging rules

## Repo-Tracked Evidence

- Detection: `outputs/thesis_final_detection_full_v2/`
  - `TP=222`, `FP=11`, `FN=11`
  - `Precision=Recall=F1=0.9528`
  - Same headline numbers as the older v1 run, but with provenance and CIs
- Explanation: `outputs/thesis_final_explanation_full_v2/`
  - `Citation@TP (ctx)=1.000` (`222/222`)
  - `Citation@TP (no-ctx)=0.009` (`2/222`)
  - `Citation@FP (ctx)=1.000` (`9/9`)
  - `Citation@FP (no-ctx)=0.000` (`0/9`)
- Remediation baseline: `outputs/thesis_final_remediation_v2/`
  - `25/25` fully verified
  - `Brier=0.0057`, `ECE=0.0696`

## Follow-Up Evidence

- Provenance-backed remediation rerun: `outputs/thesis_final_remediation_v3/`
  - `18/25 = 0.72`
- Strongest provenance-backed remediation anchor: `outputs/thesis_final_remediation_v4/`
  - `24/25 = 0.96`

If a minimum remediation threshold of `70%` is required, use:

- primary anchor: `24/25` remediation v4 artifact
- fallback anchor: `18/25` remediation v3 artifact

## Run And Citation Guidance

- Prefer canonical configs under `configs/benchmark/`.
- Use `REPRODUCIBILITY.md` for exact commands and environment setup.
- Cite output files under `outputs/`, not prose summaries.
- Distinguish:
  - thesis baseline artifacts
  - provenance-backed follow-up reruns
  - historical reference runs

## Current Bounded Risks

- Detection still has concentrated precision noise in command/path/SQL families.
- Weak crypto remains guarded and can legitimately produce `NO_FIX`.
- Remediation is still model-sensitive even with the bounded structured contract.
- Real-world apps validate workflow breadth more than remediation coverage.

## What Not To Overclaim

- Do not describe benchmark-focused heuristics as full taint analysis.
- Do not describe remediation as open-ended production autonomous repair.
- Do not treat sample-app behavior as the primary scientific evidence surface.
- Treat `Citation@FP (no-ctx)=0.000` as the expected ablation floor, not a failure.
