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

- Detection figures are not restated here. `docs/thesis_context.md` owns the
  thesis-final figure, its bootstrap intervals, and why it does not reproduce; `REPRODUCIBILITY.md` owns the current measured figure beside the command that produces it. Read those before citing a detection number. Artifacts: `outputs/thesis_final_detection_full_v2/` (qualified) and `outputs/2026-09-14-detection-full/detection_composed/` (current).
- Explanation: `outputs/thesis_final_explanation_full_v2/`
  - `Citation@TP (ctx)=1.000` (`222/222`)
  - `Citation@TP (no-ctx)=0.009` (`2/222`)
  - `Citation@FP (ctx)=1.000` (`9/9`)
  - `Citation@FP (no-ctx)=0.000` (`0/9`)
- Remediation per-case evidence: `outputs/thesis_final_remediation_v2/` (25 case directories and `results.jsonl`; no `provenance.json`, so cite the v4 anchor below when a recorded commit is needed)
  - `25/25` fully verified
  - `Brier=0.0057`, `ECE=0.0696` (per `remediation_metrics.json` / `confidence_calibration.json`; the prose block in that run's `summary.md` diverges and is not the canonical carrier)

## Follow-Up Evidence

- Provenance-backed bounded remediation rerun: `outputs/thesis_final_remediation_v3/`
  - `18/25 = 0.72`
- Strongest provenance-backed bounded remediation anchor: `outputs/thesis_final_remediation_v4/`
  - `25/25 = 1.00`
  - `Brier=0.0057`, `ECE=0.0696`
- Autonomous agentic remediation baseline (multi-turn, 8 categories): `outputs/2026-09-22-agentic-remediation-final/`
  - `60/84` correct fixes, `2/84` correct abstentions, `0` missed fixes (`73.81%` correct outcome rate)
  - `qwen/qwen3.8-27b` via local MLX / LM Studio under 3-gate verification (JDT compile, regression tests, OPA/OpenGrep policy)

## Canonical Citation Mapping for Thesis

| Thesis Section | Empirical Evaluation Focus | Primary Canonical Artifact | Key Metrics |
| :--- | :--- | :--- | :--- |
| **Detection (RQ1)** | OPA + OpenGrep policy compliance checks | `outputs/2026-09-14-detection-full/detection_composed/` | Per-category PRF & union any-rule metrics |
| **Explanation (RQ2)** | Graph-grounded vs context-free citations | `outputs/thesis_final_explanation_full_v2/` | `Citation@TP = 1.000` vs `0.009` |
| **Bounded Remediation (RQ3a)** | Single-method bounded repair with calibration | `outputs/thesis_final_remediation_v4/` | `25/25 = 100%`, `Brier = 0.0057`, `ECE = 0.0696` |
| **Agentic Remediation (RQ3b)** | Autonomous multi-turn 3-gate refactoring | `outputs/2026-09-22-agentic-remediation-final/` | `73.81%` correct outcome rate (60 fixes, 0 missed) |

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
