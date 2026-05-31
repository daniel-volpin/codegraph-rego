# Benchmark Latest

Repo-tracked benchmark evidence for the current thesis baseline set.

- Detection and explanation source the 2026-05-03 defensibility reruns.
- Remediation sources the 2026-03-22 thesis-final baseline.

## Detection Full

Source: `outputs/thesis_final_detection_full_v2/`
Config: `multicat_full.json` · seed=7 · 60 cases/category · 454 total cases

- Overall:
  - `TP=222`
  - `FP=11`
  - `FN=11`
  - `Precision=0.9528`
  - `Recall=0.9528`
  - `F1=0.9528`
- Per-category results:
  - Crypto (CWE-327): `TP=27`, `FP=0`, `FN=4`, `P=1.000`, `R=0.871`, `F1=0.931`
  - Hash (CWE-328): `TP=22`, `FP=0`, `FN=7`, `P=1.000`, `R=0.759`, `F1=0.863`
  - Randomness (CWE-330): `TP=32`, `FP=0`, `FN=0`, `P=1.000`, `R=1.000`, `F1=1.000`
  - SQL Injection (CWE-89): `TP=35`, `FP=2`, `FN=0`, `P=0.946`, `R=1.000`, `F1=0.972`
  - Path Traversal (CWE-22): `TP=29`, `FP=2`, `FN=0`, `P=0.935`, `R=1.000`, `F1=0.967`
  - Command Injection (CWE-78): `TP=35`, `FP=3`, `FN=0`, `P=0.921`, `R=1.000`, `F1=0.959`
  - LDAP Injection (CWE-90): `TP=27`, `FP=1`, `FN=0`, `P=0.964`, `R=1.000`, `F1=0.982`
  - XPath Injection (CWE-643): `TP=15`, `FP=1`, `FN=0`, `P=0.938`, `R=1.000`, `F1=0.968`
- Zero false positives on crypto, hash, and randomness categories.
- All five injection categories achieve perfect recall (R=1.000).
- Remaining FN concentrated in hash (7) and crypto (4).

## Explanation Full

Source: `outputs/thesis_final_explanation_full_v2/`
Config: `multicat_full.json` · seed=7 · `evidence_mode=lean` · `llm_max_tokens_eval=192` · `LLM_CONCURRENCY=1`

- TP cohort: `222`
- FP cohort: `9`
- Overall `Citation@TP (ctx)`: `1.000` (222/222)
- Overall `Citation@TP (no-ctx)`: `0.009` (2/222)
- Overall `Citation@FP (ctx)`: `1.000` (9/9)
- Overall `Citation@FP (no-ctx)`: `0.000` (0/9)
- TP-context is perfect across all 8 categories.
- FP-context is perfect across the 9 evaluated false positives.
- `Citation@FP (no-ctx)=0.000` remains the expected ablation floor: without evidence context the LLM cannot ground citations.

## Remediation Supported Medium

Source: `outputs/thesis_final_remediation_v2/`
Config: `remediation_supported_medium.json` · seed=42 · 20 cases/category · 3 categories · `--sample-size 60` · `mode=dry_run`

- Attempted: `25`
- Fix Success Rate: `1.000` (25/25)
- Build Success Rate: `1.000` (25/25)
- `final_status_counts`: `{"OK": 25}`
- Confidence calibration Brier score: `0.0057`
- Confidence calibration ECE: `0.0696`
- Confidence gate active (PR #81 on `main`)

Note: 25 attempted vs. 17 in the prior reference run reflects improved detection recall on `main`. All 25 succeeded.

## Authoritative vs Reference Runs

Cite the following as the thesis-final authoritative evidence:
- detection: `outputs/thesis_final_detection_full_v2/`
- explanation: `outputs/thesis_final_explanation_full_v2/`
- remediation: `outputs/thesis_final_remediation_v2/`

Preserve but do not cite as primary evidence:
- `outputs/detection_calibration_path_precision_v4/` — pre-taint intermediate run (F1=0.798); useful for showing improvement trajectory
- `outputs/repro_supported_medium_branch_benchmarktest01017_fix/` — pre-confidence-gate remediation reference (17/17)
- `outputs/final_full_remediation_current_main/` — 10-case regression/reference run

## Real-World Case Studies

Source: `outputs/reporting/baseline_freeze_v0_2_0/report.md`

- `spring_petclinic`: ingest, search, policy evaluation, and explanation validated; no bounded remediation category surfaced
- `gs_securing_web`: ingest and search validated; no policy findings surfaced (acceptable transferability outcome)

Case studies validate workflow breadth. They are not the primary benchmark evidence surface.
