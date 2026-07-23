# Canonical Benchmark Configs

- `policy_registry.json` - canonical thesis policy registry for CWE, Rego, control, remediation-tier, and framework-demo mapping
- `baseline.json` – narrow baseline coverage (`crypto-md5`, `hash-md5`)
- `smoke_mixed.json` – small pinned smoke run for fast detection checks
- `multicat_medium.json` – medium sampled thesis evaluation set
- `multicat_full.json` – full thesis multicategory evaluation set
- `multicat_all_available.json` – uncapped variant of the multicategory set
- `multicat_full_debug_fn.json` – full multicategory set with `debug_fn_analysis` enabled for FN triage
- `expanded_eval.json` – broader framework coverage across eight benchmark families
- `framework_demo.json` – curated benchmark demo pack aligned to the UI demo focus mode
- `remediation_hash_smoke.json` – targeted remediation smoke for weak-hash fix-and-verify
- `remediation_bounded_smoke.json` – targeted remediation smoke across full and guarded remediation tiers
- `remediation_supported_medium.json` – thesis-final supported remediation set (full + guarded tiers)
- `sql_fn_recovery_smoke.json` – pinned SQL-injection testcases with `debug_fn_analysis` for FN-recovery checks
- `lexical_noise_v1.json` – LexicalNoiseJava v1 manifest for the F10 lexical-noise eval (`run_lexical_noise_eval.py`)

These files are the supported defaults for documentation, scripts, and reruns.
