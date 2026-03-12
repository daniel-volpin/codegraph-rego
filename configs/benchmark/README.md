# Canonical Benchmark Configs

- `policy_registry.json` - canonical thesis policy registry for CWE, Rego, control, remediation-tier, and framework-demo mapping
- `baseline.json` – narrow baseline coverage (`crypto-md5`, `hash-md5`)
- `smoke_mixed.json` – small pinned smoke run for fast detection checks
- `multicat_medium.json` – medium sampled thesis evaluation set
- `multicat_full.json` – full thesis multicategory evaluation set
- `expanded_eval.json` – broader framework coverage across eight benchmark families
- `framework_demo.json` – curated benchmark demo pack aligned to the UI demo focus mode
- `remediation_hash_smoke.json` – targeted remediation smoke for weak-hash fix-and-verify
- `remediation_bounded_smoke.json` – targeted remediation smoke across full and guarded remediation tiers

These files are the supported defaults for docs, scripts, and reruns on this branch.
