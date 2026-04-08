# 02 — Authoritative Benchmark Results

## Provenance

All results produced on `main` on **2026-03-22**.
Benchmark: **OWASP Benchmark v1.2** (2,740 total Java test cases).

---

## Detection

**Artifact:** `outputs/thesis_final_detection_full/`

**Files:**
- `metrics.json` — full machine-readable results with per-case detail
- `metrics.csv` — summary CSV
- `table.md` — thesis-ready Markdown table

**Config:** `configs/benchmark/multicat_full.json`
- 8 categories, 60 cases/category (except LDAP: 59, XPath: 35)
- Seed: 7
- Total evaluated: **454 cases**

**Command:**
```bash
python run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_detection_full \
  --reset-neo4j
```

### Results (verified from `metrics.json` and `table.md`)

| Category | CWE | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| Weak Crypto | 327 | 27 | 0 | 4 | 1.000 | 0.871 | 0.931 |
| Weak Hash | 328 | 22 | 0 | 7 | 1.000 | 0.759 | 0.863 |
| Weak Random | 330 | 32 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| SQL Injection | 89 | 35 | 2 | 0 | 0.946 | 1.000 | 0.972 |
| Path Traversal | 22 | 29 | 2 | 0 | 0.936 | 1.000 | 0.967 |
| Command Injection | 78 | 35 | 3 | 0 | 0.921 | 1.000 | 0.959 |
| LDAP Injection | 90 | 27 | 1 | 0 | 0.964 | 1.000 | 0.982 |
| XPath Injection | 643 | 15 | 1 | 0 | 0.938 | 1.000 | 0.968 |
| **Overall** | | **222** | **11** | **11** | **0.953** | **0.953** | **0.953** |

### Notable patterns
- Zero false positives on all three crypto/hash/random categories.
- Perfect recall (1.000) on all five injection categories.
- FN concentrated in weak hash (7) and weak crypto (4) — these are cases where the pattern-matching heuristics do not capture non-standard API usage.
- FP concentrated in command injection (3), path traversal (2), SQL injection (2) — these arise from benchmark-safe transforms/helpers that the bounded analysis cannot fully distinguish.

### How the evaluated subset is determined
- Ground truth is loaded from `BenchmarkJava/expectedresults-1.2.csv` (OWASP-provided).
- `codegraph/evaluation/benchmark.py` selects cases by category, applies `max_cases_per_category` sampling with the configured seed.
- Categories map to CWEs via `configs/benchmark/policy_registry.json`.
- Each case has a known ground-truth `real_vulnerability` boolean.
- TP/FP/FN are computed by comparing detected violations against ground truth per case.

### How metrics are computed
- TP: case is truly vulnerable AND policy detected a violation.
- FP: case is NOT vulnerable BUT policy detected a violation.
- FN: case IS vulnerable BUT policy did NOT detect a violation.
- Precision = TP / (TP + FP), Recall = TP / (TP + FN), F1 = harmonic mean.
- Computed in `codegraph/evaluation/pipeline.py`.

---

## Explanation

**Artifact:** `outputs/thesis_final_explanation_full/`

**Files:**
- `citation_metrics.json` — full machine-readable results
- `citation_metrics.csv` — summary CSV
- `table.md` — thesis-ready Markdown table
- `explanation_samples.jsonl` — 24 sample explanation records

**Config:** Same `multicat_full.json` as detection.
- Evidence mode: `lean`
- LLM max tokens: 192
- LLM concurrency: 1
- Model: `qwen3.5-9b-mlx` (local, via LM Studio)

**Command:**
```bash
LLM_CONCURRENCY=1 python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_explanation_full \
  --evidence-mode lean --llm-max-tokens-eval 192 --reset-neo4j
```

### Results (verified from `citation_metrics.json` and `table.md`)

| Category | CWE | TP Count | Citation@Context | Citation@NoContext |
|---|---|---|---|---|
| Weak Crypto | 327 | 27 | 1.000 | 0.000 |
| Weak Hash | 328 | 22 | 1.000 | 0.000 |
| Weak Random | 330 | 32 | 1.000 | 0.000 |
| SQL Injection | 89 | 35 | 1.000 | 0.000 |
| Path Traversal | 22 | 29 | 1.000 | 0.000 |
| Command Injection | 78 | 35 | 1.000 | 0.000 |
| LDAP Injection | 90 | 27 | 1.000 | 0.000 |
| XPath Injection | 643 | 15 | 0.933 | 0.000 |
| **Overall** | | **222** | **0.9955** | **0.000** |

### What these metrics mean
- **Citation@Context**: fraction of true-positive explanations where the LLM produced grounded citations referencing specific evidence fields. 221/222 succeeded.
- **Citation@NoContext**: ablation control — same LLM without evidence context. 0/222 produced citations, confirming that the structured evidence is load-bearing.
- XPath scored 14/15 (0.933) — 1 case did not produce a grounded citation. All other categories achieved 1.000.

### Why XPath may differ
- XPath has the smallest sample (15 TPs from 35 available cases — no sampling, all evaluated).
- The XPath evidence patterns may be less familiar to the explanation model.
- A single non-citation in 15 cases produces the observed 0.933.

---

## Remediation

**Artifact:** `outputs/thesis_final_remediation_v2/`

**Files:**
- `remediation_metrics.json` — full machine-readable results with per-case detail
- `remediation_metrics.csv` — summary CSV
- `table.md` — thesis-ready Markdown table
- `summary.md` — human-readable summary
- `confidence_calibration.json` — Brier score, ECE, reliability bins, risk-coverage curve
- `results.jsonl` — per-case streaming results
- `cases/` — per-case artifact directories (25 cases)

**Config:** `configs/benchmark/remediation_supported_medium.json`
- 3 categories: weak hash, weak random, weak crypto
- 20 cases/category
- Seed: 42
- `--sample-size 60`
- Mode: `dry_run`
- Max attempts: 2
- Model: `qwen/qwen3-coder-30b` (local, via LM Studio)

**Command:**
```bash
python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_remediation_v2 \
  --sample-size 60 --reset-neo4j
```

### Results (verified from `remediation_metrics.json`, `confidence_calibration.json`, `summary.md`)

| Metric | Value |
|---|---|
| Cases attempted | 25 |
| Structured valid | 25 |
| Replacement applied | 25 |
| Policy fixed (target rule removed, no new violations) | 25 |
| Build attempted | 25 |
| Build success | 25 |
| Fix+build success rate | **1.000** |
| Final status: OK | 25 |
| Final status: NO_FIX | 0 |
| Final status: GENERATION_ERROR | 0 |
| Final status: BUILD_ERROR | 0 |
| Final status: VERIFICATION_ERROR | 0 |

### Confidence Calibration (from `confidence_calibration.json`)

| Metric | Value |
|---|---|
| Brier score | **0.0057** |
| ECE | **0.0696** |
| Reliability bin [0.8–0.9] | 9 cases, avg conf 0.891, empirical success 1.0, gap 0.109 |
| Reliability bin [0.9–1.0] | 16 cases, avg conf 0.953, empirical success 1.0, gap 0.047 |

**Note on Brier/ECE discrepancy:** `summary.md` shows slightly different numbers (Brier=0.0119, ECE=0.1091) because `summary.md` is a live-progress artifact written during the run using per-case streaming data. The authoritative numbers are in `confidence_calibration.json` and the matching field in `remediation_metrics.json`, which are computed post-hoc over all completed cases. **Use the `confidence_calibration.json` numbers for thesis claims.**

### Why 25 cases from a 60-case sample?
- The config selects up to 20 cases per category from hash, random, and crypto.
- The evaluation pipeline first runs detection. Only detected true positives are eligible for remediation.
- 25 of the selected cases were detected as true positives and thus attempted.
- All 25 succeeded.

### Remediation scope
| Tier | Categories | Behavior |
|---|---|---|
| `full` | ISO-A.10-WEAK-HASH, ISO-A.10-WEAK-RANDOM | Full auto-fix support. |
| `guarded` | ISO-A.10-WEAK-CRYPTO | Auto-fix for explicit literal subcases; `NO_FIX` is a valid safe outcome. |
| `manual` | All 5 injection families + access + logging | Explanation only; LLM is never called for remediation. |

---

## Historical / Reference Runs (do NOT cite as primary)

| Run | Directory | Notes |
|---|---|---|
| Pre-taint detection | `outputs/detection_calibration_path_precision_v4/` | F1=0.798, shows improvement trajectory |
| Pre-confidence remediation | `outputs/repro_supported_medium_branch_benchmarktest01017_fix/` | 17/17 success, no confidence gate |
| 10-case regression | `outputs/final_full_remediation_current_main/` | Regression reference |

---

## Reproducibility

All evaluations are reproducible from the repo:
1. Commands documented in `REPRODUCIBILITY.md` and `.opencode/project/runbook.md`.
2. Configs are versioned under `configs/benchmark/`.
3. Ground truth comes from OWASP Benchmark v1.2 (`expectedresults-1.2.csv`).
4. `--reset-neo4j` ensures clean graph state.
5. Detection is deterministic (no LLM). Explanation and remediation depend on local LLM model behavior.
