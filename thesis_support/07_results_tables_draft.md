# 07 — Results Tables (Thesis-Ready Draft)

All numbers verified against authoritative artifact files. Ready for direct inclusion in thesis.

---

## Table 1: Detection Results — OWASP Benchmark v1.2

**Source:** `outputs/thesis_final_detection_full/metrics.json`
**Config:** `multicat_full.json` · seed=7 · 60 cases/category · 454 total

| Category | CWE | TP | FP | FN | Precision | Recall | F₁ |
|---|---|---|---|---|---|---|---|
| Weak Crypto | 327 | 27 | 0 | 4 | 1.000 | 0.871 | 0.931 |
| Weak Hash | 328 | 22 | 0 | 7 | 1.000 | 0.759 | 0.863 |
| Weak Random | 330 | 32 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| SQL Injection | 89 | 35 | 2 | 0 | 0.946 | 1.000 | 0.972 |
| Path Traversal | 22 | 29 | 2 | 0 | 0.936 | 1.000 | 0.967 |
| Command Injection | 78 | 35 | 3 | 0 | 0.921 | 1.000 | 0.959 |
| LDAP Injection | 90 | 27 | 1 | 0 | 0.964 | 1.000 | 0.982 |
| XPath Injection | 643 | 15 | 1 | 0 | 0.938 | 1.000 | 0.968 |
| **Overall** | — | **222** | **11** | **11** | **0.953** | **0.953** | **0.953** |

**Caption draft:** Detection results on a stratified sample of 454 cases from OWASP Benchmark v1.2 across 8 CWE categories. Detection is fully deterministic (no LLM involvement). Cryptographic categories achieve zero false positives; all five injection categories achieve perfect recall.

---

## Table 2: Explanation Citation Results

**Source:** `outputs/thesis_final_explanation_full/citation_metrics.json`
**Config:** `multicat_full.json` · evidence_mode=lean · llm_max_tokens=192 · model=qwen3.5-9b-mlx

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
| **Overall** | — | **222** | **0.996** | **0.000** |

**Caption draft:** Citation grounding rates for LLM-generated explanations of 222 true-positive violations. Citation@Context measures the fraction of explanations that produce citations referencing specific evidence fields. Citation@NoContext is the ablation control with evidence withheld, confirming that the structured evidence context is necessary for grounded citation behavior.

---

## Table 3: Remediation Results — Supported Categories

**Source:** `outputs/thesis_final_remediation_v2/remediation_metrics.json`
**Config:** `remediation_supported_medium.json` · seed=42 · mode=dry_run · model=qwen/qwen3-coder-30b

| Metric | Value |
|---|---|
| Cases attempted | 25 |
| Structured valid | 25 (100%) |
| Replacement applied | 25 (100%) |
| Policy fixed | 25 (100%) |
| Build success | 25 (100%) |
| Fix+build+verify rate | 1.000 |
| GENERATION_ERROR | 0 |
| BUILD_ERROR | 0 |
| VERIFICATION_ERROR | 0 |

**Caption draft:** Remediation results on 25 true-positive cases across three supported categories (weak hash, weak random, weak crypto) from OWASP Benchmark v1.2. Each fix is verified through a complete fix-rescan loop: compilation, graph re-ingestion, and policy re-evaluation. All 25 cases achieved successful fix, build, and verification.

---

## Table 4: Remediation Support Matrix

| Tier | ISO Control | CWE | Behavior |
|---|---|---|---|
| Full | ISO-A.10-WEAK-HASH | 328 | Automatic fix supported |
| Full | ISO-A.10-WEAK-RANDOM | 330 | Automatic fix supported |
| Guarded | ISO-A.10-WEAK-CRYPTO | 327 | Fix for explicit literal subcases; safe NO_FIX otherwise |
| Manual | ISO-A.8-SQL-INJECTION | 89 | Explanation only |
| Manual | ISO-A.8-PATH-TRAVERSAL | 22 | Explanation only |
| Manual | ISO-A.8-CMD-INJECTION | 78 | Explanation only |
| Manual | ISO-A.8-LDAP-INJECTION | 90 | Explanation only |
| Manual | ISO-A.8-XPATH-INJECTION | 643 | Explanation only |
| Manual | ISO-A.9.4.1 | — | Explanation only |
| Manual | ISO-A.12.4.1 | — | Explanation only |

**Caption draft:** Remediation support tiers for the 10 policy controls in CodeGraph. Full and guarded categories undergo automatic LLM-assisted remediation with fix-rescan verification. Manual categories receive structured explanations but are not candidates for automatic remediation.

---

## Table 5: Confidence Calibration

**Source:** `outputs/thesis_final_remediation_v2/confidence_calibration.json`

| Metric | Value |
|---|---|
| Brier score | 0.006 |
| ECE | 0.070 |

| Confidence Bin | Count | Avg. Confidence | Empirical Success | Gap |
|---|---|---|---|---|
| [0.80, 0.90) | 9 | 0.891 | 1.000 | 0.109 |
| [0.90, 1.00) | 16 | 0.953 | 1.000 | 0.047 |

**Caption draft:** Confidence calibration for the sigmoid-based remediation confidence model on 25 evaluated cases. Brier score measures the mean squared error between predicted confidence and actual outcome (lower is better). ECE measures the expected calibration error across reliability bins.

---

## Table 6: Evaluation Setup Summary

| Parameter | Detection | Explanation | Remediation |
|---|---|---|---|
| Benchmark | OWASP v1.2 | OWASP v1.2 | OWASP v1.2 |
| Cases evaluated | 454 | 222 (TPs) | 25 (TPs in supported categories) |
| Categories | 8 | 8 | 3 |
| LLM involvement | None | qwen3.5-9b-mlx | qwen/qwen3-coder-30b |
| Deterministic | Yes | No (LLM) | No (LLM) |
| Config | multicat_full.json | multicat_full.json | remediation_supported_medium.json |
| Seed | 7 | 7 | 42 |
| Run date | 2026-03-22 | 2026-03-22 | 2026-03-22 |

**Caption draft:** Evaluation setup for the three benchmark components. Detection is fully deterministic. Explanation and remediation use local LLM models via LM Studio.

---

## Table 7: Detection — Error Analysis Summary

| Category | FP Source | FN Source |
|---|---|---|
| Weak Crypto (CWE-327) | None (FP=0) | 4 cases with non-standard API patterns |
| Weak Hash (CWE-328) | None (FP=0) | 7 cases with non-standard API patterns |
| Weak Random (CWE-330) | None (FP=0) | None (FN=0) |
| SQL Injection (CWE-89) | 2 benchmark-safe transforms | None (FN=0) |
| Path Traversal (CWE-22) | 2 benchmark-safe transforms | None (FN=0) |
| Command Injection (CWE-78) | 3 benchmark-safe helper returns | None (FN=0) |
| LDAP Injection (CWE-90) | 1 transform sensitivity | None (FN=0) |
| XPath Injection (CWE-643) | 1 transform sensitivity | None (FN=0) |

**Caption draft:** Error analysis for detection results. False negatives are concentrated in cryptographic categories where non-standard API usage patterns are not captured by the pattern-based analysis. False positives in injection categories arise from benchmark test cases that apply sanitization transforms which the bounded analysis cannot fully distinguish.

---

## LaTeX-Ready Detection Table

```latex
\begin{table}[htbp]
\centering
\caption{Detection results on OWASP Benchmark v1.2 (454 cases, 8 CWE categories)}
\label{tab:detection-results}
\begin{tabular}{lrrrrrr}
\toprule
\textbf{Category} & \textbf{TP} & \textbf{FP} & \textbf{FN} & \textbf{Precision} & \textbf{Recall} & \textbf{F\textsubscript{1}} \\
\midrule
Weak Crypto (CWE-327)     & 27 & 0 & 4 & 1.000 & 0.871 & 0.931 \\
Weak Hash (CWE-328)       & 22 & 0 & 7 & 1.000 & 0.759 & 0.863 \\
Weak Random (CWE-330)     & 32 & 0 & 0 & 1.000 & 1.000 & 1.000 \\
SQL Injection (CWE-89)    & 35 & 2 & 0 & 0.946 & 1.000 & 0.972 \\
Path Traversal (CWE-22)   & 29 & 2 & 0 & 0.936 & 1.000 & 0.967 \\
Command Inj. (CWE-78)     & 35 & 3 & 0 & 0.921 & 1.000 & 0.959 \\
LDAP Injection (CWE-90)   & 27 & 1 & 0 & 0.964 & 1.000 & 0.982 \\
XPath Injection (CWE-643) & 15 & 1 & 0 & 0.938 & 1.000 & 0.968 \\
\midrule
\textbf{Overall}           & \textbf{222} & \textbf{11} & \textbf{11} & \textbf{0.953} & \textbf{0.953} & \textbf{0.953} \\
\bottomrule
\end{tabular}
\end{table}
```

## LaTeX-Ready Explanation Table

```latex
\begin{table}[htbp]
\centering
\caption{Citation grounding rates for LLM explanations of 222 true-positive violations}
\label{tab:explanation-results}
\begin{tabular}{lrcc}
\toprule
\textbf{Category} & \textbf{TP Count} & \textbf{Citation@Context} & \textbf{Citation@NoContext} \\
\midrule
Weak Crypto (CWE-327)     & 27 & 1.000 & 0.000 \\
Weak Hash (CWE-328)       & 22 & 1.000 & 0.000 \\
Weak Random (CWE-330)     & 32 & 1.000 & 0.000 \\
SQL Injection (CWE-89)    & 35 & 1.000 & 0.000 \\
Path Traversal (CWE-22)   & 29 & 1.000 & 0.000 \\
Command Inj. (CWE-78)     & 35 & 1.000 & 0.000 \\
LDAP Injection (CWE-90)   & 27 & 1.000 & 0.000 \\
XPath Injection (CWE-643) & 15 & 0.933 & 0.000 \\
\midrule
\textbf{Overall}           & \textbf{222} & \textbf{0.996} & \textbf{0.000} \\
\bottomrule
\end{tabular}
\end{table}
```

## LaTeX-Ready Remediation Table

```latex
\begin{table}[htbp]
\centering
\caption{Remediation results on 25 cases across three supported categories}
\label{tab:remediation-results}
\begin{tabular}{lr}
\toprule
\textbf{Metric} & \textbf{Value} \\
\midrule
Cases attempted      & 25 \\
Structured valid     & 25 (100\%) \\
Replacement applied  & 25 (100\%) \\
Policy fixed         & 25 (100\%) \\
Build success        & 25 (100\%) \\
Fix+build+verify     & 1.000 \\
\midrule
Brier score          & 0.006 \\
ECE                  & 0.070 \\
\bottomrule
\end{tabular}
\end{table}
```
