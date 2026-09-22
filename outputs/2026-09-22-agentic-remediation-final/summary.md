# Agentic Remediation Evaluation - Final Merged Baseline

- **Artifact Directory**: `outputs/2026-09-22-agentic-remediation-final/`
- **Commit**: `3fabbea84d0bcfe89af8380c1136e8f64fa3f633`
- **Model**: `qwen/qwen3.8-27b` (local MLX / LM Studio)
- **Evaluation Mode**: `agentic` (3-gate verification: JDT compilation, regression tests, policy recheck)
- **Total Evaluated Cases**: `84`
- **Correct Outcome Rate**: `73.81%` (62 / 84)

## Headline Outcome Breakdown

| Outcome Classification | Count | Percentage | Description |
| :--- | :--- | :--- | :--- |
| **Fixed Vulnerabilities (Correct Fix)** | `60` | `71.4%` | True positive vulnerability correctly remediated and passed 3 gates |
| **Correct Abstentions** | `2` | `2.4%` | Benign testcase (false finding) where agent correctly refused remediation |
| **False Fixes** | `10` | `11.9%` | Benign testcase where remediation was applied despite no real vulnerability |
| **Missed Fixes** | `0` | `0.0%` | True vulnerability where agent incorrectly refused remediation |
| **Inconclusive / Timeout / Max Turns** | `12` | `14.3%` | Agent exceeded maximum allowed turns or encountered scoped config barrier |

## Category Breakdown

| Category | Total Cases | True Positives | Benign (FP) | 3-Gate Success | Refused | Max Turns / Inconclusive | Build Pass Rate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Command Injection (CWE-78) | 10 | 8 | 2 | 6 | 0 | 4 | 70.0% (7/10) |
| Crypto (CWE-327) | 12 | 12 | 0 | 9 | 0 | 3 | 100.0% (12/12) |
| Hash (CWE-328) | 10 | 10 | 0 | 9 | 0 | 1 | 100.0% (10/10) |
| LDAP Injection (CWE-90) | 10 | 7 | 3 | 10 | 0 | 0 | 100.0% (10/10) |
| Path Traversal (CWE-22) | 11 | 6 | 5 | 11 | 0 | 0 | 100.0% (11/11) |
| Randomness (CWE-330) | 11 | 8 | 3 | 8 | 1 | 2 | 90.9% (10/11) |
| SQL Injection (CWE-89) | 12 | 9 | 3 | 10 | 0 | 2 | 100.0% (12/12) |
| XPath Injection (CWE-643) | 8 | 7 | 1 | 7 | 1 | 0 | 87.5% (7/8) |
