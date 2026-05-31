# LexicalNoiseJava — Detection Summary (lexical_noise_v1, n=30)

| Method | TP | FP | TN | FN | Precision | Recall | F1 | P CI (95%) | R CI (95%) | F1 CI (95%) |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|
| pre_f10 | 3 | 15 | 10 | 2 | 0.167 | 0.600 | 0.261 | [0.000, 0.357] | [0.000, 1.000] | [0.000, 0.500] |
| post_f10 | 3 | 7 | 18 | 2 | 0.300 | 0.600 | 0.400 | [0.000, 0.625] | [0.000, 1.000] | [0.000, 0.700] |
| semgrep | 5 | 0 | 25 | 0 | 1.000 | 1.000 | 1.000 | [1.000, 1.000] | [1.000, 1.000] | [1.000, 1.000] |

## Effect of F10 (post_f10 vs pre_f10)

Per-case paired analysis. McNemar's exact binomial test is reported for ΔFP and Δ(any) — for n_disagreements = 0 the test is undefined and the cell reads `n/a (b=c=0)`. Δ rates are bootstrapped on the *paired* sample.

| Scope | b (improvements) | c (regressions) | McNemar p (exact) | ΔFPR (post − pre) | ΔFPR 95% CI | ΔFNR (post − pre) | ΔFNR 95% CI |
|---|---:|---:|---|---:|---|---:|---|
| overall | 8 | 0 | 0.0078 | -0.320 | [-0.500, -0.154] | +0.000 | [+0.000, +0.000] |
| fp_class | 8 | 0 | 0.0078 | -0.320 | [-0.500, -0.154] | +0.000 | [+0.000, +0.000] |
| stratum:block_comment | 4 | 0 | 0.1250 | -0.800 | [-1.000, -0.400] | +0.000 | [+0.000, +0.000] |
| stratum:char_literal | 0 | 0 | n/a (b=c=0) | +0.000 | [+0.000, +0.000] | +0.000 | [+0.000, +0.000] |
| stratum:line_comment | 4 | 0 | 0.1250 | -0.800 | [-1.000, -0.400] | +0.000 | [+0.000, +0.000] |
| stratum:string_literal | 0 | 0 | n/a (b=c=0) | +0.000 | [+0.000, +0.000] | +0.000 | [+0.000, +0.000] |
| stratum:text_block | 0 | 0 | n/a (b=c=0) | +0.000 | [+0.000, +0.000] | +0.000 | [+0.000, +0.000] |

## Per-stratum decomposition (by fp_source)

Diagnostic breakdown of F10's effect by lexical-noise source type. Single-stratum CIs are wide at n≈5-6 — read the *pattern* (comment strata cleaned, literal / text-block strata unchanged), not the point estimates.

| Stratum | n | n_pos | n_neg | Method | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|
| block_comment | 6 | 1 | 5 | pre_f10 | 0 | 4 | 1 | 1 | 0.000 | 0.000 | 0.000 |
| block_comment | 6 | 1 | 5 | post_f10 | 0 | 0 | 5 | 1 | 0.000 | 0.000 | 0.000 |
| block_comment | 6 | 1 | 5 | semgrep | 1 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 |
| char_literal | 6 | 1 | 5 | pre_f10 | 0 | 0 | 5 | 1 | 0.000 | 0.000 | 0.000 |
| char_literal | 6 | 1 | 5 | post_f10 | 0 | 0 | 5 | 1 | 0.000 | 0.000 | 0.000 |
| char_literal | 6 | 1 | 5 | semgrep | 1 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 |
| line_comment | 6 | 1 | 5 | pre_f10 | 1 | 4 | 1 | 0 | 0.200 | 1.000 | 0.333 |
| line_comment | 6 | 1 | 5 | post_f10 | 1 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 |
| line_comment | 6 | 1 | 5 | semgrep | 1 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 |
| string_literal | 6 | 1 | 5 | pre_f10 | 1 | 3 | 2 | 0 | 0.250 | 1.000 | 0.400 |
| string_literal | 6 | 1 | 5 | post_f10 | 1 | 3 | 2 | 0 | 0.250 | 1.000 | 0.400 |
| string_literal | 6 | 1 | 5 | semgrep | 1 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 |
| text_block | 6 | 1 | 5 | pre_f10 | 1 | 4 | 1 | 0 | 0.200 | 1.000 | 0.333 |
| text_block | 6 | 1 | 5 | post_f10 | 1 | 4 | 1 | 0 | 0.200 | 1.000 | 0.333 |
| text_block | 6 | 1 | 5 | semgrep | 1 | 0 | 5 | 0 | 1.000 | 1.000 | 1.000 |

## Per-case verdicts

| Case | fp_source | expected | target | pre_f10 | post_f10 | semgrep |
|---|---|---|---|---|---|---|
| L01 | line_comment | negative | ISO-A.10-WEAK-HASH | fire | — | — |
| L02 | line_comment | negative | ISO-A.8-SQL-INJECTION | fire | — | — |
| L03 | line_comment | negative | ISO-A.10-WEAK-RANDOM | — | — | — |
| L04 | line_comment | negative | ISO-A.8-CMD-INJECTION | fire | — | — |
| L05 | line_comment | negative | ISO-A.8-XPATH-INJECTION | fire | — | — |
| L06 | line_comment | positive | ISO-A.10-WEAK-HASH | fire | fire | fire |
| L07 | block_comment | negative | ISO-A.10-WEAK-HASH | fire | — | — |
| L08 | block_comment | negative | ISO-A.8-SQL-INJECTION | fire | — | — |
| L09 | block_comment | negative | ISO-A.8-PATH-TRAVERSAL | — | — | — |
| L10 | block_comment | negative | ISO-A.8-LDAP-INJECTION | fire | — | — |
| L11 | block_comment | negative | ISO-A.10-WEAK-CRYPTO | fire | — | — |
| L12 | block_comment | positive | ISO-A.8-SQL-INJECTION | — | — | fire |
| L13 | string_literal | negative | ISO-A.10-WEAK-HASH | — | — | — |
| L14 | string_literal | negative | ISO-A.8-SQL-INJECTION | fire | fire | — |
| L15 | string_literal | negative | ISO-A.10-WEAK-RANDOM | — | — | — |
| L16 | string_literal | negative | ISO-A.8-CMD-INJECTION | fire | fire | — |
| L17 | string_literal | negative | ISO-A.8-PATH-TRAVERSAL | fire | fire | — |
| L18 | string_literal | positive | ISO-A.10-WEAK-RANDOM | fire | fire | fire |
| L19 | char_literal | negative | ISO-A.10-WEAK-HASH | — | — | — |
| L20 | char_literal | negative | ISO-A.8-PATH-TRAVERSAL | — | — | — |
| L21 | char_literal | negative | ISO-A.10-WEAK-CRYPTO | — | — | — |
| L22 | char_literal | negative | ISO-A.8-SQL-INJECTION | — | — | — |
| L23 | char_literal | negative | ISO-A.8-SQL-INJECTION | — | — | — |
| L24 | char_literal | positive | ISO-A.8-PATH-TRAVERSAL | — | — | fire |
| L25 | text_block | negative | ISO-A.8-SQL-INJECTION | fire | fire | — |
| L26 | text_block | negative | ISO-A.10-WEAK-HASH | — | — | — |
| L27 | text_block | negative | ISO-A.8-XPATH-INJECTION | fire | fire | — |
| L28 | text_block | negative | ISO-A.8-LDAP-INJECTION | fire | fire | — |
| L29 | text_block | negative | ISO-A.8-CMD-INJECTION | fire | fire | — |
| L30 | text_block | positive | ISO-A.8-XPATH-INJECTION | fire | fire | fire |
