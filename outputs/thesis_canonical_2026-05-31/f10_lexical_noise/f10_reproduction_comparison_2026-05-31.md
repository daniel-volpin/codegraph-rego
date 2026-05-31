# F10 Reproduction Comparison

Keep the LexicalNoiseJava and OWASP point metrics. Replace the LexicalNoiseJava 95% CI if citing the regenerated artifact: delta FPR CI is [-0.500, -0.154] with seed 42 and 2000 bootstrap resamples, not [-0.478, -0.154].

## LexicalNoiseJava

| Method | TP | FP | TN | FN | P | R | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| pre_f10 | 3 | 15 | 10 | 2 | 0.167 | 0.6 | 0.261 |
| post_f10 | 3 | 7 | 18 | 2 | 0.3 | 0.6 | 0.4 |
| semgrep | 5 | 0 | 25 | 0 | 1.0 | 1.0 | 1.0 |

- McNemar p: 0.0078125
- Delta FPR: -0.31999999999999995
- Delta FPR 95% CI: [-0.5, -0.15384615384615385]

## OWASP File Level

| Method | TP | FP | TN | FN | P | R | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| pre_f10 | 185 | 24 | 155 | 21 | 0.885 | 0.898 | 0.892 |
| post_f10 | 185 | 24 | 155 | 21 | 0.885 | 0.898 | 0.892 |

- Zero per-case deltas: True
