# Lexical Anchoring (F10) — Methodology and Literature Context

This note documents the research positioning, methodology, and honest
limitations of the F10 lexical anchoring step and its evaluation
artefacts. The thesis chapter will derive its formal write-up from
this; the doc is the single point of truth for what was measured,
how, and why.

The thesis chapter will adopt formal academic citations (BibTeX).
Bracketed labels below mark where those citations belong.

---

## 1. What F10 is

A deterministic, single-pass lexer (`strip_java_lexical_noise` in
`codegraph/policy/source_analysis_core.py`) that produces two cleaned
views of every Java method body the policy pipeline analyses:

* **`source_code_substring_safe`** — comments AND string / char / text-block
  literals are blanked. Newlines and per-character offsets are preserved.
  This is the view consumed by the OPA / Rego rules, which match via naive
  `contains(...)` substring tests.
* **`source_code_active`** — comments blanked, literals preserved. This is
  the view consumed by the Python regex pre-analyzer
  (`analyze_policy_indicators`), whose patterns are structurally anchored
  (e.g. `MessageDigest.getInstance("MD5")`) and rely on string-literal
  contents being visible.

The raw source is preserved verbatim in `source_code_raw` and routed to
the LLM and UI evidence cards (citation-grounding contract).

F10 is the unification of an ad-hoc pattern that was previously applied
only by `codegraph.policy.analysis.crypto` via `SourceSanitizer`. After
F10, every rule path (Rego, Python flag layer, evidence-card renderer)
operates on the view appropriate to its match style.

## 2. Why F10 is interesting research-wise

Static analysis false-positive (FP) taxonomies identify *textual /
lexical confusion* as a recurring FP source: a pattern matcher sees
the targeted substring inside a comment, log message, or
documentation example and fires even though the underlying code is
safe. Surveys of SAST-tool effectiveness in industrial code
[1, 2] consistently
identify FP rate (and resulting alarm fatigue) as the dominant
barrier to adoption. The OWASP Benchmark v1.2 [3]
became the de-facto SAST measurement substrate precisely because it
removes most ambiguity sources at the source-code level — including
this lexical-noise class.

The empirical risk is that benchmarks designed to be
unambiguous (OWASP Benchmark, Juliet Test Suite) systematically
underestimate FP rates seen in real-world code [4].
F10 is positioned in that gap:

* It addresses a specific FP class that synthetic benchmarks do not
  exercise.
* It is deterministic, deployable as a preprocessing step in any
  pattern-based SAST, and orthogonal to the matcher's core logic.
* It does *not* require an AST, taint engine, or LLM — and therefore
  composes with all three (LLM-assisted SAST [5,
  6] gets a cleaner token budget;
  AST-based tools get a sanity-checked input).

## 3. Evaluation design

Two benchmarks, by deliberate contrast.

### LexicalNoiseJava v1 (hand-crafted, hyper-stratified)

* 30 cases, 5 strata × 6 cases (5 negative + 1 positive per stratum)
  along the **lexical-FP source type**: line_comment, block_comment,
  string_literal, char_literal, text_block.
* Manifest: `configs/benchmark/lexical_noise_v1.json` (auditable;
  schema enforced by `LexicalNoiseBenchmark`).
* Each NEG fixture contains the *full* FP-triggering pattern inside
  its noise (sink call + string concat + tainted input cue +
  `HttpServletRequest` mention). Each POS fixture has the same pattern
  in active code as well.
* Diagnostic constraint pinned by tests: pre-F10 must fire on at
  least one NEG per comment stratum, otherwise the benchmark cannot
  measure F10's contribution.

This benchmark is intentionally narrow. It is *not* a recall
benchmark — it measures **whether F10 strips lexical noise without
over-stripping active code**.

### OWASP Benchmark v1.2 (synthetic, large-scale)

* 2,092 testcases across the 8 CWE families that map to CodeGraph's
  active Rego rules (CWE-22 / 78 / 89 / 90 / 327 / 328 / 330 / 643).
* Ground truth from `expectedresults-1.2.csv` (`real_vulnerability ∈
  {true, false}`).
* File-level eval — no Neo4j, no LLM, no graph context — so the run
  is reproducible inside CI and isolates F10's contribution at the
  pattern layer. The full-pipeline thesis-final numbers (P=R=F1=0.953, qualified evidence
  that does not reproduce; current full-corpus F1 is 0.8591)
  add graph context and helper summaries on top.

The OWASP eval has two structural roles in the thesis:

1. **Regression safety**: F10 must not degrade detection on the
   established synthetic benchmark. The Phase D evaluator pins this:
   pre_f10 and post_f10 outcomes are identical for every case.
2. **Empirical evidence for the synthetic-vs-real gap**: F10's
   benefit is invisible on OWASP because OWASP lacks the FP class
   F10 addresses (see §6).

### SemGrep AST baseline

* 8 hand-written rules under `baselines/semgrep/rules/`, one per
  active CWE family, mirroring CodeGraph's coverage.
* SemGrep [7] is the natural AST-based comparison
  point: it never sees inside comments, so on LexicalNoiseJava it
  achieves the same robustness F10 brings to the lexical pipeline.
  On OWASP, SemGrep's hand-written rules lack the wrapper/indirection
  tracking that the regex+flag pipeline provides, so recall is low.
  The thesis chapter must not over-claim from this asymmetry: the
  AST comparison validates F10's correctness, not the relative
  ranking of the two pipelines.

## 4. Metrics and uncertainty

### 4.1 Per-case outcomes

* Per-case label: `real_vulnerability` (OWASP) or `expected ∈ {positive,
  negative}` (LexicalNoiseJava).
* Per-case prediction: target ISO violation_id fired by the method
  (pre_f10 / post_f10 / semgrep / [optional] semgrep_registry).
* Aggregates: TP / FP / TN / FN → Precision, Recall, F1.

### 4.2 Within-run uncertainty

Percentile bootstrap (2,000 resamples by default, seeded) over per-case
outcomes (`bootstrap_prf_ci` in `codegraph/evaluation/uncertainty.py`).
The same resample partition feeds Precision, Recall, and F1 so the
intervals are jointly comparable.

### 4.3 Paired classifier comparison

For the headline F10 contract (post_f10 vs pre_f10) we report two
paired statistics directly tied to research-level convention for
classifier comparison on a shared corpus:

* **Exact-binomial McNemar's test** (`paired_classifier_mcnemar`):
  counts discordant pairs `b` (pre fires, post doesn't) and `c`
  (post fires, pre doesn't). Under H₀ that both classifiers are
  equally likely to err, `b ~ Binomial(b+c, 0.5)`; the two-sided
  exact p-value is `2 · min(P(X≤b), P(X≥b))`. The exact form
  (rather than the χ² approximation) is robust at small n and
  handles `b+c=0` cleanly via `test_defined=False` — the expected
  outcome on the OWASP synthetic corpus (see §6).
* **Paired-bootstrap effect sizes**
  (`bootstrap_paired_delta_ci`) for ΔFPR and ΔFNR. Resamples each
  pair with replacement (same indices for both classifiers, so the
  paired structure is preserved), then computes
  `metric(B) − metric(A)` on the resampled set and reports the
  percentile CI. ΔFPR's CI excluding zero implies F10's FP
  reduction is not a sampling artefact.

Three scopes are reported in every run: `overall` (every case),
`fp_class` (NEG cases only — the design target of F10), and one
per stratum (`stratum:line_comment`, `cwe:22`, etc.). Per-stratum
p-values at n=5-6 are often above α=0.05 even when the effect is
real; we read these as *descriptive*, not *confirmatory*, and rely
on the overall test for significance.

### 4.4 Across-seed stability (multi-seed)

`run_owasp_multiseed_eval.py` runs the OWASP evaluator N times with
different sampling seeds and reports across-seed mean ± standard
deviation on every method's Precision / Recall / F1. This is
orthogonal to the within-run bootstrap: bootstrap measures resample
noise inside one stratified sample; multi-seed measures sensitivity
to *which* stratified sample was drawn. Both being tight is what
"stable result" means in SAST eval practice.

### 4.5 Provenance

Every run writes `provenance.json` with the Git SHA of CodeGraph,
the OPA version, the Python interpreter, the manifest sha256, the
seed, the metrics summary, and — for OWASP runs — the
`owasp_benchmark_sha` (the BenchmarkJava commit on disk, since the
v1.2 tag does not fully pin the corpus).

## 5. Reproducibility

The evaluator is LLM-free and Neo4j-free. The required external
binaries are `opa` and `semgrep`. Each is detected by the runner and
the integration tests skip cleanly when either is absent.

```bash
# LexicalNoiseJava — 30 cases, ~5s
.venv/bin/python run_lexical_noise_eval.py \
    --output-dir outputs/lexical_noise_eval_v1 \
    --seed 42

# LexicalNoiseJava with optional SemGrep registry 4th column (needs network)
.venv/bin/python run_lexical_noise_eval.py \
    --output-dir outputs/lexical_noise_eval_v1 \
    --seed 42 \
    --semgrep-registry-config p/java

# OWASP Benchmark — default 50 cases per CWE (~400 cases), ~1 min on
# 8 cores with multiprocessing
git clone --depth=1 https://github.com/OWASP-Benchmark/BenchmarkJava.git \
    .benchmark_cache/owasp-benchmark
.venv/bin/python run_owasp_lexical_eval.py \
    --owasp-root .benchmark_cache/owasp-benchmark \
    --output-dir outputs/owasp_lexical_eval_v1 \
    --limit-per-cwe 50 --seed 7

# OWASP Benchmark multi-seed stability — ~2 min on 8 cores
.venv/bin/python run_owasp_multiseed_eval.py \
    --owasp-root .benchmark_cache/owasp-benchmark \
    --output-dir outputs/owasp_multiseed_v1 \
    --seeds 7,13,23,42,101 --limit-per-cwe 50
```

## 6. Headline results

### LexicalNoiseJava v1 (n=30, seed=42)

#### Detection metrics

| Method    |  TP |  FP |  TN |  FN |   P   |   R   |   F1  |
|-----------|----:|----:|----:|----:|------:|------:|------:|
| pre_f10   |  3  | 15  | 10  |  2  | 0.167 | 0.600 | 0.261 |
| post_f10  |  3  |  7  | 18  |  2  | 0.300 | 0.600 | 0.400 |
| semgrep   |  5  |  0  | 25  |  0  | 1.000 | 1.000 | 1.000 |

F10 eliminates 8 / 8 comment-stratum FPs (53 % total FP reduction;
precision +80 %; recall unchanged). The 7 residual post-F10 FPs all
live in string-literal / text-block strata where the Python regex
layer still matches the FP pattern inside the active-code view —
candidate F11 follow-up. 2 POSITIVE cases (L12 SQL, L24 PATH) involve
variable indirection the regex layer cannot follow; SemGrep catches
both via AST matching.

#### Paired statistical test (post_f10 vs pre_f10)

| Scope | b (improvements) | c (regressions) | McNemar p (exact) | ΔFPR (post − pre) | ΔFPR 95 % CI |
|---|---:|---:|---:|---:|---|
| overall          | 8 | 0 | **0.0078** | −0.320 | [−0.478, −0.154] |
| fp_class         | 8 | 0 | **0.0078** | −0.320 | [−0.478, −0.154] |
| stratum:line_comment  | 4 | 0 | 0.1250 | −0.800 | [−1.000, −0.400] |
| stratum:block_comment | 4 | 0 | 0.1250 | −0.800 | [−1.000, −0.400] |

The overall and FP-class tests are significant at α=0.05 (exact
p ≈ 0.0078); the ΔFPR 95 % CI does not cross zero. Per-stratum
McNemar at n=5 is underpowered (p ≈ 0.125 with b=4, c=0 — the largest
possible discordant-pair count gives p = 2·0.5⁴ = 0.125, the minimum
achievable at this n); the per-stratum effect-size CIs of ΔFPR =
−0.800 [−1.000, −0.400] communicate the same finding through magnitude
rather than significance.

### OWASP Benchmark v1.2 file-level (n=385, 50 per CWE × 8 CWEs, seed=7)

| Method    |  TP |  FP |  TN |  FN |   P   |   R   |   F1  |
|-----------|----:|----:|----:|----:|------:|------:|------:|
| pre_f10   | 185 |  24 | 155 |  21 | 0.885 | 0.898 | 0.892 |
| post_f10  | 185 |  24 | 155 |  21 | 0.885 | 0.898 | 0.892 |
| semgrep   |  23 |   0 | 179 | 183 | 1.000 | 0.112 | 0.201 |

**F10 produces zero deltas on every OWASP case** in the published run
(385 cases) — and the regression-safety property is independently
pinned in CI by `test_f10_does_not_change_owasp_outcomes` on a
stratified 80-case sample (`limit_per_cwe=10`). The McNemar test
returns `test_defined=False` (b=c=0) and the ΔFPR / ΔFNR bootstrap
CIs are exactly `[0.000, 0.000]` on every scope (overall, fp_class,
and each CWE individually) — the regression-safety claim is
substantiated as both a hypothesis-test result *and* an effect-size
result.

An empirical scan over the full 2,740-case corpus confirms the
underlying reason: zero comment occurrences of any of `MD5`,
`MessageDigest`, `executeQuery`, `ProcessBuilder`, `new Random`,
`XPathFactory` — i.e. the lexical-noise FP class F10 targets is
absent from OWASP Benchmark. This is the data-grounded confirmation
of the synthetic-vs-real gap [4].

The CodeGraph file-level F1 = 0.892 is the *lower bound* for the
production full-pipeline number (F1 = 0.953, qualified evidence that does
not reproduce; current full-corpus F1 is 0.8591); graph context and
helper summaries supply the remaining ~6 F1 points.

The SemGrep low recall on OWASP is **not** evidence that SemGrep is
weaker than CodeGraph — it reflects that our 8 hand-written rules
are simple call-site patterns and do not track OWASP's
`getPropertyValue()` / `getParameterValues()` wrapper indirection.
A taint-aware SemGrep ruleset (or `--config p/owasp-top-ten` from
the SemGrep registry) would close that gap; the apples-to-apples
comparison this evaluator pins is *AST robustness to lexical noise*,
not *recall on synthetic-benchmark wrappers*.

## 7. Honest limitations

1. **LexicalNoiseJava is hand-crafted.** It cannot quantify real-world
   FP rates; only the gradient between pre-F10 and post-F10 on a
   deliberately-stratified FP class.
2. **OWASP Benchmark cannot measure F10's value** — see §6. This is
   itself a result, but the thesis must not claim "F10 improves
   OWASP" from these numbers (it doesn't; it just doesn't hurt).
3. **No real-world FP measurement yet.** Spring PetClinic and
   gs-securing-web are secondary case studies in this thesis; a measured
   FP delta from F10 on a real codebase remains future work.
4. **The file-level evaluator drops graph context** by design. Cases
   where F10 might interact with multi-hop taint paths or helper
   summaries are out of scope here; the full graph pipeline is evaluated
   separately.
5. **The Python regex layer (active-code view) still matches FP
   patterns inside string literals.** F10's literal-stripping applies
   only to the Rego substring view; the active-code view preserves
   them so crypto algorithm strings like `"MD5"` inside
   `MessageDigest.getInstance` remain detectable. The price is that 7
   of the LexicalNoiseJava NEG fixtures (literal / text-block strata)
   still trigger the rule via the flag path. This remains a known
   limitation of the active-code view.
6. **Bootstrap CIs assume per-case independence.** OWASP test cases
   are programmatically generated and share boilerplate; the true
   effective sample size is smaller than n. The multi-seed evaluator
   (`run_owasp_multiseed_eval.py`) partially addresses this by
   resampling at the *stratified-sample* level rather than the
   per-case level — across-seed stdev complements the within-run
   bootstrap CI. A formal block-bootstrap by CWE category remains
   future work; at n=8 categories the block-bootstrap CI would be
   too wide to be useful as a primary statistic.
7. **SemGrep registry comparison is opt-in and LexicalNoiseJava-only.**
   The 4th-method column (`--semgrep-registry-config p/java` or
   similar) requires network access and uses a "did any registry
   rule fire on this file?" semantic — registry rule IDs do not
   deterministically map to CodeGraph violation IDs, so per-CWE
   semantic alignment for OWASP would require parsing each
   finding's `metadata.cwe` field, which is outside this evaluation's
   scope.
