# Code property graph engine: evaluated, not adopted

Status: rejected Date: 2026-09-13 Relates to: `2026-09-12-detection-engine-plugin-contract.md`

## Why this record exists

A code property graph engine (Joern) was built, measured, and removed. The implementation is gone; the measurements are kept here so the question is not re-litigated from intuition, and because the negative result is itself evidence about source-based CPG analysis on dependency-less input.

## What was measured

OpenGrep, the intra-file taint engine, cannot follow taint across file boundaries. On OWASP Benchmark, 17-23% of true positives per category reach untrusted input through a helper class in another file, so that is real missed coverage rather than a theoretical gap.

Joern 4.0.620 was integrated behind the detection-engine plugin contract: declarative rules, a generated Scala driver, SARIF at the boundary, findings anchored to JDT `method_key`, and a fail-closed gate on graph resolution quality. All figures below use `configs/benchmark/multicat_full.json` (60 cases/category, seed 7).

| Configuration | Precision | Recall | F1 | TP/FP/FN |
| --- | --- | --- | --- | --- |
| OPA + OpenGrep | 0.793 | 0.888 | 0.838 | 207/54/26 |
| + CPG, all flows | 0.658 | 0.966 | 0.783 | 225/117/8 |
| + CPG, cross-file flows only | 0.773 | 0.949 | 0.852 | 221/65/12 |
| + CPG, cross-file, XPath excluded | 0.780 | 0.944 | 0.854 | 220/62/13 |

Capability findings, which hold independently of the adoption decision:

- **Cross-file taint works.** A tainted chain through a helper in another file
  was traced correctly, and an otherwise identical chain whose helper returns a constant was correctly not flagged.
- **Type resolution is poor but survivable.** On a staged corpus with no pom
  and no jars, 0 of 7 servlet sources resolved by `methodFullName` and 19.1% of calls were unresolved, yet detection still worked because matching on call *name* is resolution-independent.
- **Reporting every flow is worse than reporting none.** Emitting the CPG
  engine's intra-file flows cost 0.055 F1: the intra-file engine covers that ground more precisely, and the dataflow engine overapproximates through unresolved calls. An engine should report only what no other engine can see.
- **Engine value is per-rule.** Net positive for SQL (+0.030), command
  (+0.039), path traversal (+0.025) and LDAP (+0.016); net negative for XPath (-0.042), where only 2 of 15 true positives cross a file boundary.
- **Collection index-insensitivity is not solved by a CPG.** Joern and
  OpenGrep both flag `list.add(tainted); list.remove(0); list.get(1)`, which is provably safe. Joern's design tracks containers, not elements.

## Decision

Not adopted. The best configuration gained **+0.016 F1** over the OpenGrep-only baseline, halving cross-file false negatives (26 -> 13), in exchange for:

- a ~1.7GB JVM toolchain, against a 45MB single binary;
- a full CPG rebuild per evaluation, with no incremental analysis, versus
  per-file seconds;
- near-daily bot releases with no release notes and documented precedent for
  breaking the query API at a patch bump;
- a second Java frontend, in tension with Eclipse JDT being the sole parser of
  record;
- a second rule language and toolchain to keep installed, in CI and locally.

The recall gain is genuine and worth more than the F1 delta suggests: for a security tool a missed vulnerability costs more than a false positive a reviewer dismisses. It did not outweigh the operational cost for a framework whose value is compliance-mapped policy and verified remediation rather than best-in-class detection, and where a lightweight, reproducible install is a design goal.

## What was kept

- The **detection-engine plugin contract**, which made both adding and
  removing the engine bounded work rather than a migration. Removal touched no call site in policy evaluation, registry validation, or candidate re-verification.
- `fetch_active_revision_file_paths` in `codegraph/policy/runtime/graph_queries.py`:
  engines analyse what the graph records was ingested. The bug this replaced is worth remembering — a configuration fallback silently analysed a stale directory and reported a confident "no findings", which reads as *clean* rather than *looked in the wrong place*.

## If this is revisited

- Require cross-file coverage to be worth more than a lightweight install, or
  an engine whose install is comparable to OpenGrep's.
- `jimple2cpg` (bytecode) resolves types almost perfectly and traces the same
  cross-file flows, but needs compiled classes, loses `SOURCE`-retention annotations, and reports `.class` paths. Measuring the product on a bytecode path the product cannot always run would also break construct validity.
- Restrict any such engine to `scope: cross_file` from the start. That was the
  difference between a regression and a gain.
