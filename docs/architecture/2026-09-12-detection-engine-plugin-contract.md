# Detection engines are plugins behind a SARIF contract

Status: accepted Date: 2026-09-12 (revised same day after empirical spike; see Revision note) Constrains: every current and future detection engine, including OPA/Rego, OpenGrep, and any code property graph engine.

## Revision note

This document was first written as a narrower decision ("a CPG is a derived analysis layer"). Hands-on measurement the same day showed the narrower framing asked the wrong question. The problem was never *which* engine; it was that detection was treated as a core component rather than a replaceable input, so each engine change churned the whole stack. The decision below supersedes the earlier framing and subsumes its constraints.

## Context

Detection has been rewritten three times:

1. Hand-rolled regex heuristics inside Rego. Failed OWASP Benchmark's
   deliberate "looks tainted, isn't" cases, because textual co-occurrence is not a data dependency. Measured `0.795` F1.
2. OpenGrep taint analysis. Measured `0.838` F1 on the same configuration, and
   correct on the cases the heuristics failed. Limited to intra-file flows.
3. A code property graph engine, built and measured behind this contract and
   then removed; see `2026-09-13-cpg-engine-evaluation.md`. Adding and removing it touched no call site, which is the property this contract exists to provide.

Each transition churned Rego rules, Python analyzers, tests, fixtures, CI, and documentation. That churn — not any individual engine — is the accumulated complexity, and it follows from the original design fusing three separable concerns:

- **Finding code facts** ("does tainted input reach this sink?"). Commodity.
  Mature engines exist; this project should not implement it.
- **Deciding compliance** ("does that fact violate ISO A.8, at what severity,
  mapped to which control?"). This is policy, it is declarative, and it is auditable. Rego is well suited and this is the project's contribution.
- **Explaining and remediating with verified gates.** Also the project's
  contribution.

Fusing the first into the second is what made engine changes expensive.

## Decision

**Detection engines are plugins behind a SARIF contract. Engine identity is an implementation detail of a rule, not an architectural property of the system.**

`codegraph/policy/sarif_import.py` and the registry's `evidence_source` field already constitute most of this boundary. This decision formalises it so that adding, replacing, or removing an engine is bounded work rather than a migration.

### The contract every engine implements

1. **Rule discovery from a directory.** Rules live in their own directory and
   are discovered at call time. No engine enumerates rules in code, and no rule requires per-rule dispatch logic.
2. **Registry declaration.** Each rule declares its owning engine via
   `evidence_source` in `configs/benchmark/policy_registry.json`. Registry load validates that a declared rule id actually exists in that engine's discovered rule set, so a typo fails loudly instead of silently never firing.
3. **SARIF v2.1.0 at the boundary.** Findings enter through
   `import_findings_from_sarif` and are anchored to JDT `method_key` identities. Nothing downstream learns which engine produced a finding.
4. **Fail closed.** An engine that cannot run is an error, never an implicit
   pass. Anything that re-evaluates a finding routes by `evidence_source_for_rule_id`; re-checking with the wrong engine finds nothing and would read as "fixed".
5. **Self-diagnosis.** An engine that can degrade silently must expose a
   health signal and refuse rather than under-report. For a CPG engine this is an unresolved-call ratio threshold and a check for skipped reaching-definitions passes.
6. **Contract tests per rule.** Every rule ships a fixture asserting both a
   detection and a non-detection. A rule without a fixture fails the suite.
7. **Deduplication.** Findings are deduplicated by `(rule_id, method_key)`, so
   two engines may cover one rule during a transition without double counting.

### Layers that are not engines and do not move

| Concern | Owner | Why |
| --- | --- | --- |
| Java parsing, method identity, byte ranges, source hashes | Eclipse JDT | Safe editing depends on verified native ranges and captured hashes. A best-effort symbol solver cannot back a refuse-rather-than-guess guarantee. |
| Graph system of record: immutable revisions, publishing, predecessor receipts | Neo4j | No analysis engine models revisions or rollback. |
| Compliance decisions, control mapping, severity | OPA/Rego + `policy/packs/` | The ISO/PCI/NIST mapping is the auditable artifact. Moving it into an engine's query language would repeat the original mistake in a new language. |
| Remediation acceptance | The three invariant gates | Acceptance is deterministic and engine-independent by design. |

An engine may only produce **evidence**. It never supplies identity, decides compliance, or accepts a remediation.

## Constraints on any engine added later

1. **Pin the engine version exactly and treat upgrades as re-validation**
   against the fixture suite. Analysis tools move fast and have broken query APIs at patch bumps.
2. **No network egress driven by analysed input.** Dependency-fetching flags
   resolve coordinates from attacker-supplied build files, which is attacker-influenced network access on untrusted uploads.
3. **No long-running analysis server.** Engines that execute arbitrary queries
   server-side are not security boundaries; invoke them as subprocesses with explicit output.
4. **Expensive analysis stays off interactive request paths** without caching.
5. **Report only what the engine uniquely sees.** Overlapping a more precise
   engine measurably costs precision — see the CPG evaluation record.

## Non-goals

- Replacing Neo4j, JDT, or Rego.
- Expressing compliance predicates in an engine query language.
- Chasing detection F1 for its own sake. The current `0.838` already exceeds
  published OWASP Benchmark figures for CodeQL (~`0.744`) and Semgrep (~`0.694`); the recorded `0.9528` is qualified evidence (see `docs/thesis_context.md`). Marginal detection tuning is explicitly lower priority than remediation, calibration, and evidence quality.

## Consequences

- Engine choice becomes reversible, so "full migration vs complement" stops
  being an architectural question and becomes a per-rule decision on evidence.
- The registry's `evidence_source` routing and the per-rule fixture requirement
  become load-bearing rather than incidental.
- Cross-file taint becomes reachable without weakening provenance.
- More than one engine may be installed, so setup and CI must install each one
  a rule depends on, and a missing engine must fail rather than silently reduce coverage.
- Each engine also costs install weight, setup steps and CI time. A
  lightweight, reproducible install is a design goal, so an engine must earn its place on measured coverage and is a candidate for removal when it does not.
