# Code property graph as a derived analysis layer

Status: accepted (boundary decision; no CPG code exists yet)
Date: 2026-09-12
Supersedes: nothing. Constrains: any future Joern/CPG integration.

## Context

Injection detection moved from lexical Rego heuristics to dataflow taint
analysis (OpenGrep), measured at `0.838` F1 against `0.795` for the heuristics
on the matched benchmark configuration. Two limits remain, and neither is
fixable by writing better rules for the current engine:

- **Cross-file taint is not followed.** OpenGrep offers only intra-file
  interprocedural analysis (`--taint-intrafile`); `--pro`/`--pro-intrafile` do
  not exist in the fork. Roughly 17–23% of OWASP Benchmark true positives per
  category reach input through a helper class in another file.
- **Collection index-sensitivity is unmodelled.** `list.add(tainted);
  list.remove(0); bar = list.get(1)` yields a false positive because inserting
  a tainted member taints the container. Joern and Semgrep share this limit.

A code property graph (CPG) unifies AST, control flow, and program dependence
in one queryable structure, and Joern ships a traversal DSL (CPGQL) plus an
interprocedural dataflow engine under Apache-2.0. Its documented cross-file
test case is materially identical to the `SeparateClassRequest` shape this
corpus uses, so it addresses the first limit — but not the second.

This raises a genuine architectural question rather than a tooling one, because
CodeGraph is *itself* a code-graph-plus-queries system. The risk is drift: a
CPG could plausibly absorb the graph, the query layer, and the parser, and that
would happen incrementally and without a decision being taken. This document
takes the decision up front.

## Decision

A CPG is adopted, if adopted at all, as a **derived analysis artifact** that
produces evidence. It does not become the system of record, the decision layer,
or a second source of code identity.

### Layers that do not move

| Concern | Owner | Why it does not move |
| --- | --- | --- |
| Java parsing, method identity, byte ranges, source hashes | Eclipse JDT (`tools/java-parser/`, `codegraph/java/models.py`) | Safe source editing depends on verified native ranges and captured hashes. A best-effort symbol solver cannot back a refuse-rather-than-guess guarantee. |
| Graph system of record: immutable revisions, active-workspace publishing, predecessor receipts | Neo4j (`codegraph/ingestion/`, `codegraph/policy/runtime/graph_queries.py`) | A CPG has no revision or rollback model. Provenance and conditional rollback are product requirements, not analysis conveniences. |
| Compliance decisions and control mapping | OPA/Rego + `configs/benchmark/policy_registry.json` | The ISO/PCI/NIST mapping is the auditable artifact. Policy must stay declarative and versioned, not embedded in JVM analysis code. |
| Remediation acceptance | The three invariant gates (`codegraph/remediation/`) | Acceptance is deterministic and engine-independent by design. |

### What a CPG may own

- Dataflow-rich **evidence**: verified source→sink paths, including across file
  boundaries, expressed as CPGQL traversals.
- Graph-level **facts** that Cypher over the JDT graph cannot express, because
  the JDT graph carries AST and call edges but no control-flow or
  data-dependence edges.

### Required integration shape

1. **Registry-routed, like every other engine.** A CPG-backed rule declares
   `evidence_source: "cpg"` in `configs/benchmark/policy_registry.json`, is
   discovered from its own rule directory, and is validated at registry load
   time the way `opengrep` rules are. No dispatch code per rule, and no rule
   that is declared but undiscoverable.
2. **SARIF at the boundary.** Findings enter through
   `codegraph/policy/sarif_import.py`, anchored to JDT `method_key` identities.
   `joern-scan` emits plain text, so a SARIF emitter is part of the
   integration cost, not an afterthought. Nothing downstream learns that a new
   engine exists.
3. **Fail closed.** Any engine that re-verifies a finding must route by
   `evidence_source_for_rule_id`. An engine that cannot run is an error, never
   an implicit pass. This is the defect fixed for OpenGrep and it must not be
   reintroduced.
4. **Ephemeral artifact.** The CPG is built from a staged workspace, consumed,
   and discarded. It is not persisted as a parallel long-lived graph, because
   two systems of record for code identity is precisely the drift this
   document exists to prevent.
5. **Second parser is contained.** Joern's Java frontend may parse only to
   build the analysis CPG. It must not supply method identities, ranges,
   hashes, or anything reaching a source write. Where a CPG finding must be
   acted upon, it is anchored back to the JDT identity first. This keeps the
   "Eclipse JDT is the sole Java parser" invariant meaningful: JDT remains the
   sole parser of record, and the CPG frontend is an analysis input.

### Non-goals

- Replacing Neo4j, JDT, or Rego.
- Persisting a CPG as a queryable product surface.
- Expressing compliance predicates in CPGQL. If the prototype shows CPGQL
  expresses them better than Rego, that is a later decision, taken on
  measurement and recorded in its own ADR.

## Adoption gate

CPG integration proceeds only if a prototype, measured on the existing harness
(`run_benchmark_eval.py` with `configs/benchmark/multicat_full.json`, 60
cases/category, seed 7 — the configuration all current comparisons use),
demonstrates:

- F1 above the OpenGrep baseline of `0.838`, **and**
- a measurable reduction in the cross-file false negatives specifically, since
  that is the only structural limit a CPG is expected to remove.

Stock Joern Java queries are not a shortcut here: published results put them at
`8.2%` recall on OWASP Benchmark, attributable to a near-empty default Java
query set. The engine is strong; the rules must be written. The prototype cost
is therefore five CPGQL taint queries with custom flow semantics plus a SARIF
emitter, and that cost should be accepted deliberately.

A negative result is a valid and publishable outcome, and is cheaper to obtain
than an overhaul is to reverse.

## Consequences

- Cross-file taint becomes addressable without weakening the provenance model.
- The engine count rises, so the registry's `evidence_source` routing and the
  per-rule fixture requirement become load-bearing rather than incidental.
- Runtime cost grows: CPG construction is JVM-based and measured in tens of
  seconds for a full corpus, against per-file seconds for OpenGrep. Acceptable
  for batch evaluation; it must not sit on an interactive request path without
  caching.
- Collection index-sensitivity remains a documented limitation under every
  engine considered. It should be stated as scope, not presented as solved.
