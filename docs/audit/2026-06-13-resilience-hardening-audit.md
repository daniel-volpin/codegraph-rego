# CodeGraph Resilience Hardening Review

- **Date:** 2026-06-13 to 2026-06-15
- **Scope:** Java ingestion -> Neo4j graph persistence -> evidence bundle
  construction -> OPA/Rego policy evaluation -> explanation/remediation context -> patch apply -> build and policy re-verification -> evaluation provenance.
- **Purpose:** record the reviewer-facing outcome of the resilience audit for the
  thesis baseline. This note is engineering evidence; cite the canonical artifacts under `outputs/thesis_final_*` for reported metrics.

## Reviewer Verdict

The hardening work is part of the thesis baseline. It improves resilience, reproducibility, and failure honesty without silently changing the thesis-reported metrics. The canonical manifest, manifest generator, and pytest tripwire are also worth keeping because they turn accidental metric drift into a visible review event.

The audit document should stay concise. Raw pass-by-pass audit scratchwork, temporary environment failures, and superseded stop/go conclusions are not useful on GitHub because they obscure the final claim. The durable evidence is:

- what changed,
- what was deliberately not changed because it could affect thesis metrics,
- which canonical outputs support the paper's numbers, and
- which tests/commands protect those claims.

## Changes Landed During The Audit

- OPA `eval` calls are bounded by a configurable timeout so a hung policy engine
  cannot stall a full run indefinitely.
- Batch policy evaluation records per-bundle OPA failures and continues, instead
  of discarding all already-computed results on the first bad bundle.
- Apply-mode remediation now requires a build to be both attempted and successful
  before writing to the live workspace.
- Rollback failures are surfaced as non-success remediation outcomes, so a case
  cannot be reported cleanly if the workspace or graph may have been left in a candidate state.
- Source replacement validates the generated method before splicing and validates
  the final candidate file before mutating the graph.
- Candidate ingestion fails loudly on unparseable Java instead of purging graph
  state and later surfacing an opaque `method_not_found`.
- ZIP extraction rejects symlink entries, root-write entries, path traversal, and
  unsafe compression patterns.
- Graph context lists are sorted before serialization, including batch and
  single-method evidence paths, so evidence bundle bytes are stable.
- OPA is pinned to the canonical thesis version and protected by a drift test.
- Evaluation provenance records benchmark ground-truth identity and corpus commit
  information for future runs.
- `outputs/canonical_manifest.sha256`,
  `scripts/evaluation/generate_canonical_manifest.py`, and `tests/test_canonical_artifacts.py` protect committed thesis artifacts from silent overwrite.
- The benchmark-only weak-random corpus fingerprint was removed after live A/B
  validation showed the OWASP detection result was metric-neutral.
- `--require-complete-corpus` fails fast when the OWASP corpus checkout is
  incomplete, preventing a partial denominator from producing headline metrics.

## Canonical Evidence To Keep On GitHub

Keep these because they are directly useful to a thesis examiner or reviewer:

- `outputs/canonical_manifest.sha256`
- `scripts/evaluation/generate_canonical_manifest.py`
- `tests/test_canonical_artifacts.py`
- `tests/test_opa_version_pin.py`
- selected files under `outputs/thesis_final_detection_full_v2/`
- selected files under `outputs/thesis_final_explanation_full_v2/`
- selected files under `outputs/thesis_final_remediation_v2/`
- selected files under `outputs/thesis_final_remediation_v3/`
- selected files under `outputs/thesis_final_remediation_v4/`
- `docs/architecture/artifact-policy.md`
- `docs/thesis_context.md`
- this concise audit note

Do not keep local progress files, transient request logs, ad hoc reruns, or full audit scratch transcripts unless they are promoted into a deliberate evidence artifact with a clear citation purpose.

## Validation Evidence

The live validation runs used OPA 1.15.1, Neo4j 5.26.20, and the full OWASP Benchmark corpus unless noted otherwise.

- Full multi-category detection reproduced the committed canonical oracle
  bit-for-bit: `222/11/11`, precision/recall/F1 `0.9528`, support `454`.
- Graph-pipeline weak-random A/B with the benchmark fingerprint removed vs
  restored was identical: TP `218`, FP `0`, FN `0`, precision/recall/F1 `1.000`. The fingerprint removal is therefore metric-neutral for OWASP Benchmark.
- The sentence-transformer/embedding model was HTTP-403 blocked during detection,
  and detection still completed with identical metrics. This confirms FAISS/vector retrieval is not in the authoritative detection path.
- An instrumented dry-run trace on a real ingested weak-hash case confirmed that
  dry-run verification mutates the live graph, evaluates the patched state, then restores the graph. The serial canonical run is therefore not invalidated, but the crash/concurrency window remains a future hardening target.
- Remediation v4 completes `25/25` attempted cases as `OK` and fully verified.
- The remediation gate does not count skipped builds, failed builds, failed
  rollbacks, parse failures, or failed candidate reconstruction as clean verified successes.
- Canonical artifacts are unchanged unless their checksum manifest is updated in
  the same intentional metric-regeneration change.

Use `outputs/thesis_final_*` files and each directory's `provenance.json` for paper citations. Use this audit note only to explain the engineering control surface around those artifacts.

## Deliberately Deferred Metric-Affecting Work

The following issues remain valid architectural hotspots, but they were deliberately excluded because a correct fix could change reported metrics or evidence semantics:

- **Method span inference:** current brace-count span inference can be confused by
  braces inside comments or string/char literals. Replacing it with parser-backed spans is the right direction, but detection inputs may change.
- **Overloaded method graph keys:** overloaded methods can collapse when graph
  identity does not include parameter types. Fixing this changes graph evidence.
- **Dry-run graph mutation:** remediation dry runs currently mutate and then
  restore the live graph during candidate verification. The canonical serial run is not invalidated by the observed mutate-then-evaluate-then-restore behavior, but future hardening should isolate candidate verification from the live graph.
- **Candidate source slicing:** candidate re-evaluation depends on graph line
  spans. If dry-run graph mutation is removed, candidate method spans must be recomputed from the candidate file.

Treat these as separate thesis follow-up work that requires explicit metric regeneration and prose updates.

## Thesis Citation Guidance

- Cite canonical outputs for numbers, not this audit note.
- Cite `provenance.json` fields for commit, OPA version, config hash, and
  benchmark ground-truth identity.
- Cite the canonical manifest/test only for reproducibility and artifact
  integrity claims.
- Phrase the main claim as symbolic-first detection with graph-structured
  evidence and bounded LLM remediation. Do not overclaim full data-flow, AST-level, or production-grade parser precision beyond what the graph actually stores.
