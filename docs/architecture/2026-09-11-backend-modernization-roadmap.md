# Backend review and modernization roadmap

Date: 2026-09-11

Reviewed baseline: `15d4366` (main after frontend PR #242)

Status: first modernization baseline implemented and validated locally.
The wider roadmap remains staged follow-up work. This document grants no deployment approval.

## Execution progress (2026-09-11)

The initial focused environment used Python 3.11.15 and OPA 1.15.1 without embedding
packages, model downloads, or a persistent OPA service. The integrated offline
backend run passed 822 tests and 78 subtests, with 27 explicit skips: 26 need
Semgrep and one needs the missing `/tmp/owasp-benchmark` checkout. Ruff and strict
policy checks and the offline lockfile consistency check passed. One existing
Starlette/HTTPX deprecation warning remains. The unchanged frontend passed 52 tests
across 15 files, lint, and its production build.

| Packet | Commit | Scope and promotion boundary |
| --- | --- | --- |
| W0/W1 foundation | `05fe32a` | Python/package alignment, honest scan/cleanup results, bounded policy workers, lazy ML imports, provider settings. |
| W5 response handling | `b919ca2` | Reject truncated/refused outputs, preserve cleanup and cancellation semantics, prevent duplicate generation on internal errors. |
| W7 shadow safeguards | `715f2e8` | Reject unsupported, ambiguous, conflicting, or non-operative plans; no recipe promotion. |
| W4 contract coverage | `d245573` | Real-OPA positive/negative input contracts for all eight benchmark categories; not new corpus metrics. |
| W2 source-span prerequisite | `eef455e` | Lexical-noise-aware source ranges, parser-column anchoring and explicit ambiguity refusal; graph identities unchanged. |
| W6 artifact generations | `ecb5d96` | Atomic manifest publication and per-search pinned artifacts with validation; see [migration notes](2026-09-11-retrieval-generations.md). |
| Migration CLI | `f4540bb` | Rebuild command uses canonical configuration and honors its overrides; help works without ML or graph access. |
| Cross-packet integration | `51dc84f` | Embeddings use strict stored source ranges; invalid/ambiguous targets are rejected, and CLI tests remain isolated across imports. |

The initial foundation received an independent non-Astra review. Subsequent
workers implemented and tested separate owned packets; the lead reviewed their
integration and only concrete correction diffs, without additional reviewers.
No live graph/corpus rerun, packaged-container execution, real embedding inference,
or paid-model evaluation is claimed. Original thesis artifacts remain unchanged.
Root `trace_id` is unavailable; no comparative cost or latency improvement is claimed.

### Current milestone: clean baseline before integration

The owner has clarified that the completed thesis is a historical baseline, not
a requirement to freeze the application. Post-thesis changes may improve
architecture, tooling, policies, and behavior when justified and validated.
Preserve the recorded thesis artifacts and label new measurements separately;
do not attribute later behavior or results to the original thesis implementation.

The active retrieval-generation and Java source-span corrections are complete.
The integrated offline backend, canonical-artifact, policy, and lint gates passed.
The baseline and migration requirements are committed before considering a
governed merge; nothing has been pushed, deployed, or rebuilt against the live graph.

This milestone does not complete the whole roadmap: modern parser and graph
identity migration, isolated candidate workers, durable run budgets/orchestration,
deterministic recipe promotion, and comparative corpus/resource evidence remain
separate follow-up work. No pending packet is implicitly approved for deployment.
The legacy standalone search CLI also still uses obsolete configuration constants;
the managed application search path and required embedding-rebuild CLI are the
surfaces modernized in this milestone.

The first worker wave exposed gaps in failure-boundary tests: mocked coordinators
did not prove atomic publication, and happy-path cleanup did not cover
cancellation. Future dispatches name these invariants up front and require
public-path regressions with only external dependencies mocked. Review corrections
stay scoped to concrete findings; no additional reviewer is added by default.
These are process adjustments, not measured efficiency claims.

### Next stage: agentic runtime foundations

Work continues on `feat/agentic-runtime-foundations`, branched from the completed
`5dc9948` baseline. The original baseline branch remains available for its
separate governed publishing step.

Two non-Astra workers have independent scopes:

- One resolves the coupled W2/W3 source-snapshot and candidate-isolation
  interfaces before implementation. Parser/graph migration and restricted build
  execution are not assumed available.
- One implements W5 process-local provider admission: bounded active requests,
  bounded waiting capacity, and a queue deadline. It owns transport/config tests
  and configuration reference entries, not snapshot or remediation interfaces.

No heavyweight ML stack, model download, live graph change, or deployment is
required for these packets. Shared interfaces are frozen before further worker
splitting; tests use small bounded thread counts on the three-vCPU VM.

#### Frozen W2/W3 slice: offline scoped candidate verification

Use the existing Java 8 parser behind an immutable snapshot boundary before
introducing JavaParser or changing graph keys. A new opt-in offline CLI will
exercise the implementation; existing HTTP preview/apply behavior stays unchanged.
This avoids both a graph migration and an unused internal framework.

Ownership is one coupled worker for these interfaces:

| Module | Responsibility |
| --- | --- |
| `codegraph/ingestion/snapshots.py` | Source-derived method identity and immutable source snapshots; no database access. |
| `codegraph/remediation/candidate.py` | Validate candidate shape and construct an in-memory replacement from a baseline snapshot. |
| `codegraph/remediation/scoped_verification.py` | Fingerprint policies, evaluate baseline/candidate bundles, and compose an honest target-only report. |
| `scripts/remediation/verify_candidate.py` | Opt-in command taking explicit source, candidate, target, and expected baseline hash; emit the scoped report without applying changes. |

Keep frozen records deeply immutable: source bytes/text, strings, tuples, and
frozen child records, not mutable dictionaries or lists masquerading as snapshots.
Identity contains workspace-relative path, declaring type, method/constructor
name, syntactic parameter types including array/varargs distinctions, and the
source revision hash. These are syntactic declarations, not resolved JVM
descriptors. Name/arity alone never disambiguates an overload.

The snapshot records full original file content, exact target bounds, file hash,
and method hash. Candidate construction re-parses the replacement within its file
context, preserves every byte outside the target, and checks target identity.
If current line-based machinery cannot safely isolate a same-line declaration,
refuse explicitly rather than replacing neighboring code. Unsupported syntax and
unbalanced input produce explicit invalid/unsupported outcomes.

Policy evidence must use an immutable copy of the exact Rego/data inputs that are
fingerprinted, not a hash of one version followed by evaluation of mutable global
paths. Reuse the existing OPA adapter with an additive explicit policy-path
argument if needed; never mutate global settings to redirect evaluation. Temporary
OPA input/policy files are allowed; source, graph, and active index writes are not.

Expose orthogonal outcome fields:

```text
status: POLICY_PASS | POLICY_FAIL | STALE_CANDIDATE |
        AMBIGUOUS_METHOD | INVALID_CANDIDATE | UNSUPPORTED_SOURCE | OPA_ERROR
policy_status: PASS | FAIL | ERROR | NOT_EVALUATED
build_status: NOT_EVALUATED
build_reason: governed_build_worker_unavailable
scope: target_method_only
affected_callers_status: NOT_EVALUATED
```

Include baseline/candidate source and method hashes, policy fingerprint, engine
version, target-rule result, and normalized before/after findings. Never emit a
full verification `PASS`, safety confidence, or application approval. Failure to
collect engine provenance is an error, not an invented version.

Implementation acceptance, in order:

1. Add failing snapshot/overlay regressions for same-arity overloads, arrays,
   varargs, constructors, CRLF, unchanged surrounding bytes, ambiguous legacy
   selectors, unsupported syntax, and stale expected source hashes.
2. Implement the smallest pure snapshot/overlay helpers and run those targets.
3. Add failing real-OPA scoped verification cases: MD5 to SHA-256, unchanged MD5,
   changed source/policy hashes, malformed candidate, and OPA failure. Prohibit
   database calls, source/index writes, and build execution in these tests.
4. Implement normalized local evidence through the existing source bundle builder.
   Recompute candidate ranges and local facts; do not retain stale baseline taint
   flags as candidate evidence. Report caller effects as unevaluated.
5. Wire and test the offline CLI using temporary fixture files, with no provider
   calls or live graph. Document that policy success is not behavioral verification.
6. Return targeted results and concrete limitations for one lead integration
   review. No worker commits, extra reviewers, model installations, or deployment.

The provider-admission worker owns separate config/transport files. Serialize
any newly discovered shared-file requirement through the lead.

#### Parser selection: deeper investigation requested

The user prefers one coherent long-term Java analysis backend and permits a full
replacement, including Spoon if it better serves analysis and remediation.
JavaParser is a provisional recommendation, not a frozen dependency decision.
Keep the scoped snapshot boundary independent of parser-specific AST classes.

Two independent read-only investigations precede migration:

- Map actual ingestion, evidence, graph identity, and remediation requirements.
- Compare upstream Spoon, JavaParser/JavaSymbolSolver, and OpenRewrite against
  those requirements using primary documentation, source, and release evidence.

The upstream investigation found a material Spoon integration boundary:
`CtTypeReference.getTypeDeclaration()` can fall back to reflection, and its
reflection builder can read static fields, initializing dependency classes.
Source-model inspection and reflective shadow expansion must not be conflated.
See the pinned [type reference implementation](https://github.com/INRIA/spoon/blob/v11.5.0/src/main/java/spoon/support/reflect/reference/CtTypeReferenceImpl.java)
and [reflection builder](https://github.com/INRIA/spoon/blob/v11.5.0/src/main/java/spoon/support/visitor/java/JavaReflectionTreeBuilder.java).

Direct Eclipse JDT Core is therefore also under comparison: stable compiler
binding APIs may provide source/binary/unresolved provenance without adding
Spoon-specific internal hooks or reflective target-class access. This is an
evidence-driven extension of the comparison, not a second permanent backend.

Prioritize honest symbol resolution with incomplete dependencies, modern syntax,
exact original-source edits, explicit parse diagnostics, and candidate-local
analysis. Separate documented capabilities from measured behavior. Runtime
memory/latency remain unknown until a bounded local comparison; do not infer
them from package size. No parser installation, default cutover, or live graph
migration is authorized by this investigation alone.

**Research outcome:** recommend direct Eclipse JDT Core DOM as the single backend,
subject to a bounded offline feasibility fixture. Maven Central reports `3.47.0`
as the latest/release version (metadata updated 2026-09-07); the deeper API/source
review used `3.46.0`, so its runtime/dependency assumptions must not silently be
applied to the newer artifact.

The deciding requirement is public compiler-binding provenance, not a claim that
one parser is universally more accurate. JDT exposes `IBinding.isRecovered()`,
`ITypeBinding.isFromSource()`, method declarations/parameter erasure, and nullable
bindings directly. Spoon adds a useful transformation model but would require
extra care or internal hooks for this provenance; JavaParser remains a viable
lighter alternative, not a disproven implementation. OpenRewrite's recipe-first
model is less directly aligned with custom policy evidence.

Repository mapping identified four parser consumers that must migrate together:
ingestion extraction, remediation editing/shape validation, virtual evidence
context, and planning invocation contracts. A package swap alone is insufficient:
graph keys also conflate overloads and lack first-class workspace revisions.

The intended boundary is Python orchestration -> bounded JDT subprocess ->
versioned normalized facts, original-source ranges, and explicit diagnostics.
There will be no permanent dual-parser fallback. Use native UTF-16 offsets with
verified conversion to original UTF-8 bytes, not display line numbers or mandatory
whole-file pretty printing. Begin with fresh analysis state per candidate rather
than claiming unproven cache isolation.

Before migration, establish exact modern-syntax/range behavior, source/binary/
missing-dependency distinctions, absence of annotation-processor/static-initializer
execution, and measured memory/latency. A timeout or subprocess is not a sandbox.
No parser artifacts were installed or candidate projects executed during research.

Primary references:
[ASTParser](https://help.eclipse.org/latest/topic/org.eclipse.jdt.doc.isv/reference/api/org/eclipse/jdt/core/dom/ASTParser.html),
[IBinding](https://help.eclipse.org/latest/topic/org.eclipse.jdt.doc.isv/reference/api/org/eclipse/jdt/core/dom/IBinding.html),
[ITypeBinding](https://help.eclipse.org/latest/topic/org.eclipse.jdt.doc.isv/reference/api/org/eclipse/jdt/core/dom/ITypeBinding.html),
[ASTRewrite](https://help.eclipse.org/latest/topic/org.eclipse.jdt.doc.isv/reference/api/org/eclipse/jdt/core/dom/rewrite/ASTRewrite.html),
[published versions](https://repo.maven.apache.org/maven2/org/eclipse/jdt/org.eclipse.jdt.core/maven-metadata.xml).
Research root `trace_id`: unavailable.

#### Active implementation: clean JDT cutover

The user authorized implementation and explicitly requires no working legacy
backend or fallback path. Work is isolated on `feat/jdt-parser-foundation` from
`219c26e`; the provider and scoped-verification foundations remain separate commits.

Three bounded workers own independent surfaces:

| Packet | Ownership | Completion condition |
| --- | --- | --- |
| Typed contract | `codegraph/java/models.py`, exports, model tests | Immutable strict wire records with source/binary/unknown binding provenance, exact ranges, and complete candidate-shape metadata. |
| Java extractor | `tools/java-parser/`, controlled Java fixtures, extractor tests | Runnable pinned JDT 3.47.0 adapter; real compiler facts and bounded, offline analysis without target-project execution. |
| Python transport | `codegraph/java/service.py`, new config fields, transport tests | Validated original-source requests, strict result decoding, bounded process resources and admission, explicit failures, and reliable cancellation/reaping. |

The canonical entrypoint is:

```python
parse_java_source(
    source_bytes: bytes,
    *,
    relative_path: str,
    source_roots: tuple[Path, ...] = (),
    classpath: tuple[Path, ...] = (),
    resolve_bindings: bool = True,
    language_level: str | None = None,
) -> ParsedJavaFileDTO
```

After freezing that contract and establishing the runnable adapter, migrate the
four parser consumers, graph identities and their callers, packaging, and CI.
Finish by removing the `javalang` dependency, imports, alternative parser
implementations, ambiguous signature lookups, and migration-only compatibility
branches. Existing persisted state that cannot satisfy the new identity contract
must require an explicit rebuild, not a silent compatibility read.

Historical thesis evidence stays archived and unchanged; it is not an active
legacy execution path. Missing JDT, unsupported source, unresolved bindings,
invalid ranges, and stale revisions must produce visible errors or refusals.
There is no automatic downgrade to a different parser, guessed symbol, or
name-only source edit.

Java and `javac` 21.0.12.1 are already available. A missing Maven prerequisite was
resolved with publisher-SHA512-verified Maven 3.9.11 under ignored
`build/jdt-tools/` (11 MiB unpacked), not a host-global installation. Maven builds
the trusted adapter only, with an isolated local dependency cache/settings file.
Builds remain serialized on the loaded three-vCPU VM.

#### Integration handoff: VM implementation, Mac acceptance

On 2026-09-11 the user assigned the later full local run to an agent on their
Mac, where the complete runtime has sufficient resources. Finish the coherent
source cutover here; do not expand this packet into new features or spend the
shared VM's resources on model downloads, full benchmarks, or live graph runs.
The Mac run is a pending acceptance gate, not evidence already obtained.

Current implementation milestones:

- Strict JDT transport, resource limits, subprocess cleanup, and native range
  DTOs are implemented.
- HTTP/frontend remediation requests now require `method_key`; signatures are
  display evidence. Finding-cache keys include the workspace revision.
- Startup is read-only and requires compatible graph/index generations.
- `javalang` has been removed from the dependency manifest and lockfile.
- Frontend brace-based snippet cropping and explanation-time name/file lookup
  have been removed; captured source evidence is preserved.
- Native extractor corrections are complete, including explicit language levels,
  failed-file diagnostics, compact constructor APIs, erased descriptors, and
  streamed analysis-input fingerprints.
- Upload publication now returns a predecessor receipt so failed embedding
  creation can restore the previous active graph, including the first-upload
  case where no previous workspace exists.
- Focused graph/retrieval acceptance is complete; live Neo4j concurrency and
  runtime acceptance remain assigned to the Mac.
- Remediation selects the canonical key and captured file hash, then compiles,
  verifies, and writes identical candidate bytes using isolated workspaces.
  Public-path regressions now exercise the real candidate-path containment
  boundary, not only mocked verifier responses. Non-passing verification,
  skipped builds, and concurrent source edits refuse success. Temporary
  cleanup finishes before source writes and graph publication.
- Orphaned string-replacement and brace-counting helpers are removed. Failed
  JDT file diagnostics surface before method selection; malformed policy
  catalogs return structured verification errors instead of escaping.

The user authorized feature-branch publication and an unmerged PR on
2026-09-11. This does not authorize merge, deployment, or a live graph rebuild.
Publishing must still use an available governed route.

The Mac agent should use the existing project prerequisites (JDK 21+, Maven,
Python 3.14.7, Node 24 LTS, Yarn, uv 0.12.13+, and pinned OPA), then run:

```sh
./scripts/setup_benchmark_env.sh
uv run ruff check .
uv run python -m pytest -q
PATH="$PWD/.venv/bin:$PATH" make policy-check
cd frontend
yarn install --frozen-lockfile
yarn lint
yarn test
yarn build
```

After these gates, exercise the real application against a disposable local
Neo4j database and a new retrieval-artifact directory: upload modern Java with
overloads/records, evaluate policy evidence, search the matching generation,
and preview/verify a controlled candidate. Confirm dry-run source/graph
immutability, stale-revision refusal, missing-classpath diagnostics, and failed
publication recovery. Use controlled model fixtures unless paid model calls
are separately authorized. Preserve historical benchmark artifacts; do not use
production credentials or reinterpret old signature-keyed graphs as JDT state.

The requested delivery is a clean feature branch and an unmerged PR for that
Mac acceptance. This repository's origin is GitHub, unlike the home-server
repositories hosted on Forgejo. Both forge CLIs are configured on the host.
Use the authenticated Git/forge CLI workflow with explicit approval for the
feature-branch push; no persistent permission or credential changes are needed.
The earlier conclusion that publishing required a separate runtime publisher
was incorrect. The runtime launcher exists at
`/usr/local/libexec/platform-capability`, but does not provide general Git
publication commands.

The normal Mac handoff is to fetch `feat/jdt-parser-foundation` from origin.
A complete-history Git bundle is an optional offline transfer path, including
the unpublished prerequisite commits if the branch has not yet been pushed.

If using the bundle, transfer it to the Mac and import without resetting existing
local work or force-updating an existing branch:

```sh
git bundle verify /path/to/codegraph-jdt-foundation.bundle
git fetch /path/to/codegraph-jdt-foundation.bundle \
  refs/heads/feat/jdt-parser-foundation:refs/heads/feat/jdt-parser-foundation
git switch feat/jdt-parser-foundation
```

Use the PR title `feat: establish a clean JDT and Python 3.14 baseline`.
Describe the breaking parser/identity migration, immutable graph publication,
isolated remediation, dependency/runtime refresh, and deferred Mac acceptance.
Keep the PR unmerged until the disposable runtime and E2E acceptance above
are complete. Root `trace_id`: unavailable.

#### Stable dependency refresh

On 2026-09-11 the user expanded acceptance to current stable dependencies and
clean major-version migrations. This is additional work, not evidence that
the earlier source handoff or production acceptance is complete.

- Maven Central still lists JDT 3.47.0 as current. The adapter now uses Gson
  2.14.0, compiler plugin 3.16.0, and shade plugin 3.6.2. Maven 3.9.16 is the
  current stable build baseline; Maven 4 release candidates and compiler-plugin
  4 betas are deliberately excluded.
- OPA 1.20.2 replaces 1.15.1 for new runs. Historical thesis artifacts retain
  their original provenance. Setup checks the cached executable's version,
  verifies downloaded checksums and versions before replacement, and refuses
  failed upgrades without treating the older binary as a successful fallback.
- Node 24.21.0 is the current LTS target for CI and frontend packaging. At the
  user's request, Python is now 3.14.7 across `.python-version`, CI, and the
  digest-pinned backend image, with a Python 3.14 minimum. JDK 21 remains the
  supported Java execution baseline, not a claim to be the newest JDK.
- Dependabot now covers the Maven adapter. Blanket major-version ignores are
  removed; major upgrades can open individual reviewable PRs instead of being
  hidden indefinitely. No automatic merging is enabled.
- Python direct dependencies now resolve to current compatible releases,
  including OpenAI 3.13.0 and sentence-transformers 6.0.1. SDK cleanup uses
  HTTPX2's exception hierarchy directly. The Python upgrade removes the old
  runtime dependency forks: NumPy is 2.5.3 and SciPy is 1.18.1.
- Python 3.14 acceptance uses `build/python314-review-venv`, not either older
  review environment. The native FAISS/NumPy round-trip is now a persisted
  regression. Ruff targets Python 3.14 with the existing lint policy explicitly
  selected, rather than silently adopting a different policy from new defaults.
- Remaining transitive version gaps are upstream compatibility constraints:
  Pydantic 2.13.5 pins pydantic-core 2.46.5, Torch 2.14.0 pins its Linux CUDA
  family, and SymPy 1.14.0 requires mpmath below 1.4. Do not override these
  independently merely to make an outdated-package report empty.
- Frontend migration uses React 19.3, Vite 8.3, Vitest 5, ESLint 10 flat
  configuration, TanStack Table 9, and TypeScript 6.0.3. TypeScript 7 is held
  only because the current typescript-eslint peer range requires below 6.1.
- Frontend tests use memory-bounded `vmForks` for the default jsdom project,
  regular forks for environment/module-reset cases, and Node for explicit
  DOM-free tests. New TypeScript tests remain discoverable by default, and
  project routing is covered by regression cases. Per-file isolation remains
  enabled. VM setup supplies Node's TransformStream before loading MSW.
- The worker measured 54 tests at 34.30 seconds with default forks versus
  27.12 and 27.00 seconds with the selected projects. Shuffled seed 1705 took
  36.70 seconds, so shared-host timings are not a guaranteed speedup. The
  final lead run, including five discovery regressions, passed 59 tests in
  22.23 seconds; lint and production build also passed.
- Heavy ML execution, container builds, and real application E2E remain Mac
  acceptance gates. Native JDT parsing and FAISS/NumPy persistence were
  exercised here; no production-ready runtime claim follows from unit gates.

## Recommendation

Keep CodeGraph's symbolic-first architecture. Modernize the boundaries that make
its results reliable before increasing autonomy:

`versioned workspace -> parsed method snapshots -> OPA findings -> grounded explanation -> bounded candidate -> isolated verification -> reviewable patch`

OPA remains authoritative for the configured policy rules, not a proof of complete
security. Models propose explanations and candidates; deterministic code owns
state transitions, budgets, verification and promotion. A successful compile and
OPA re-check do not prove behavioral equivalence or production safety.

Do not attempt to "solve every vulnerability." The achievable goal is an
end-to-end, resumable research pipeline with explicit supported cases, useful
refusals, reproducible evidence and no hidden mutation of the baseline.

## Review scope and evidence limits

Reviewed the HTTP adapters, startup, configuration, ingestion and graph identity,
policy execution and evidence bundling, retrieval/index publication, LLM
transport, remediation generation/apply/verification, shadow repair components,
CI/container definitions and selected canonical artifacts. This is an
architecture and correctness review, not an exhaustive exploit audit or a new
benchmark experiment.

The checkout was clean at the reviewed commit. No backend source, dependency
manifests, live services or canonical results were changed in this review.

The attempted focused backend test command could not start because
`.venv/bin/python` is absent. Do not interpret prior frontend CI or the
home-server harness preflight as backend validation. No heavyweight Python
dependencies, model weights or benchmark corpus were downloaded. No paid model
calls, uploaded-code builds or live graph experiments were run.

After the user authorized lightweight OPA setup, the official Linux amd64 static
OPA 1.15.1 binary was installed at `.venv/bin/opa` (53,031,355 bytes, approximately
51 MiB). Its SHA-256 matched the official GitHub release asset digest:
`0f96986e4f96a39715257a19ae5aa79615a0344a4cb743ec5a38d316db18b735`.
The binary is git-ignored and no OPA server was started.

`PATH="$PWD/.venv/bin:$PATH" make policy-check` completed successfully. All six
existing `tests/fixtures/policy_contract/*.json` fixtures were evaluated directly
with OPA and their actual violation-ID sets matched `expected_violation_ids`.
This validates those Rego fixtures, not the Python adapter, graph pipeline or
full benchmark.

The user subsequently authorized additional lightweight tooling. A separate,
git-ignored environment at `build/backend-review-venv` was created from the
locked development group using Python 3.11.15:

```sh
UV_PROJECT_ENVIRONMENT=build/backend-review-venv \
  uv sync --locked --only-group dev --python 3.11
```

It installs 13 packages, including pytest 9.1.1, Ruff 0.15.22 and HTTPX 0.28.1,
without installing the backend's ML runtime. The environment occupies about
37 MiB; the Python interpreter was a separate 29.5 MiB download. No manifest or
lockfile changes were needed.

The five existing canonical-artifact and OPA-version-pin tests passed, and
`ruff check .` passed. The full backend test baseline remains unestablished:
the development-only environment intentionally excludes application dependencies.

From the repository root, use:

```sh
.venv/bin/opa version
PATH="$PWD/.venv/bin:$PATH" make policy-check
env -u CODEGRAPH_ENV_FILE OTEL_SDK_DISABLED=true \
  PATH="$PWD/.venv/bin:$PATH" \
  build/backend-review-venv/bin/python -m pytest -q \
  tests/test_canonical_artifacts.py tests/test_opa_version_pin.py
build/backend-review-venv/bin/ruff check .
```

The flight recorder reports active capture, but did not return a root trace ID
for this review. Root `trace_id`: unavailable; do not substitute an unrelated
trace. The reviewed Git commit and this document identify the source assessment.

### Existing strengths worth preserving

- Clear `api/` versus `codegraph/` boundary and centralized Pydantic settings.
- Structured explanation/remediation contracts and task-specific model settings.
- OpenAI Responses support already exists; adopting it is not new work.
- OPA timeouts, per-bundle failure records, deterministic evidence ordering,
  bounded generation retries and explicit remediation support tiers.
- Pure virtual-preview evidence construction, separate from mutating dry runs.
- Build/policy gates, provenance, confidence evaluation, canonical checksum
  protection and an existing Semgrep comparison baseline.
- Existing repair intent, deterministic compiler, candidate comparison/ranking
  and dossier modules. These are building blocks, not a finished live agent loop.

Dependencies have already received recent updates. Package age alone is not a
reason to replace FastAPI, Pydantic, Neo4j, uv or the existing transport interface.

### Scientific baseline

Keep the existing `outputs/thesis_final_*` directories immutable.

- Detection provenance: `outputs/thesis_final_detection_full_v2/provenance.json`,
  source SHA `7ad90a25a3ed69c50d4e639014342bad0e8413fb`.
- Remediation v4: `outputs/thesis_final_remediation_v4/remediation_metrics.json`
  records 25 attempted cases, 25 policy passes and 25 successful builds.
  Its provenance records source SHA
  `80d0084b69f880e89954aaa373f8d12eb30146f8`, remediation model `gpt-5.4`
  and OPA 1.15.1.
- The v4 confidence population has 25 positive and zero negative outcomes.
  Its calibration statistics cannot establish reliability across unsupported
  categories or general production repairs.

These are historical artifacts, not fresh results from the reviewed main commit.
The earlier `docs/audit/2026-06-13-resilience-hardening-audit.md` already identifies
method spans, overload identity and dry-run graph mutation as deferred work.

## Findings and priorities

Evidence classifications: **confirmed** means directly established by source or
artifact inspection; **risk** means a failure scenario still needs a regression
test or experiment. Priorities are engineering order, not security severity.

| ID | Priority | Finding and evidence | Required change |
| --- | --- | --- | --- |
| B01 | P0 | **Confirmed:** `apply_flow.py:602-609` uses `restore_failed = restore_failed or not restore_*()`. If graph restoration fails first, Boolean short-circuiting skips file restoration. Early returns within the try also bypass final result construction after cleanup. | Attempt each cleanup independently; preserve the primary error plus cleanup outcomes in the final result. |
| B02 | P0 | **Confirmed:** candidate verification calls `process_single_file_content` at `apply_flow.py:534` even for dry runs. Shared graph state is subsequently restored, not isolated. | Verify candidates against immutable baseline snapshots plus a candidate overlay; no live graph/file/index writes during preview or dry run. |
| B03 | P0 | **Confirmed:** `verification.py:119` defaults to Maven compile with tests skipped; Gradle uses `compileJava`. `build_verification_summary` compares rule IDs, not distinct finding locations. | Separate parse, compile, behavioral tests, target-rule removal and introduced-finding checks. Define the scope and identity of each check. |
| B04 | P0 | **Confirmed:** `Dockerfile.backend` does not copy `policy/` and has no JDK/Maven/Gradle provisioning. The Compose source bind mount masks the missing-policy packaging issue. | Build self-contained API/policy and isolated verification-worker artifacts; do not treat development Compose as production packaging. |
| B05 | P1 | **Confirmed:** `ingestion/service.py:277` drops parameters from the persisted key; `create_class_and_method` merges on that key and `db.py` constrains it unique. `full_signature` is merely a property/index. | Introduce workspace/revision-aware method identity, including parameter types, and migrate all graph/evidence/index consumers together. |
| B06 | P1 | **Confirmed:** `_infer_block_end_line` counts raw braces. `javalang` targets Java 8; bulk extraction returns empty entity lists after logged parse errors. | Parser-backed ranges and explicit parse-coverage diagnostics; unsupported syntax must not appear as successfully analyzed empty code. |
| B07 | P1 | **Confirmed:** batch OPA failure counts are recorded, but there is no explicit complete/partial/failed result contract. `PolicyPage.tsx:319-322` infers partial status from missing `opa_output`/`enriched`, not failures or truncation. | Carry typed scan completeness and scope through API, Zod, UI and stored artifacts. All-failed and truncated scans must never appear clean. |
| B08 | P1 | **Confirmed:** `policy/runtime/opa.py` starts a subprocess and reloads policies per bundle. `policy/integration.py:80-96` submits all bundles with CPU-derived concurrency up to 32. | Add configurable bounded concurrency; measure an interchangeable persistent OPA adapter against the CLI oracle before choosing it. |
| B09 | P1 | **Confirmed:** `_parse_opa_stdout` and `_extract_opa_value` collapse some malformed/undefined outputs to empty defaults. | Explicitly distinguish a valid empty violation list from undefined query, invalid envelope and engine failure. |
| B10 | P1 | **Confirmed:** `search/hybrid.py:80-83` indexes the signature map without validating result indices. FAISS missing-neighbor `-1` can become the last Python list item. Cache identity uses mtime rather than a complete index/model identity. | Test and reject invalid neighbor IDs; validate model/dimension/count/generation; key caches by artifact identity. |
| B11 | P1 | **Confirmed:** embeddings use method-name snippet extraction and separately publish index/maps/metadata. Startup eagerly ingests and loads retrieval resources; source imports pull ML packages into detection paths. | Exact method snapshots, atomic index generations, lazy retrieval and capability-specific readiness. Avoid graph synchronization as an implicit web-server startup side effect. |
| B12 | P1 | **Confirmed:** `_generation_config` chooses Chat Completions only for structured requests to recognized localhost LM Studio URLs; other compatible endpoints go to Responses. Client creation has no explicit application timeout/retry budget. | Explicit provider capabilities, endpoint selection and parameter support, reusable clients, request deadlines and total retry/token budgets. SDK defaults are not absence of retries. |
| B13 | P1 | **Confirmed:** repair intent/compiler/ranking are shadow components; `patch_compiler.py` uses string matching and skips import-adjustment operations. | Keep shadow mode until exact target matching, import handling, verification and refusal behavior meet promotion criteria. |
| B14 | P2 | **Confirmed:** remediation HTTP work runs in threads; upload progress is an in-memory, 64-slot store. No durable remediation run/state machine is wired through the reviewed request path. | Add persisted runs, bounded worker scheduling, restart recovery, idempotency, cancellation and event replay. |
| B15 | P2 | **Confirmed:** declared Python floor is 3.10, CI uses 3.11 and the image uses 3.14; `repair_intent.py` imports Python-3.11 `StrEnum`. | Select and enforce a supported Python matrix; audit locked dependencies, image compatibility and required tool versions together. |
| B16 | P2 | **Confirmed:** `taint_graph.py` follows CALLS edges and matches sink patterns, not value-level taint propagation. Confidence uses hand-weighted features. | Preserve honest terminology; evaluate stronger analysis and calibration separately rather than changing scientific claims by renaming components. |

The `-1` retrieval case, rollback failure combinations, concurrent dry runs and
packaged-image execution need executable regressions. No live reproduction is
claimed here.

## Architecture choices

| Approach | Benefit | Cost / limitation | Decision |
| --- | --- | --- | --- |
| Patch the current synchronous flow only | Lowest migration cost; good for thesis reproducibility | Does not provide durable agent runs or modern Java support | Use for the first correctness batch only |
| Incrementally add typed snapshots, isolated verification and a bounded run controller | Reuses the research contribution and existing tests; measurable promotion gates | Requires careful identity/contract migration | **Recommended** |
| Rewrite around a broad agent platform and replace storage/retrieval together | More orchestration facilities available immediately | High migration and benchmark risk; framework does not fix parser, state or verification problems | Reject as the initial plan |

### Proposed runtime boundaries

1. **Workspace snapshot:** immutable source revision, content hashes and explicit
   workspace identity. Never let a stale finding authorize edits to newer source.
2. **Analysis snapshot:** versioned method identities/ranges, parse diagnostics,
   graph context and optional retrieval artifact identity.
3. **Policy engine:** a typed adapter shared by CLI and optional persistent OPA.
   Inputs and results carry policy bundle/version/hash and evaluation scope.
4. **Candidate generator:** deterministic recipe first for allowlisted patterns;
   otherwise a schema-constrained model. Return `NO_FIX` for unsupported cases.
5. **Verification worker:** isolated filesystem and candidate analysis overlay;
   restricted build execution with CPU/memory/time/network limits and no host
   credentials. A temporary directory alone is not a sandbox.
6. **Run controller:** deterministic state machine with persisted transitions:
   `queued -> snapshot -> evaluate -> explain -> propose -> verify -> review_ready`.
   Failures, cancellation, budget exhaustion and abstention are explicit terminal
   outcomes. Verification feedback may trigger a bounded next attempt.
7. **Promotion:** initially export a patch/dossier only. Later source application
   requires approval bound to the exact baseline and candidate hashes; reject
   stale or duplicate approvals.

If using Rego to authorize agent actions, use a separate operational-policy
namespace and contract from thesis detection rules. Models cannot modify either
policy set, extend their own budgets or turn a denial into approval.

Do not assume Neo4j Community offers an unrestricted database per candidate.
Prefer in-memory snapshot overlays for the bounded pipeline; use a dedicated
ephemeral graph worker only if parity cannot be achieved otherwise.

## Tooling evaluation, not a shopping list

Official documentation consulted on 2026-09-11:

| Option | Fit | Adoption gate |
| --- | --- | --- |
| [JavaParser + JavaSymbolSolver](https://github.com/javaparser/javaparser) | AST ranges, Java syntax beyond Java 8, declaration/type resolution. Upstream currently documents Java 1-25 support. | Small versioned JSON adapter; fixture matrix for records, text blocks, overloads, arrays, generics and unresolved dependencies. Pin a tested version; do not infer perfect resolution from parser support. |
| [OpenRewrite](https://docs.openrewrite.org/) | Deterministic, formatting-preserving Java transformations and recipes | Evaluate only after snapshot/verification contracts exist. Prove a narrow supported recipe beats current candidates on correctness and cost; no assumption that all injection families have safe recipes. |
| [OPA REST API](https://www.openpolicyagent.org/docs/rest-api) and [policy tests](https://www.openpolicyagent.org/docs/policy-testing) | Reuse a loaded policy engine; explicit policy/bundle identity; native rule tests | Equal normalized findings on identical bundles, correct undefined/error semantics, measured CPU/RSS/latency benefit. Keep CLI as reference. Add tests using the existing OPA tool, not another platform. |
| [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence) | Checkpointing, recovery and human-in-the-loop state | Compare a small prototype with a typed state machine plus SQLite. Select one; persistent checkpoints do not make side effects idempotent or safe. |
| [Pydantic AI](https://ai.pydantic.dev/) | Typed model/tool boundary aligned with the current stack | Optional transport pilot only if provider handling becomes simpler. Do not combine it with LangGraph by default or replace working schema validation without evidence. |
| [OpenAI Python SDK](https://github.com/openai/openai-python) | Existing Responses/Chat interfaces and typed transport | Improve the adapter already present: explicit endpoint capabilities, timeouts, model-compatible parameters, token accounting and fake-provider contract tests. |
| [Neo4j vector indexes](https://neo4j.com/docs/cypher-manual/current/indexes/semantic-indexes/vector-indexes/) | Potentially remove separate FAISS/map lifecycle | Compare retrieval quality, RSS and update complexity on the actual deployed Neo4j version. Current documentation includes features newer than the repo's 5.26.20 image. Keep FAISS unless measured simplification wins. |
| [Semgrep taint rules](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview) | Existing baseline can support stronger comparisons and negative controls | Keep external analyzer evidence distinct from the original CodeGraph method; confirm licensing and intra/interprocedural capabilities before making claims. |

Do not add Redis, a second vector database, a GPU service, an always-on model
server or several agent frameworks without a measured requirement. Splitting
optional embedding dependencies from the policy API is likely a more direct
home-server improvement.

## Execution packets

Each packet is one reviewable change or a short sequence of tightly related PRs.
Add failing regressions before implementation. Start from a feature branch, never
modify canonical outputs, and do not merge a packet merely because its author
reports success. Effort labels are relative, not elapsed-time promises.

### W0 - Establish a runnable baseline (S)

Dependencies: none. Targets: `pyproject.toml`, `uv.lock`,
`Dockerfile.backend`, `.github/workflows/ci.yml`, existing tests.

- Provision the locked Python environment without protected runtime credentials.
  OPA 1.15.1 is now installed locally; preserve or reinstall the verified binary if
  creating the Python environment replaces `.venv/`.
- The separate development-only environment and lightweight gates above are
  complete. Reuse them for static/artifact checks; do not represent them as the
  full application environment.
- Run focused tests first, then baseline lint/policy/full unit gates. Separate
  environment failures from code failures.
- Record interpreter/tool/lock versions and canonical checksum status. Confirm
  whether 3.10 support is intended; remove the false promise or restore support.
- Check current dependency advisories and compatibility, rather than carrying
  forward an old vulnerability count. Upgrade in isolated groups.
- Acceptance: a documented reproducible backend baseline; no skipped or missing
  dependencies presented as passing. Image smoke tests must not depend on a source
  bind mount. Worker tools can be packaged separately from the API.

### W1 - Correct failure handling and result honesty (M)

Dependencies: W0. Targets: `remediation/apply_flow.py`,
`policy/runtime/opa.py`, `policy/integration.py`, `api/models/validation.py`,
policy router, frontend schemas/status component.

- Reproduce B01 cleanup short-circuit and early-return cases. Attempt file and
  graph cleanup independently; include both failure records in the result.
- Define complete/partial/failed/truncated scan metadata with attempted,
  evaluated, failed and excluded scope counts.
- Make invalid/undefined OPA output distinguishable from an empty result.
- Acceptance: all-failed evaluation never appears clean; partial findings remain
  visible; every relevant cleanup is attempted even when another cleanup fails;
  valid existing API consumers retain compatible behavior or are migrated together.

### W2 - Snapshot identity and exact source boundaries (L)

Dependencies: W0; interfaces reviewed before coding. Targets:
`ingestion/service.py`, ingestion models, `db.py`, snippets/editing helpers,
`policy/runtime/bundles.py`, embedding/search consumers and their tests.

- Compare JavaParser adapter with retaining the existing parser behind a legacy
  mode. Adopt a normalized parser-neutral snapshot schema.
- Identity includes workspace, revision, declaring type and resolved descriptor
  where available; unresolved types/calls are explicit, never silently conflated.
- Recompute candidate ranges from candidate content, not baseline line numbers.
- Acceptance: distinct overloaded methods remain distinct throughout graph,
  evidence, retrieval and remediation. Comments/string braces cannot truncate
  methods. Parse failures lower coverage visibly. Re-ingestion is idempotent.
- Publish versioned new graph/index data, not an in-place destructive migration
  of the only baseline. Keep a rollback reference to the previous generation.

### W3 - Isolated candidate verification (L)

Dependencies: W1, W2 snapshot contract. Targets: `apply_flow.py`,
`verification.py`, `context.py`, canonical evidence builder, worker packaging.

- Reuse the pure virtual-preview builder where its semantics are sufficient;
  overlay candidate methods and affected call edges in a run-local snapshot.
- Execute builds/tests in a restricted worker, not the web server or host shell.
  Do not expose existing unauthenticated research endpoints publicly.
- Acceptance: source/graph/index hashes remain unchanged after success, rejection,
  timeout, cancellation and a crashed worker. Concurrent candidates cannot observe
  one another. Candidate ranges and affected-method rechecks match a separately
  ingested candidate oracle on fixtures.
- Test preservation of behavior as a separate gate; missing tests mean "not
  evaluated", not "passed". Retain explicit bounded verification language.

### W4 - Predictable policy/runtime resource use (M)

Dependencies: W1; W2 only for snapshot-keyed caching. Targets:
`policy/runtime/opa.py`, `policy/integration.py`, settings and policy fixtures.

- Introduce a common engine result and bounded concurrency/queue size.
- Benchmark CLI versus a local persistent OPA with identical versioned rules.
  Cache only with policy hash + complete normalized input hash + engine version.
- Add positive/negative/undefined fixtures for every supported category.
- Acceptance: exact normalized finding parity excluding timestamps/decision IDs;
  fail on engine errors; adopt the persistent path only after measured resource
  and latency improvement. Preserve policy version in every decision.

### W5 - Provider compatibility and cost controls (M)

Dependencies: W0. Targets: LLM transport/base/tasks/services, settings and tests.

- Add explicit Responses/Chat selection and provider/model capability profiles.
  Support non-local compatible endpoints without hostname heuristics.
- Set request deadlines, retry categories, total attempt/token limits and client
  lifecycle. Account for SDK retries and schema-repair retries together.
- Persist token use/model/prompt-schema version and sanitized error classes;
  never record credentials or raw reasoning in telemetry.
- Acceptance: fake endpoints cover refusal, malformed structured output, timeout,
  429, unsupported parameters, missing usage and budget exhaustion. No automatic
  expensive-model escalation. Paid comparisons require an approved budget.

### W6 - Retrieval correctness and optionality (M)

Dependencies: W2 for exact snapshot identity. Targets: `search/`,
`embedding/service.py`, startup/readiness and packaging.

- Filter invalid FAISS neighbors and test `k > index size`, empty indexes and
  mismatched maps. Index cache identity includes path/generation/model.
- Publish index, map and metadata as one atomic generation, with content hashes.
- Lazy-load embeddings; distinguish policy-ready from retrieval-ready.
- Acceptance: stale/incomplete indexes never provide misidentified citations;
  detection works with embedding dependencies absent, not just a missing model;
  no startup re-ingestion on an ordinary API restart.
- Run FAISS versus Neo4j-vector retrieval comparison only after correctness is
  stable. Promotion needs non-regressing retrieval metrics and measured resources.

### W7 - Promote deterministic repair carefully (M-L)

Dependencies: W2, W3. Targets: `repair_intent.py`, `patch_compiler.py`,
`comparison.py`, `ranking.py`, `dossier.py`, remediation service.

- Compare current shadow candidates to LLM candidates on identical held-out cases.
  Replace string-only targeting or reject ambiguous matches.
- Handle imports and overlapping edits explicitly; no silently ignored operation
  may be reported as implemented. Reject empty/non-operative repair candidates.
- Acceptance: deterministic allowlisted fixes need no generation call and pass
  the same verification gates. Keep guarded crypto and unsupported injection
  cases as review/refusal until category-specific evidence supports promotion.

### W8 - Durable bounded agent pipeline (L)

Dependencies: W1, W3, W4, W5; consume W7 when promoted.
Targets: new run-controller/store module under `codegraph/`, API run/event DTOs,
worker integration and frontend progress consumers.

- Choose typed controller + SQLite by default for a single-host prototype;
  use LangGraph only if its checkpoint/interrupt facilities reduce demonstrated
  complexity. Do not introduce two competing state stores.
- Persist versioned run IDs, source/policy hashes, approved budget, candidate
  hashes, attempt history, verification outcomes and review status.
- Proposed default: at most two candidate attempts, one active verification
  worker and a configured queue cap; tune using measurements.
- Acceptance: restart recovery, duplicate submissions, stale approvals,
  disconnect/reconnect and cancellation cannot duplicate application or corrupt
  snapshots. An LLM/tool response cannot override a deterministic denial.
- Final artifact: patch + evidence citations + scoped verification report.
  Source application remains separately approved; deployment is not an agent step.

### W9 - New evidence and cleanup (M-L, ongoing)

Dependencies: relevant earlier packets. Targets: evaluation runners, existing
Semgrep baseline, new output directories, reproducibility/API docs.

- Compare legacy and modernized pipelines using the same pinned corpus/config.
  Report changed cases and coverage, not only headline F1.
- Add behavioral negative controls, unseen projects, unsupported syntax and
  failed repairs to evaluation. Keep model calibration fitting separate from
  held-out reporting.
- Track detection precision/recall/F1 by category, parse/graph coverage, citation
  correctness, verified-fix rate with explicit denominator, refusal rate,
  regression rate, token cost, p50/p95 latency and peak RSS.
- Promote evidence only with corpus/source/policy/parser/model/config hashes.
  Keep new methods and results labeled as thesis follow-up unless the manuscript
  is deliberately revised.
- After replacements are proven, remove dead adapters/shadow paths and duplicate
  helpers. Do not delete compatibility layers before checking all callers.

## Low-cost execution and review protocol

Separate two budgets: development-assistant usage and models called by CodeGraph.
Neither implies permission to spend the other.

Suggested development routing, subject to actual account availability and cost:

| Work | Suggested model tier | Parent involvement |
| --- | --- | --- |
| Bounded tests, DTO plumbing, mechanical cleanup after interfaces are frozen | `gpt-5.4-mini` | Review diff and acceptance evidence once per packet |
| Parser adapter, state machine, failure-handling implementation | `gpt-5.3-codex` or another proven non-Astra coding model | Freeze architecture first; review integrated behavior after the packet |
| Independent fresh-context diff review | Non-Astra reviewer | Lead adjudicates concrete findings |
| Cross-cutting design, scientific interpretation, final integration decision | Astra lead | Reserve for decisions and final review, not repetitive tool output |

These are routing suggestions, not a claim about current pricing or that any
model is inherently reliable. Begin with a small packet and compare correctness,
rework and total usage before assigning larger ones.

The standing home-server lean policy allows bounded single-repository
implementation workers when file ownership and approval gates are explicit.
Prefer direct execution for tiny tasks and use one integration review pass after
worker completion; do not run repeated broad worker/lead re-review loops.

Implementation-worker protocol:

- Each worker owns one packet and a non-overlapping worktree; W2 and W3 interfaces
  are frozen together before splitting implementation. Shared core files are
  serialized, not edited competitively.
- A dispatch includes baseline SHA, file ownership, invariants, exact acceptance
  cases, test commands, prohibited mutations and stop conditions.
- Workers return commit/diff, actual command results, remaining unknowns and
  relevant run/trace identifiers. No broad cleanup outside the packet.
- Wait for the batch to finish before reviewing its code. Review the integrated
  diff and execute cross-boundary checks, not just isolated worker assertions.
- Send one bounded correction round with explicit findings. After two failed
  correction rounds or an exhausted budget, stop for a design decision rather
  than running an open-ended "improve again" loop.
- No worker pushes, merges, deploys, resets the live graph, reads credentials or
  invokes paid application models without the applicable authorization.

## First milestone and release gates

Start with **W0 + W1**, then agree the W2/W3 snapshot interface. That produces a
runnable baseline and honest failure behavior before the higher-risk migration.

For each later release, require its targeted tests, `ruff check .`, applicable
`make policy-check`, API/Zod parity checks and a focused benchmark where semantics
change. Require a real isolated end-to-end run before claiming the complete
agentic pipeline works. Unit tests, a mocked UI and successful compilation alone
are insufficient evidence.

Persistent backend deployment needs a separate governed release plan covering
authenticated access, worker isolation, resource limits, health checks and
rollback. The earlier Vite frontend preview is neither a persistent backend
deployment nor evidence that this pipeline already runs.
