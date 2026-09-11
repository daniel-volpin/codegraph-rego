# Scoped candidate verification

This W2/W3 slice adds an opt-in offline verification path for one remediation
candidate. It does not change HTTP preview/apply behavior and does not write to
source files, Neo4j, embedding indexes, or build outputs.

## Entrypoint

```bash
PATH="$PWD/.venv/bin:$PATH" \
  build/backend-review-venv/bin/python -m scripts.remediation.verify_candidate \
  --workspace-root /path/to/workspace \
  --source src/main/java/demo/Crypto.java \
  --method 'demo.Crypto#hash()' \
  --candidate candidate-method.java \
  --rule-id ISO-A.10-WEAK-HASH \
  --expected-source-sha256 <current-source-file-sha256>
```

`--method` is a source declaration selector, not a JVM descriptor. Use
`declaring.Type#method(Type,String[],String...)`. Constructors use the source
constructor name, for example `demo.Sample#Sample(String...)`.
Constructor identities are supported by snapshots; candidate overlays currently
accept methods only and explicitly refuse constructor replacements.

`--expected-policy-sha256` is optional only when the caller intentionally wants
to capture the policy fingerprint in the same invocation. If supplied, a mismatch
returns `STALE_CANDIDATE` before OPA evaluation.

The source path and candidate replacement file must resolve under
`--workspace-root`. The CLI exits `0` only for `POLICY_PASS`; stale, invalid,
not-evaluated, policy-fail, and OPA-error reports are emitted as JSON with a
non-zero exit.

## Guarantees and limits

- Source snapshots are immutable frozen records containing full file bytes,
  exact method bounds, syntactic parameter identity, file hash, and method hash.
- Parameter identity preserves qualified source type chains, arrays, and varargs;
  generic parameter shapes are explicitly unsupported pending modern parser work.
- Legacy `class.method()` selectors are refused when overloaded.
- Same-line declarations are refused because line-splice replacement could alter
  neighboring code.
- Candidate files must contain exactly one complete replacement method
  declaration; extra methods, fields, nested types, initializers, or class-closing
  injection are rejected.
- Candidate overlays preserve bytes outside the target method and re-parse the
  resulting file before policy evaluation.
- OPA evaluates an immutable copied policy directory through an explicit
  `policy_dir`; global settings are not changed.
- Source/candidate path errors are reported as `INPUT_ERROR`; policy copy,
  catalog decode, provenance, and OPA execution errors are reported as
  `OPA_ERROR`.
- Policy-capture cleanup errors are surfaced as `cleanup_error`. If cleanup
  fails after a policy pass, the final status is `CLEANUP_ERROR` so the CLI
  cannot exit successfully while cleanup state is unknown.
- Candidate facts are rebuilt from the candidate source with the existing pure
  evidence builder. Baseline analysis flags are not reused.
- Results report `POLICY_PASS`/`POLICY_FAIL`, not full verification success.
- `POLICY_PASS` requires the captured policy catalog to contain the requested rule
  and the baseline policy evaluation to detect that rule; otherwise the result is
  `NOT_EVALUATED`.
- Builds are never executed here: `build_status=NOT_EVALUATED` and
  `build_reason=governed_build_worker_unavailable`.
- Affected callers are explicitly `NOT_EVALUATED`; no graph caller coverage is
  fabricated.

Java parsing remains limited to the existing `javalang` Java 8 parser. Modern
parser migration can replace `codegraph.ingestion.snapshots` behind the same
immutable interface later.
