# Codegraph Java Parser

Standalone Eclipse JDT adapter for Codegraph. From the repository root, build with JDK 21+ and Maven on `PATH`; the target uses the repository's non-credential settings and isolated dependency cache:

```sh
make java-parser-build
```

The shaded JAR is the single trusted Java adapter executable. With no command it runs the existing parse protocol; with `source-edit` it runs bounded source transformations used by remediation. Both modes accept one bounded UTF-8 JSON request on stdin and emit one JSON DTO on stdout; protocol-fatal errors go to stderr.

Runtime parsing keeps the existing contract unchanged. The primary compilation unit comes from caller-supplied `source_base64` bytes, not a replacement read of that file. Binding resolution and provenance fingerprinting may read explicitly supplied Java source roots and binary classpath entries. The adapter does not build or execute target project code.

The `source-edit` mode currently exposes `ensure_import`. It parses caller-supplied bytes with JDT, creates a real `ImportDeclaration`, applies it through `ASTRewrite`/`ListRewrite`, reparses the rewritten source, and returns either the rewritten bytes or a fail-closed rejection. It only short-circuits exact existing imports; Java name-resolution conflicts are left to JDT diagnostics and the existing compilation gate rather than reimplemented with custom heuristics. Python callers provide typed intent and orchestration but do not parse or synthesize Java import syntax.

Binding resolution uses the running JDK bootclasspath and supplied analysis paths; missing bindings remain unresolved. Source level is explicitly 8 through 25, with preview features disabled. Selecting Java 25 syntax does not install Java 25 standard libraries. Maven resolves dependencies only while building this trusted adapter, never on a runtime parsing or source-edit request.
