# Codegraph Java Parser

Standalone Eclipse JDT adapter for Codegraph. From the repository root, build
with JDK 21+ and Maven on `PATH`; the target uses the repository's non-credential
settings and isolated dependency cache:

```sh
make java-parser-build
```

Runtime protocol is one bounded UTF-8 JSON request on stdin and one JSON DTO on
stdout. Parse/binding diagnostics are in the DTO; protocol-fatal errors go to
stderr. The primary compilation unit comes from caller-supplied `source_base64`
bytes, not a replacement read of that file. Binding resolution and provenance
fingerprinting may read explicitly supplied Java source roots and binary
classpath entries. The adapter does not build or execute target project code.

Binding resolution uses the running JDK bootclasspath and supplied analysis
paths; missing bindings remain unresolved. Source level is explicitly 8 through
25, with preview features disabled. Selecting Java 25 syntax does not install
Java 25 standard libraries. Maven resolves dependencies only while building
this trusted adapter, never on a runtime parsing request.
