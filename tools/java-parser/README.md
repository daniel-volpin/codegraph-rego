# CodeGraph Java Parser

Standalone Eclipse JDT adapter used by CodeGraph. Build it from the repository root with JDK 21+ and Maven:

```bash
make java-parser-build
```

The adapter accepts one bounded UTF-8 JSON request on stdin and emits one JSON DTO on stdout. Caller-supplied `source_base64` bytes are the authoritative primary compilation unit; binding resolution may additionally read only the source roots and binary classpath entries supplied in the request.

The adapter parses and resolves analysis facts but does not build or execute the analysed project. Missing bindings remain unresolved rather than being guessed. Supported source levels are 8 through 25 with preview features disabled; choosing a language level does not install that JDK's standard library.

The Python boundary in `codegraph/java/` owns process limits and typed protocol validation. Do not add a second Java parser or fallback source-range implementation.
