# Security Policy

CodeGraph is a local research system, not a hardened production or multi-tenant sandbox.

## Trust Boundary

- The backend binds to loopback by default and has no application authentication or rate limiting. Do not expose it directly to an untrusted network.
- Uploaded or cloned projects are untrusted input. Archive extraction is bounded, but remediation verification may execute `javac`, Maven, or Gradle against analysed source.
- Build verification is a code-execution boundary. Analyse untrusted third-party projects inside an appropriate container or sandbox.
- Source code and graph-derived context may be sent to the configured OpenAI-compatible LLM endpoint for explanation or remediation. Do not use an external provider for confidential source unless authorized.
- Remediation apply mode can modify the active workspace after verification. Review the candidate and verification result before applying changes to valuable source trees.

Parser timeouts, upload limits, and process resource limits reduce accidental resource exhaustion; they do not turn the service into a hostile-code sandbox.

## Reporting a Vulnerability

Report security vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://github.com/daniel-volpin/codegraph-rego/security/advisories/new). Do not include credentials, confidential source, or sensitive environment data in a public issue.

Please include the affected revision, impact, reproduction steps or a minimal proof of concept, and the affected component or endpoint when known.
