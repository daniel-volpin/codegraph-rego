# Security Policy

## Security Model and Scope

CodeGraph is a **research software framework** designed to evaluate JVM code analysis, ISO-aligned policy evaluation, grounded LLM explanations, and bounded remediation with re-verification.

It is **not a hardened production multi-tenant sandbox**.

### Trust Boundary and Operating Assumptions

When deploying or running CodeGraph locally or in testing environments, keep the following security assumptions in mind:

1. **Single-User & Loopback Only**: By default, CodeGraph binds HTTP endpoints to `127.0.0.1` (loopback) with no authentication or rate limiting. Exposing the service to untrusted networks without an authenticating reverse proxy is unsafe.
2. **Untrusted Code Ingestion**: Uploaded ZIP archives are extracted into a shared workspace directory (`uploaded_code/`). While Zip-bomb protections and path traversal checks (`safe_extract_zip`) are enforced, arbitrary code extracted into the workspace may be compiled during remediation build verification.
3. **Build Execution**: Remediation verification runs build tools (`javac`, `mvn`, `gradle`) against workspace source code. Ingesting code from untrusted sources should occur inside isolated containers or sandboxed virtual environments.
4. **LLM Integration**: Source code snippets and graph metadata are transmitted to the configured OpenAI-compatible LLM provider for explanation and remediation patch generation. Do not send confidential code to external API endpoints unless authorized.

---

## Reporting a Security Vulnerability

If you discover a security vulnerability in CodeGraph, please report it privately before making it public.

### How to Report

- **GitHub Advisory**: Submit a private report via [GitHub Private Vulnerability Reporting](https://github.com/daniel-volpin/codegraph-rego/security/advisories/new) if enabled.
- **GitHub Issue**: Alternatively, open a GitHub issue marked with the `security` label, taking care **not to include sensitive credentials, live tokens, or exploitable payloads**.

### What to Include

When reporting a vulnerability, please provide:

1. A brief description of the issue and its potential impact.
2. Step-by-step instructions or a minimal proof of concept to reproduce the issue.
3. Affected components, endpoints, or environment configurations.

### Response Timeline

- **Acknowledgement**: We aim to acknowledge reports within 3 business days.
- **Assessment & Patching**: Confirmed security issues will be addressed in a dedicated fix branch and release patch.
