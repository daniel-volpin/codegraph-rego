import type { PolicyCatalogResponse, PolicyEvaluateResponse } from "../schemas";
import { DEMO_VIOLATIONS } from "./violationsList";

export const DEMO_POLICY_EVALUATION: PolicyEvaluateResponse = {
  violations: DEMO_VIOLATIONS,
  evaluation: {
    status: "complete",
    attempted_bundles: DEMO_VIOLATIONS.length,
    evaluated_bundles: DEMO_VIOLATIONS.length,
    failed_bundles: 0,
    omitted_findings: 0,
    excluded_findings: 0,
    truncated: false,
    scope_limited: false,
    rule_ids: [],
  },
  opa_output: {
    evaluated_rules: DEMO_VIOLATIONS.length,
    passed_rules: 0,
    violated_rules: DEMO_VIOLATIONS.length,
    execution_time_ms: 24.8,
  },
  enriched: DEMO_VIOLATIONS.map((v) => ({
    violation_id: v.violation_id,
    cwe: v.control_metadata && Array.isArray((v.control_metadata as Record<string, unknown>).cwes)
      ? String(((v.control_metadata as Record<string, unknown>).cwes as string[])[0] || "CWE-General")
      : "CWE-General",
  })),
};

export const DEMO_POLICY_CATALOG: PolicyCatalogResponse = {
  controls: [
    { control_id: "ISO-A.10.1", title: "Cryptographic Controls and Key Management", rego_rules: ["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-CRYPTO", "ISO-A.10-WEAK-RANDOM"] },
    { control_id: "ISO-A.8.2", title: "Privileged Access and Injection Prevention", rego_rules: ["ISO-A.8-SQL-INJECTION", "ISO-A.8-PATH-TRAVERSAL", "ISO-A.9.4.1"] },
    { control_id: "PCI-Req-6.2.4", title: "PCI-DSS 4.0: Software Security & Injection Flaws", rego_rules: ["PCI-6.2.4.1-SQL-INJECTION", "PCI-6.2.4.2-PATH-TRAVERSAL", "PCI-6.2.4.3-CMD-INJECTION"] },
    { control_id: "OWASP-A03:2021", title: "OWASP Top 10: Injection Flaws", rego_rules: ["A03:2021-SQL-INJECTION", "A03:2021-CMD-INJECTION", "A03:2021-LDAP-INJECTION", "A03:2021-XPATH-INJECTION"] },
    { control_id: "NIST-SI-10", title: "NIST SP 800-53: Information Input Validation", rego_rules: ["NIST-SI-10-SQL-INJECTION", "AU-2-EVENT-LOGGING"] },
    { control_id: "SAST-SARIF-RULES", title: "Universal SAST: Third-Party Findings", rego_rules: ["SEMGREP-CWE-79", "CODEQL-CWE-502", "SONAR-CWE-611", "SEMGREP-CWE-352"] },
  ],
  rules: DEMO_VIOLATIONS.map((v) => ({
    rule_id: v.rule_id || "",
    title: v.description || v.rule_id || "",
    severity: v.severity || "HIGH",
    cwe: v.control_metadata && Array.isArray((v.control_metadata as Record<string, unknown>).cwes)
      ? String(((v.control_metadata as Record<string, unknown>).cwes as string[])[0] || "CWE-General")
      : "CWE-General",
    frameworks: [String((v.control_metadata as Record<string, unknown>)?.standard || "ISO 27001")],
    remediation_strategy: "agentic_graph_repair",
    remediation_tier: "guarded",
  })),
  benchmark_categories: [
    { category_id: "hash-md5", label: "Hash (CWE-328)", cwes: ["CWE-328"], rego_rule_ids: ["ISO-A.10-WEAK-HASH"], control_ids: ["A.10"], remediation_tier: "full", framework_demo: true },
    { category_id: "crypto-md5", label: "Crypto (CWE-327)", cwes: ["CWE-327"], rego_rule_ids: ["ISO-A.10-WEAK-CRYPTO"], control_ids: ["A.10"], remediation_tier: "guarded", framework_demo: true },
    { category_id: "rng-insecure", label: "Randomness (CWE-330)", cwes: ["CWE-330"], rego_rule_ids: ["ISO-A.10-WEAK-RANDOM"], control_ids: ["A.10"], remediation_tier: "full", framework_demo: true },
    { category_id: "sql-injection", label: "SQL Injection (CWE-89)", cwes: ["CWE-89"], rego_rule_ids: ["ISO-A.8-SQL-INJECTION"], control_ids: ["A.8"], remediation_tier: "guarded", framework_demo: true },
    { category_id: "path-traversal", label: "Path Traversal (CWE-22)", cwes: ["CWE-22"], rego_rule_ids: ["ISO-A.8-PATH-TRAVERSAL"], control_ids: ["A.8"], remediation_tier: "guarded", framework_demo: true },
  ],
  framework_demo_rule_ids: ["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-RANDOM", "ISO-A.10-WEAK-CRYPTO", "ISO-A.8-SQL-INJECTION", "ISO-A.8-PATH-TRAVERSAL"],
};
