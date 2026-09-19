export const POLICY_VIEW_PRESET_STORAGE_KEY = "codegraph:policy:viewPreset";

export const LEGACY_FRAMEWORK_DEMO_RULE_IDS = [
  "ISO-A.10-WEAK-HASH",
  "ISO-A.10-WEAK-RANDOM",
  "ISO-A.10-WEAK-CRYPTO",
  "ISO-A.8-SQL-INJECTION",
  "ISO-A.8-PATH-TRAVERSAL",
  "ISO-A.8-CMD-INJECTION",
  "ISO-A.8-LDAP-INJECTION",
  "ISO-A.8-XPATH-INJECTION",
  "ISO-A.9.4.1",
  "ISO-A.12.4.1",
];

export const HUMAN_RULE_TITLES: Record<string, { title: string; standard: string; control: string }> = {
  // ISO-27001
  "ISO-A.10-WEAK-HASH": { title: "Weak Cryptographic Hash (MD5/SHA-1)", standard: "ISO/IEC 27001", control: "Control A.10" },
  "ISO-A.10-WEAK-CRYPTO": { title: "Insecure Cryptographic Cipher (DES/ECB)", standard: "ISO/IEC 27001", control: "Control A.10" },
  "ISO-A.10-WEAK-RANDOM": { title: "Insecure Random Number Generator", standard: "ISO/IEC 27001", control: "Control A.10" },
  "ISO-A.8-SQL-INJECTION": { title: "Dynamic SQL Injection via Concatenation", standard: "ISO/IEC 27001", control: "Control A.8" },
  "ISO-A.8-PATH-TRAVERSAL": { title: "Arbitrary Path Traversal via Unvalidated Path", standard: "ISO/IEC 27001", control: "Control A.8" },
  "ISO-A.8-CMD-INJECTION": { title: "Operating System Command Injection", standard: "ISO/IEC 27001", control: "Control A.8" },
  "ISO-A.8-LDAP-INJECTION": { title: "LDAP Search Filter Injection", standard: "ISO/IEC 27001", control: "Control A.8" },
  "ISO-A.8-XPATH-INJECTION": { title: "Dynamic XPath Query Injection", standard: "ISO/IEC 27001", control: "Control A.8" },
  "ISO-A.9.4.1": { title: "Unrestricted Privileged Endpoint Execution", standard: "ISO/IEC 27001", control: "Control A.9.4.1" },
  "ISO-A.12.4.1": { title: "Missing Security Event Audit Logging", standard: "ISO/IEC 27001", control: "Control A.12.4.1" },

  // PCI-DSS 4.0
  "PCI-6.2.4.1-SQL-INJECTION": { title: "SQL Injection in Cardholder Data Store", standard: "PCI-DSS 4.0", control: "Req 6.2.4.1" },
  "PCI-6.2.4.2-PATH-TRAVERSAL": { title: "Path Traversal in Cardholder Statement Export", standard: "PCI-DSS 4.0", control: "Req 6.2.4.2" },
  "PCI-6.2.4.3-CMD-INJECTION": { title: "Payment Batch OS Command Injection", standard: "PCI-DSS 4.0", control: "Req 6.2.4.3" },
  "PCI-3.4.1-WEAK-CRYPTO": { title: "Insecure Cipher for Cardholder PAN Encryption", standard: "PCI-DSS 4.0", control: "Req 3.4.1" },
  "PCI-3.4.2-WEAK-HASH": { title: "Insecure Cryptographic Hash for Verification", standard: "PCI-DSS 4.0", control: "Req 3.4.2" },
  "PCI-8.3.1-WEAK-RANDOM": { title: "Non-Cryptographic MFA Code Random Generator", standard: "PCI-DSS 4.0", control: "Req 8.3.1" },

  // OWASP Top 10
  "A03:2021-SQL-INJECTION": { title: "A03:2021 SQL Injection Flaw", standard: "OWASP Top 10", control: "A03:2021" },
  "A03:2021-CMD-INJECTION": { title: "A03:2021 OS Command Injection", standard: "OWASP Top 10", control: "A03:2021" },
  "A03:2021-LDAP-INJECTION": { title: "A03:2021 LDAP Search Filter Injection", standard: "OWASP Top 10", control: "A03:2021" },
  "A03:2021-XPATH-INJECTION": { title: "A03:2021 Dynamic XPath Query Injection", standard: "OWASP Top 10", control: "A03:2021" },
  "A01:2021-PATH-TRAVERSAL": { title: "A01:2021 Broken Access Control / Path Traversal", standard: "OWASP Top 10", control: "A01:2021" },
  "A02:2021-WEAK-CRYPTO": { title: "A02:2021 Deprecated Cryptographic Cipher (DES/ECB)", standard: "OWASP Top 10", control: "A02:2021" },
  "A02:2021-WEAK-HASH": { title: "A02:2021 Broken Cryptographic Hash (MD5)", standard: "OWASP Top 10", control: "A02:2021" },
  "A02:2021-WEAK-RANDOM": { title: "A02:2021 Predictable Pseudorandom Number Generator", standard: "OWASP Top 10", control: "A02:2021" },

  // NIST SP 800-53
  "NIST-SI-10-SQL-INJECTION": { title: "SI-10 SQL Input Validation and Sanitization", standard: "NIST SP 800-53", control: "SI-10" },
  "NIST-SI-10-CMD-INJECTION": { title: "SI-10 Command Execution Input Validation", standard: "NIST SP 800-53", control: "SI-10" },
  "NIST-SI-10-PATH-TRAVERSAL": { title: "SI-10 File Path Input Sanitization", standard: "NIST SP 800-53", control: "SI-10" },
  "NIST-SC-13-CRYPTOGRAPHIC-PROTECTION": { title: "SC-13 FIPS-Compliant Cryptographic Ciphers", standard: "NIST SP 800-53", control: "SC-13" },
  "NIST-SC-28-PROTECTION-AT-REST": { title: "SC-28 Strong Hashing for Information at Rest", standard: "NIST SP 800-53", control: "SC-28" },
  "AC-3-ACCESS-CONTROL": { title: "AC-3 Access Enforcement on Controller Endpoints", standard: "NIST SP 800-53", control: "AC-3" },
  "AU-2-EVENT-LOGGING": { title: "AU-2 Audit & Security Event Logging", standard: "NIST SP 800-53", control: "AU-2" },

  // SAST / SARIF
  "SEMGREP-CWE-79": { title: "CWE-79 Cross-Site Scripting (XSS)", standard: "External SAST", control: "CWE-79" },
  "CODEQL-CWE-502": { title: "CWE-502 Deserialization of Untrusted Data", standard: "External SAST", control: "CWE-502" },
  "SONAR-CWE-611": { title: "CWE-611 XML External Entity (XXE) Vulnerability", standard: "External SAST", control: "CWE-611" },
  "SEMGREP-CWE-352": { title: "CWE-352 Cross-Site Request Forgery (CSRF)", standard: "External SAST", control: "CWE-352" },
};

export const formatHumanRuleTitle = (ruleId: string, fallback?: string): string => {
  if (HUMAN_RULE_TITLES[ruleId]?.title) {
    return HUMAN_RULE_TITLES[ruleId].title;
  }
  if (fallback && fallback !== "—" && fallback.trim()) {
    return fallback.trim();
  }
  const clean = ruleId.replace(/^(iso27001\.|pci_dss\.|owasp\.|nist\.)/, "").replace(/_/g, " ");
  return clean.charAt(0).toUpperCase() + clean.slice(1);
};

export const deriveStandardFromRuleId = (ruleId: string, customStandard?: string): string => {
  if (customStandard && customStandard.trim()) return customStandard.trim();
  if (HUMAN_RULE_TITLES[ruleId]?.standard) return HUMAN_RULE_TITLES[ruleId].standard;
  const lower = ruleId.toLowerCase();
  if (lower.startsWith("iso")) return "ISO/IEC 27001";
  if (lower.startsWith("pci")) return "PCI-DSS 4.0";
  if (lower.startsWith("a0") || lower.startsWith("owasp")) return "OWASP Top 10";
  if (lower.startsWith("nist") || lower.startsWith("ac-") || lower.startsWith("au-") || lower.startsWith("sc-") || lower.startsWith("si-")) return "NIST SP 800-53";
  if (lower.startsWith("semgrep") || lower.startsWith("codeql") || lower.startsWith("sonar") || lower.startsWith("sast")) return "External SAST (SARIF)";
  return "Security Policy";
};
