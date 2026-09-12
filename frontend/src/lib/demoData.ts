import type {
  AgenticRemediationResponse,
  HealthCheckResponse,
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  PolicyExplainOneResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  SarifExportResponse,
  SearchResponse,
  UploadResponse,
  UploadStatus,
  Violation,
} from "./schemas";

export const DEMO_HEALTH: HealthCheckResponse = {
  status: "ok",
  startup_ready: true,
  neo4j: true,
  graph_generation: true,
  faiss_index: true,
  signature_map: true,
  embedding_model: true,
  opa: true,
  startup: {
    ready: true,
    phase: "ready",
    checks: {
      graph: true,
      embeddings: true,
      symbol_index: true,
      opa_engine: true,
    },
    errors: {},
  },
  details: {
    mode: "interactive_thesis_demo",
    version: "0.5.0-demo",
  },
};

export const DEMO_POLICY_CATALOG: PolicyCatalogResponse = {
  controls: [
    {
      control_id: "ISO-A.10.1",
      title: "Cryptographic Controls and Key Management",
      rego_rules: ["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-CRYPTO", "ISO-A.10-WEAK-RANDOM"],
    },
    {
      control_id: "ISO-A.8.2",
      title: "Privileged Access and Injection Prevention",
      rego_rules: ["ISO-A.8-SQL-INJECTION", "ISO-A.8-PATH-TRAVERSAL", "ISO-A.9.4.1"],
    },
    {
      control_id: "PCI-Req-6.2.4",
      title: "PCI-DSS 4.0: Software Security & Injection Flaws",
      rego_rules: [
        "PCI-6.2.4.1-SQL-INJECTION",
        "PCI-6.2.4.2-PATH-TRAVERSAL",
        "PCI-6.2.4.3-CMD-INJECTION",
        "PCI-3.4.1-WEAK-CRYPTO",
        "PCI-3.4.2-WEAK-HASH",
        "PCI-8.3.1-WEAK-RANDOM",
      ],
    },
    {
      control_id: "OWASP-A03:2021",
      title: "OWASP Top 10: Injection Flaws & Broken Access",
      rego_rules: [
        "A03:2021-SQL-INJECTION",
        "A03:2021-CMD-INJECTION",
        "A03:2021-LDAP-INJECTION",
        "A03:2021-XPATH-INJECTION",
        "A01:2021-PATH-TRAVERSAL",
        "A02:2021-WEAK-CRYPTO",
      ],
    },
    {
      control_id: "NIST-AC-3",
      title: "NIST SP 800-53: Access Enforcement & Audit",
      rego_rules: [
        "AC-3-ACCESS-CONTROL",
        "AU-2-EVENT-LOGGING",
        "SC-13-CRYPTOGRAPHIC-PROTECTION",
        "SC-28-PROTECTION-AT-REST",
      ],
    },
    {
      control_id: "SAST-SARIF-RULES",
      title: "Universal SAST: Third-Party Finding Rules",
      rego_rules: [
        "SEMGREP-CWE-79",
        "CODEQL-CWE-502",
        "SONAR-CWE-611",
        "SEMGREP-CWE-352",
      ],
    },
  ],
  rules: [
    {
      rule_id: "ISO-A.10-WEAK-HASH",
      title: "Weak Hash Algorithm (MD5/SHA-1)",
      severity: "HIGH",
      cwe: "CWE-328",
      frameworks: ["ISO 27001", "OWASP A02:2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "ISO-A.10-WEAK-CRYPTO",
      title: "Broken / Deprecated Cryptographic Cipher (DES/ECB)",
      severity: "HIGH",
      cwe: "CWE-327",
      frameworks: ["ISO 27001", "OWASP A02:2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "ISO-A.10-WEAK-RANDOM",
      title: "Insecure Random Number Generator",
      severity: "MEDIUM",
      cwe: "CWE-330",
      frameworks: ["ISO 27001"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "ISO-A.8-SQL-INJECTION",
      title: "SQL Injection via Concatenation",
      severity: "CRITICAL",
      cwe: "CWE-89",
      frameworks: ["ISO 27001", "OWASP A03:2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "ISO-A.8-PATH-TRAVERSAL",
      title: "Arbitrary Path Traversal via User Input",
      severity: "HIGH",
      cwe: "CWE-22",
      frameworks: ["ISO 27001", "OWASP A01:2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "ISO-A.9.4.1",
      title: "Access Control on Public Controller Endpoints",
      severity: "HIGH",
      cwe: "CWE-284",
      frameworks: ["ISO 27001"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "PCI-6.2.4.1-SQL-INJECTION",
      title: "PCI-DSS 4.0: SQL Injection in Cardholder Store",
      severity: "CRITICAL",
      cwe: "CWE-89",
      frameworks: ["PCI-DSS-4.0"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "PCI-6.2.4.2-PATH-TRAVERSAL",
      title: "PCI-DSS 4.0: Card Statement Path Traversal",
      severity: "HIGH",
      cwe: "CWE-22",
      frameworks: ["PCI-DSS-4.0"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "PCI-6.2.4.3-CMD-INJECTION",
      title: "PCI-DSS 4.0: Payment Batch Command Injection",
      severity: "CRITICAL",
      cwe: "CWE-78",
      frameworks: ["PCI-DSS-4.0"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "PCI-3.4.1-WEAK-CRYPTO",
      title: "PCI-DSS 4.0: Cardholder PAN Encryption with DES",
      severity: "CRITICAL",
      cwe: "CWE-327",
      frameworks: ["PCI-DSS-4.0"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "PCI-3.4.2-WEAK-HASH",
      title: "PCI-DSS 4.0: Deprecated MD5 for Transaction Hash",
      severity: "HIGH",
      cwe: "CWE-328",
      frameworks: ["PCI-DSS-4.0"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "PCI-8.3.1-WEAK-RANDOM",
      title: "PCI-DSS 4.0: Non-Cryptographic MFA Code RNG",
      severity: "HIGH",
      cwe: "CWE-330",
      frameworks: ["PCI-DSS-4.0"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "A03:2021-SQL-INJECTION",
      title: "OWASP Top 10: Dynamic JDBC Query Injection",
      severity: "CRITICAL",
      cwe: "CWE-89",
      frameworks: ["OWASP-2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "A03:2021-CMD-INJECTION",
      title: "OWASP Top 10: OS Command Injection",
      severity: "CRITICAL",
      cwe: "CWE-78",
      frameworks: ["OWASP-2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "A03:2021-LDAP-INJECTION",
      title: "OWASP Top 10: LDAP Search Filter Injection",
      severity: "HIGH",
      cwe: "CWE-90",
      frameworks: ["OWASP-2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "A03:2021-XPATH-INJECTION",
      title: "OWASP Top 10: XPath Query Expression Injection",
      severity: "HIGH",
      cwe: "CWE-643",
      frameworks: ["OWASP-2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "A01:2021-PATH-TRAVERSAL",
      title: "OWASP Top 10: Arbitrary File Read via Path Traversal",
      severity: "HIGH",
      cwe: "CWE-22",
      frameworks: ["OWASP-2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "A02:2021-WEAK-CRYPTO",
      title: "OWASP Top 10: Deprecated Session Cookie Encryption",
      severity: "HIGH",
      cwe: "CWE-327",
      frameworks: ["OWASP-2021"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "AC-3-ACCESS-CONTROL",
      title: "NIST SP 800-53: Access Enforcement Missing",
      severity: "HIGH",
      cwe: "CWE-284",
      frameworks: ["NIST-SP-800-53"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "AU-2-EVENT-LOGGING",
      title: "NIST SP 800-53: Event Logging for Sensitive Actions",
      severity: "MEDIUM",
      cwe: "CWE-778",
      frameworks: ["NIST-SP-800-53"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "SC-13-CRYPTOGRAPHIC-PROTECTION",
      title: "NIST SP 800-53: Cryptographic Protection Weakness",
      severity: "HIGH",
      cwe: "CWE-328",
      frameworks: ["NIST-SP-800-53"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "SC-28-PROTECTION-AT-REST",
      title: "NIST SP 800-53: Protection of Information at Rest",
      severity: "HIGH",
      cwe: "CWE-311",
      frameworks: ["NIST-SP-800-53"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "SEMGREP-CWE-79",
      title: "Universal SAST (Semgrep): Reflected XSS",
      severity: "HIGH",
      cwe: "CWE-79",
      frameworks: ["SAST-SARIF"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "full",
    },
    {
      rule_id: "CODEQL-CWE-502",
      title: "Universal SAST (CodeQL): Insecure Deserialization",
      severity: "CRITICAL",
      cwe: "CWE-502",
      frameworks: ["SAST-SARIF"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "SONAR-CWE-611",
      title: "Universal SAST (SonarQube): XML External Entity (XXE)",
      severity: "HIGH",
      cwe: "CWE-611",
      frameworks: ["SAST-SARIF"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
    {
      rule_id: "SEMGREP-CWE-352",
      title: "Universal SAST (Semgrep): Missing CSRF Protection",
      severity: "MEDIUM",
      cwe: "CWE-352",
      frameworks: ["SAST-SARIF"],
      remediation_strategy: "agentic_graph_repair",
      remediation_tier: "guarded",
    },
  ],
  benchmark_categories: [
    {
      category_id: "crypto-compliance",
      label: "Cryptographic Compliance",
      cwes: ["CWE-328", "CWE-327", "CWE-330"],
      rego_rule_ids: [
        "ISO-A.10-WEAK-HASH",
        "ISO-A.10-WEAK-CRYPTO",
        "ISO-A.10-WEAK-RANDOM",
        "PCI-3.4.1-WEAK-CRYPTO",
        "PCI-3.4.2-WEAK-HASH",
        "PCI-8.3.1-WEAK-RANDOM",
        "A02:2021-WEAK-CRYPTO",
        "SC-13-CRYPTOGRAPHIC-PROTECTION",
      ],
      control_ids: ["ISO-A.10.1", "PCI-Req-6.2.4", "NIST-AC-3"],
      remediation_tier: "full",
      framework_demo: true,
    },
    {
      category_id: "injection-compliance",
      label: "Injection & Input Validation",
      cwes: ["CWE-89", "CWE-22", "CWE-78", "CWE-90", "CWE-643", "CWE-79", "CWE-502", "CWE-611"],
      rego_rule_ids: [
        "ISO-A.8-SQL-INJECTION",
        "ISO-A.8-PATH-TRAVERSAL",
        "PCI-6.2.4.1-SQL-INJECTION",
        "PCI-6.2.4.2-PATH-TRAVERSAL",
        "PCI-6.2.4.3-CMD-INJECTION",
        "A03:2021-SQL-INJECTION",
        "A03:2021-CMD-INJECTION",
        "A03:2021-LDAP-INJECTION",
        "A03:2021-XPATH-INJECTION",
        "A01:2021-PATH-TRAVERSAL",
        "SEMGREP-CWE-79",
        "CODEQL-CWE-502",
        "SONAR-CWE-611",
      ],
      control_ids: ["ISO-A.8.2", "PCI-Req-6.2.4", "OWASP-A03:2021", "SAST-SARIF-RULES"],
      remediation_tier: "guarded",
      framework_demo: true,
    },
  ],
  framework_demo_rule_ids: [
    "ISO-A.10-WEAK-HASH",
    "ISO-A.10-WEAK-CRYPTO",
    "ISO-A.10-WEAK-RANDOM",
    "ISO-A.8-SQL-INJECTION",
    "ISO-A.8-PATH-TRAVERSAL",
    "ISO-A.9.4.1",
    "PCI-6.2.4.1-SQL-INJECTION",
    "PCI-6.2.4.2-PATH-TRAVERSAL",
    "PCI-6.2.4.3-CMD-INJECTION",
    "PCI-3.4.1-WEAK-CRYPTO",
    "PCI-3.4.2-WEAK-HASH",
    "PCI-8.3.1-WEAK-RANDOM",
    "A03:2021-SQL-INJECTION",
    "A03:2021-CMD-INJECTION",
    "A03:2021-LDAP-INJECTION",
    "A03:2021-XPATH-INJECTION",
    "A01:2021-PATH-TRAVERSAL",
    "A02:2021-WEAK-CRYPTO",
    "AC-3-ACCESS-CONTROL",
    "AU-2-EVENT-LOGGING",
    "SC-13-CRYPTOGRAPHIC-PROTECTION",
    "SC-28-PROTECTION-AT-REST",
    "SEMGREP-CWE-79",
    "CODEQL-CWE-502",
    "SONAR-CWE-611",
    "SEMGREP-CWE-352",
  ],
};

export const DEMO_VIOLATIONS: Violation[] = [
  {
    violation_id: "ISO-A.10-WEAK-HASH",
    rule_id: "ISO-A.10-WEAK-HASH",
    target_method: "com.acme.security.AuthService.hashPassword(String)",
    method_key: "demo@v1:AuthService.java#hashPassword",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/security/AuthService.java",
    severity: "HIGH",
    reason: "Weak MD5 cryptographic hash function used in password derivation flow.",
    description: "The authentication service derives password hashes using MD5, which is vulnerable to collision attacks (CWE-328 / OWASP A02).",
    code_snippet: `public String hashPassword(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
    return HexFormat.of().formatHex(digest);
}`,
    snippet_start_line: 42,
    snippet_end_line: 46,
    evidence: {
      source_code: `public String hashPassword(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
    return HexFormat.of().formatHex(digest);
}`,
      graph_context: {
        callers: [
          "com.acme.controller.UserController.register(UserDTO)",
          "com.acme.controller.AuthController.login(Credentials)",
        ],
      },
      vector_context: [
        "com.acme.security.TokenProvider.generateToken()",
        "com.acme.security.PasswordHasher.verifyPassword(String, String)",
      ],
    },
    remediation: {
      supported: true,
      support_tier: "full",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "replace_weak_hash",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Bounded weak-hash replacement with SHA-256 is supported and deterministically verifiable.",
      safe_refusal_possible: false,
    },
  },
  {
    violation_id: "ISO-A.10-WEAK-CRYPTO",
    rule_id: "ISO-A.10-WEAK-CRYPTO",
    target_method: "com.acme.crypto.CipherUtil.encryptPayload(byte[])",
    method_key: "demo@v1:CipherUtil.java#encryptPayload",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/crypto/CipherUtil.java",
    severity: "HIGH",
    reason: "Broken DES cipher in ECB mode used for sensitive payload encryption.",
    description: "DES with ECB mode is structurally insecure against known-plaintext and pattern analysis attacks (CWE-327 / OWASP A02).",
    code_snippet: `public byte[] encryptPayload(byte[] data, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
}`,
    snippet_start_line: 78,
    snippet_end_line: 82,
    evidence: {
      source_code: `public byte[] encryptPayload(byte[] data, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
}`,
      graph_context: {
        callers: [
          "com.acme.service.PaymentGateway.processPayment(Transaction)",
        ],
      },
      vector_context: [
        "com.acme.crypto.KeyManager.deriveKey()",
      ],
    },
    remediation: {
      supported: true,
      support_tier: "full",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "upgrade_aes_gcm",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Bounded upgrade to AES/GCM/NoPadding with authenticated encryption.",
      safe_refusal_possible: false,
    },
  },
  {
    violation_id: "ISO-A.8-SQL-INJECTION",
    rule_id: "ISO-A.8-SQL-INJECTION",
    target_method: "com.acme.repository.AccountRepository.findByUsername(String)",
    method_key: "demo@v1:AccountRepository.java#findByUsername",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/repository/AccountRepository.java",
    severity: "CRITICAL",
    reason: "Dynamic SQL query constructed via raw string concatenation.",
    description: "Unsanitized user-supplied parameter is concatenated directly into SQL statement (CWE-89 / OWASP A03).",
    code_snippet: `public User findByUsername(String username) {
    String sql = "SELECT * FROM accounts WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, new UserRowMapper());
}`,
    snippet_start_line: 34,
    snippet_end_line: 37,
    evidence: {
      source_code: `public User findByUsername(String username) {
    String sql = "SELECT * FROM accounts WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, new UserRowMapper());
}`,
      graph_context: {
        callers: [
          "com.acme.service.AccountService.getUserProfile(String)",
        ],
      },
      vector_context: [
        "com.acme.repository.AccountRepository.findAll()",
      ],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "parameterize_query_requires_review",
      strategy: "parameterize_jdbc_query",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Parameterized query replacement requires guarded developer review before deployment.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "ISO-A.8-PATH-TRAVERSAL",
    rule_id: "ISO-A.8-PATH-TRAVERSAL",
    target_method: "com.acme.storage.FileStorageService.loadFile(String)",
    method_key: "demo@v1:FileStorageService.java#loadFile",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/storage/FileStorageService.java",
    severity: "HIGH",
    reason: "Unvalidated filename passed to file system resolver without path normalization.",
    description: "User input can contain directory traversal sequences like ../ to escape the target directory (CWE-22 / OWASP A01).",
    code_snippet: `public File loadFile(String filename) {
    File baseDir = new File("/var/app/data");
    return new File(baseDir, filename);
}`,
    snippet_start_line: 19,
    snippet_end_line: 22,
    evidence: {
      source_code: `public File loadFile(String filename) {
    File baseDir = new File("/var/app/data");
    return new File(baseDir, filename);
}`,
      graph_context: {
        callers: [
          "com.acme.controller.DocumentController.download(String)",
        ],
      },
      vector_context: [
        "com.acme.storage.FileStorageService.saveFile(String, byte[])",
      ],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "path_normalization_requires_review",
      strategy: "validate_canonical_path",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Path normalization with getCanonicalPath() check proposed for review.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "PCI-6.2.4.1-SQL-INJECTION",
    rule_id: "PCI-6.2.4.1-SQL-INJECTION",
    target_method: "com.acme.payment.CardRepository.findByCardId(String)",
    method_key: "demo@v1:CardRepository.java#findByCardId",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/payment/CardRepository.java",
    severity: "CRITICAL",
    reason: "PCI-DSS 4.0 Req 6.2.4.1: Raw SQL query string concatenation on cardholder data table.",
    description: "Cardholder database query constructed without parameterization, exposing sensitive card data to injection (CWE-89 / PCI-DSS 4.0).",
    code_snippet: `public CreditCard findByCardId(String cardId) throws SQLException {
    String query = "SELECT * FROM cardholder_data WHERE card_id = '" + cardId + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    return mapToCard(rs);
}`,
    snippet_start_line: 25,
    snippet_end_line: 31,
    control_metadata: {
      standard: "PCI-DSS-4.0",
      control: "Req 6.2.4.1",
      title: "PCI-DSS 4.0: SQL Injection Prevention",
      cwes: ["CWE-89"],
    },
    evidence: {
      source_code: `public CreditCard findByCardId(String cardId) throws SQLException {
    String query = "SELECT * FROM cardholder_data WHERE card_id = '" + cardId + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    return mapToCard(rs);
}`,
      graph_context: {
        callers: ["com.acme.payment.PaymentService.charge(PaymentRequest)"],
      },
      taint_paths: [
        {
          sink_type: "sql",
          hops: 3,
          chain: [
            { signature: "com.acme.controller.PaymentController.process(Request)" },
            { signature: "com.acme.payment.PaymentService.charge(PaymentRequest)" },
            { signature: "com.acme.payment.CardRepository.findByCardId(String)" }
          ]
        }
      ],
      vector_context: ["com.acme.payment.CardRepository.saveCard(CreditCard)"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair converts Statement to parameterized PreparedStatement.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "A03:2021-CMD-INJECTION",
    rule_id: "A03:2021-CMD-INJECTION",
    target_method: "com.acme.backup.ArchiveService.createBackup(String)",
    method_key: "demo@v1:ArchiveService.java#createBackup",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/backup/ArchiveService.java",
    severity: "CRITICAL",
    reason: "OWASP A03:2021: System command constructed from unvalidated target directory string.",
    description: "OS command string is executed via Runtime.exec without argument boundary enforcement (CWE-78 / OWASP A03).",
    code_snippet: `public void createBackup(String targetDir) throws Exception {
    String cmd = "tar -czf backup.tar.gz " + targetDir;
    Runtime.getRuntime().exec(cmd);
}`,
    snippet_start_line: 15,
    snippet_end_line: 18,
    control_metadata: {
      standard: "OWASP-2021",
      control: "A03:2021-Injection",
      title: "OWASP Top 10: OS Command Injection",
      cwes: ["CWE-78"],
    },
    evidence: {
      source_code: `public void createBackup(String targetDir) throws Exception {
    String cmd = "tar -czf backup.tar.gz " + targetDir;
    Runtime.getRuntime().exec(cmd);
}`,
      graph_context: {
        callers: ["com.acme.controller.AdminController.runBackup(String)"],
      },
      taint_paths: [
        {
          sink_type: "command",
          hops: 2,
          chain: [
            { signature: "com.acme.controller.AdminController.runBackup(String)" },
            { signature: "com.acme.backup.ArchiveService.createBackup(String)" }
          ]
        }
      ],
      vector_context: ["com.acme.backup.ArchiveService.restoreBackup(String)"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair replaces shell concatenation with ProcessBuilder argument arrays.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "AC-3-ACCESS-CONTROL",
    rule_id: "AC-3-ACCESS-CONTROL",
    target_method: "com.acme.admin.UserAdminController.deleteAccount(Long)",
    method_key: "demo@v1:UserAdminController.java#deleteAccount",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/admin/UserAdminController.java",
    severity: "HIGH",
    reason: "NIST SP 800-53 Rev 5 AC-3: Privileged administrative endpoint missing access enforcement.",
    description: "Privileged endpoint executes destructive account deletion without Spring Security role check (CWE-284 / NIST AC-3).",
    code_snippet: `@DeleteMapping("/users/{id}")
public ResponseEntity<Void> deleteAccount(@PathVariable Long id) {
    userService.deleteUser(id);
    return ResponseEntity.noContent().build();
}`,
    snippet_start_line: 45,
    snippet_end_line: 49,
    control_metadata: {
      standard: "NIST-SP-800-53",
      control: "AC-3",
      title: "NIST SP 800-53: Access Enforcement",
      cwes: ["CWE-284"],
    },
    evidence: {
      source_code: `@DeleteMapping("/users/{id}")
public ResponseEntity<Void> deleteAccount(@PathVariable Long id) {
    userService.deleteUser(id);
    return ResponseEntity.noContent().build();
}`,
      graph_context: {
        annotations: ["DeleteMapping"],
        callers: [],
      },
      vector_context: ["com.acme.admin.UserAdminController.listUsers()"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair inserts @PreAuthorize(\"hasRole('ADMIN')\") and principal validation.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "ISO-A.10-WEAK-RANDOM",
    rule_id: "ISO-A.10-WEAK-RANDOM",
    target_method: "com.acme.security.TokenService.generateSessionToken()",
    method_key: "demo@v1:TokenService.java#generateSessionToken",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/security/TokenService.java",
    severity: "MEDIUM",
    reason: "Insecure java.util.Random used for security-sensitive session token generation.",
    description: "Standard java.util.Random is linearly predictable and must not be used for cryptographically sensitive values (CWE-330 / ISO A.10).",
    code_snippet: `public String generateSessionToken() {
    Random rng = new Random();
    byte[] token = new byte[32];
    rng.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
}`,
    snippet_start_line: 22,
    snippet_end_line: 27,
    control_metadata: {
      standard: "ISO-27001",
      control: "A.10.1",
      title: "Cryptographic Protection: Insecure Randomness",
      cwes: ["CWE-330"],
    },
    evidence: {
      source_code: `public String generateSessionToken() {
    Random rng = new Random();
    byte[] token = new byte[32];
    rng.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
}`,
      graph_context: {
        callers: ["com.acme.security.SessionManager.createSession(User)"],
      },
      vector_context: ["com.acme.security.TokenService.validateSessionToken(String)"],
    },
    remediation: {
      supported: true,
      support_tier: "full",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair replaces Random with java.security.SecureRandom.",
      safe_refusal_possible: false,
    },
  },
  {
    violation_id: "ISO-A.9.4.1",
    rule_id: "ISO-A.9.4.1",
    target_method: "com.acme.controller.UserController.resetPassword(ResetRequest)",
    method_key: "demo@v1:UserController.java#resetPassword",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/controller/UserController.java",
    severity: "HIGH",
    reason: "Public endpoint missing authorization annotation guard.",
    description: "Controller endpoint executes administrative reset without @PreAuthorize or session guard (CWE-284 / ISO A.9.4.1).",
    code_snippet: `@PostMapping("/reset-password")
public ResponseEntity<Void> resetPassword(@RequestBody ResetRequest req) {
    authService.executeReset(req.getEmail());
    return ResponseEntity.ok().build();
}`,
    snippet_start_line: 52,
    snippet_end_line: 56,
    control_metadata: {
      standard: "ISO-27001",
      control: "A.9.4.1",
      title: "Access Control for Applications",
      cwes: ["CWE-284"],
    },
    evidence: {
      source_code: `@PostMapping("/reset-password")
public ResponseEntity<Void> resetPassword(@RequestBody ResetRequest req) {
    authService.executeReset(req.getEmail());
    return ResponseEntity.ok().build();
}`,
      graph_context: {
        annotations: ["PostMapping"],
        callers: [],
      },
      vector_context: ["com.acme.controller.UserController.updateProfile(ProfileDTO)"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair adds @PreAuthorize and principal validation.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "PCI-6.2.4.2-PATH-TRAVERSAL",
    rule_id: "PCI-6.2.4.2-PATH-TRAVERSAL",
    target_method: "com.acme.statement.StatementStorage.getStatementPdf(String)",
    method_key: "demo@v1:StatementStorage.java#getStatementPdf",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/statement/StatementStorage.java",
    severity: "HIGH",
    reason: "PCI-DSS 4.0 Req 6.2.4.2: Unsanitized file path parameter in statement retrieval.",
    description: "Cardholder statement document lookup vulnerable to path traversal (CWE-22 / PCI-DSS 4.0).",
    code_snippet: `public byte[] getStatementPdf(String filename) throws IOException {
    File statement = new File("/var/statements/" + filename);
    return Files.readAllBytes(statement.toPath());
}`,
    snippet_start_line: 30,
    snippet_end_line: 33,
    control_metadata: {
      standard: "PCI-DSS-4.0",
      control: "Req 6.2.4.2",
      title: "PCI-DSS 4.0: Path Traversal Prevention",
      cwes: ["CWE-22"],
    },
    evidence: {
      source_code: `public byte[] getStatementPdf(String filename) throws IOException {
    File statement = new File("/var/statements/" + filename);
    return Files.readAllBytes(statement.toPath());
}`,
      graph_context: {
        callers: ["com.acme.controller.StatementController.download(String)"],
      },
      vector_context: ["com.acme.statement.StatementStorage.saveStatement(byte[])"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair enforces canonical path boundary check.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "PCI-3.4.1-WEAK-CRYPTO",
    rule_id: "PCI-3.4.1-WEAK-CRYPTO",
    target_method: "com.acme.payment.PANEncryptionService.encryptPAN(String)",
    method_key: "demo@v1:PANEncryptionService.java#encryptPAN",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/payment/PANEncryptionService.java",
    severity: "CRITICAL",
    reason: "PCI-DSS 4.0 Req 3.4.1: Primary Account Number (PAN) encrypted using deprecated 3DES cipher.",
    description: "Cardholder data encrypted with weak 3DES algorithm prohibited under PCI-DSS 4.0 (CWE-327 / PCI-DSS 4.0).",
    code_snippet: `public byte[] encryptPAN(String pan) throws Exception {
    Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    return cipher.doFinal(pan.getBytes(StandardCharsets.UTF_8));
}`,
    snippet_start_line: 40,
    snippet_end_line: 44,
    control_metadata: {
      standard: "PCI-DSS-4.0",
      control: "Req 3.4.1",
      title: "PCI-DSS 4.0: Strong Cryptography for PAN",
      cwes: ["CWE-327"],
    },
    evidence: {
      source_code: `public byte[] encryptPAN(String pan) throws Exception {
    Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
    return cipher.doFinal(pan.getBytes(StandardCharsets.UTF_8));
}`,
      graph_context: {
        callers: ["com.acme.payment.CardStorageService.storeCard(CardDTO)"],
      },
      vector_context: ["com.acme.payment.PANEncryptionService.decryptPAN(byte[])"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair upgrades 3DES to AES-256 GCM authenticated encryption.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "PCI-3.4.2-WEAK-HASH",
    rule_id: "PCI-3.4.2-WEAK-HASH",
    target_method: "com.acme.transaction.TransactionVerifier.computeChecksum(Transaction)",
    method_key: "demo@v1:TransactionVerifier.java#computeChecksum",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/transaction/TransactionVerifier.java",
    severity: "HIGH",
    reason: "PCI-DSS 4.0 Req 3.4.2: Deprecated MD5 hash used for payment transaction integrity checksum.",
    description: "Transaction verification uses MD5 which is vulnerable to preimage attacks (CWE-328 / PCI-DSS 4.0).",
    code_snippet: `public String computeChecksum(Transaction tx) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    return Hex.encodeHexString(md.digest(tx.getPayload()));
}`,
    snippet_start_line: 18,
    snippet_end_line: 21,
    control_metadata: {
      standard: "PCI-DSS-4.0",
      control: "Req 3.4.2",
      title: "PCI-DSS 4.0: Strong One-Way Hash",
      cwes: ["CWE-328"],
    },
    evidence: {
      source_code: `public String computeChecksum(Transaction tx) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    return Hex.encodeHexString(md.digest(tx.getPayload()));
}`,
      graph_context: {
        callers: ["com.acme.transaction.TransactionService.verify(Transaction)"],
      },
      vector_context: ["com.acme.transaction.TransactionVerifier.validateSignature(Transaction)"],
    },
    remediation: {
      supported: true,
      support_tier: "full",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair replaces MD5 with SHA-256.",
      safe_refusal_possible: false,
    },
  },
  {
    violation_id: "PCI-8.3.1-WEAK-RANDOM",
    rule_id: "PCI-8.3.1-WEAK-RANDOM",
    target_method: "com.acme.auth.MfaTokenGenerator.generateOtpCode()",
    method_key: "demo@v1:MfaTokenGenerator.java#generateOtpCode",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/auth/MfaTokenGenerator.java",
    severity: "HIGH",
    reason: "PCI-DSS 4.0 Req 8.3.1: Non-cryptographic Math.random used for multi-factor authentication token.",
    description: "MFA code generated with predictable Math.random() allowing token guessing (CWE-330 / PCI-DSS 4.0).",
    code_snippet: `public int generateOtpCode() {
    return 100000 + (int)(Math.random() * 900000);
}`,
    snippet_start_line: 12,
    snippet_end_line: 14,
    control_metadata: {
      standard: "PCI-DSS-4.0",
      control: "Req 8.3.1",
      title: "PCI-DSS 4.0: Strong Cryptographic RNG for MFA",
      cwes: ["CWE-330"],
    },
    evidence: {
      source_code: `public int generateOtpCode() {
    return 100000 + (int)(Math.random() * 900000);
}`,
      graph_context: {
        callers: ["com.acme.auth.MfaService.sendOtp(User)"],
      },
      vector_context: ["com.acme.auth.MfaTokenGenerator.verifyOtp(User, int)"],
    },
    remediation: {
      supported: true,
      support_tier: "full",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair replaces Math.random with SecureRandom.",
      safe_refusal_possible: false,
    },
  },
  {
    violation_id: "A03:2021-LDAP-INJECTION",
    rule_id: "A03:2021-LDAP-INJECTION",
    target_method: "com.acme.directory.LdapAuthenticator.findUser(String)",
    method_key: "demo@v1:LdapAuthenticator.java#findUser",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/directory/LdapAuthenticator.java",
    severity: "HIGH",
    reason: "OWASP A03:2021: Unsanitized user string interpolated into LDAP search filter.",
    description: "LDAP search filter constructed via concatenation, permitting directory authentication bypass (CWE-90 / OWASP A03).",
    code_snippet: `public SearchResult findUser(String username) throws NamingException {
    String filter = "(&(objectClass=user)(sAMAccountName=" + username + "))";
    return dirContext.search("dc=acme,dc=com", filter, new SearchControls());
}`,
    snippet_start_line: 28,
    snippet_end_line: 31,
    control_metadata: {
      standard: "OWASP-2021",
      control: "A03:2021-Injection",
      title: "OWASP Top 10: LDAP Search Filter Injection",
      cwes: ["CWE-90"],
    },
    evidence: {
      source_code: `public SearchResult findUser(String username) throws NamingException {
    String filter = "(&(objectClass=user)(sAMAccountName=" + username + "))";
    return dirContext.search("dc=acme,dc=com", filter, new SearchControls());
}`,
      graph_context: {
        callers: ["com.acme.directory.DirectoryService.authenticate(Credentials)"],
      },
      vector_context: ["com.acme.directory.LdapAuthenticator.findGroup(String)"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair applies RFC 4515 LDAP filter escaping.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "A03:2021-XPATH-INJECTION",
    rule_id: "A03:2021-XPATH-INJECTION",
    target_method: "com.acme.xml.XmlReportParser.extractUserNode(String)",
    method_key: "demo@v1:XmlReportParser.java#extractUserNode",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/xml/XmlReportParser.java",
    severity: "HIGH",
    reason: "OWASP A03:2021: Dynamic XPath query concatenated with untrusted user input.",
    description: "XPath query expression constructed dynamically, allowing extraction of sensitive XML nodes (CWE-643 / OWASP A03).",
    code_snippet: `public Node extractUserNode(String role) throws XPathExpressionException {
    String query = "/users/user[@role='" + role + "']";
    return (Node) xpath.evaluate(query, doc, XPathConstants.NODE);
}`,
    snippet_start_line: 20,
    snippet_end_line: 23,
    control_metadata: {
      standard: "OWASP-2021",
      control: "A03:2021-Injection",
      title: "OWASP Top 10: XPath Injection",
      cwes: ["CWE-643"],
    },
    evidence: {
      source_code: `public Node extractUserNode(String role) throws XPathExpressionException {
    String query = "/users/user[@role='" + role + "']";
    return (Node) xpath.evaluate(query, doc, XPathConstants.NODE);
}`,
      graph_context: {
        callers: ["com.acme.xml.ReportService.parseUserReport(Document)"],
      },
      vector_context: ["com.acme.xml.XmlReportParser.extractConfigNode()"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair binds XPath variables via XPathVariableResolver.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "AU-2-EVENT-LOGGING",
    rule_id: "AU-2-EVENT-LOGGING",
    target_method: "com.acme.transfer.TransferAuditService.executeTransfer(TransferRequest)",
    method_key: "demo@v1:TransferAuditService.java#executeTransfer",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/transfer/TransferAuditService.java",
    severity: "MEDIUM",
    reason: "NIST SP 800-53 Rev 5 AU-2: Financial transfer transaction missing security event audit log.",
    description: "Critical state-changing transaction executes without recording audit trail log (CWE-778 / NIST AU-2).",
    code_snippet: `public TransferResult executeTransfer(TransferRequest req) {
    accountService.debit(req.getFrom(), req.getAmount());
    accountService.credit(req.getTo(), req.getAmount());
    return TransferResult.success();
}`,
    snippet_start_line: 35,
    snippet_end_line: 39,
    control_metadata: {
      standard: "NIST-SP-800-53",
      control: "AU-2",
      title: "NIST SP 800-53: Event Logging",
      cwes: ["CWE-778"],
    },
    evidence: {
      source_code: `public TransferResult executeTransfer(TransferRequest req) {
    accountService.debit(req.getFrom(), req.getAmount());
    accountService.credit(req.getTo(), req.getAmount());
    return TransferResult.success();
}`,
      graph_context: {
        callers: ["com.acme.controller.TransferController.processTransfer(TransferRequest)"],
      },
      vector_context: ["com.acme.transfer.TransferAuditService.getAuditTrail()"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair adds structured logger.info security audit trail.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "SC-13-CRYPTOGRAPHIC-PROTECTION",
    rule_id: "SC-13-CRYPTOGRAPHIC-PROTECTION",
    target_method: "com.acme.crypto.SignatureValidator.verifySignature(byte[], byte[])",
    method_key: "demo@v1:SignatureValidator.java#verifySignature",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/crypto/SignatureValidator.java",
    severity: "HIGH",
    reason: "NIST SP 800-53 Rev 5 SC-13: Cryptographic protection using deprecated SHA1withRSA algorithm.",
    description: "Digital signature verification relies on SHA-1 which is disallowed by federal cryptographic standards (CWE-328 / NIST SC-13).",
    code_snippet: `public boolean verifySignature(byte[] data, byte[] sig) throws Exception {
    Signature signature = Signature.getInstance("SHA1withRSA");
    signature.initVerify(publicKey);
    signature.update(data);
    return signature.verify(sig);
}`,
    snippet_start_line: 24,
    snippet_end_line: 29,
    control_metadata: {
      standard: "NIST-SP-800-53",
      control: "SC-13",
      title: "NIST SP 800-53: Cryptographic Protection",
      cwes: ["CWE-328"],
    },
    evidence: {
      source_code: `public boolean verifySignature(byte[] data, byte[] sig) throws Exception {
    Signature signature = Signature.getInstance("SHA1withRSA");
    signature.initVerify(publicKey);
    signature.update(data);
    return signature.verify(sig);
}`,
      graph_context: {
        callers: ["com.acme.service.DocumentSigningService.validate(SignedDoc)"],
      },
      vector_context: ["com.acme.crypto.SignatureValidator.signData(byte[])"],
    },
    remediation: {
      supported: true,
      support_tier: "full",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair upgrades SHA1withRSA to SHA256withRSA.",
      safe_refusal_possible: false,
    },
  },
  {
    violation_id: "CODEQL-CWE-502",
    rule_id: "CODEQL-CWE-502",
    target_method: "com.acme.io.PayloadDeserializer.readPayload(byte[])",
    method_key: "demo@v1:PayloadDeserializer.java#readPayload",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/io/PayloadDeserializer.java",
    severity: "CRITICAL",
    reason: "Universal SAST (CodeQL): Deserialization of untrusted Java ObjectInputStream data.",
    description: "Raw ObjectInputStream deserialization allows remote code execution via gadget chains (CWE-502 / CodeQL java/unsafe-deserialization).",
    code_snippet: `public Object readPayload(byte[] bytes) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
    return ois.readObject();
}`,
    snippet_start_line: 16,
    snippet_end_line: 19,
    control_metadata: {
      standard: "SAST-SARIF",
      control: "CWE-502",
      title: "Universal SAST: Insecure Deserialization",
      cwes: ["CWE-502"],
    },
    evidence: {
      imported_from_sarif: true,
      source_code: `public Object readPayload(byte[] bytes) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
    return ois.readObject();
}`,
      graph_context: {
        callers: ["com.acme.messaging.QueueListener.onMessage(byte[])"],
      },
      vector_context: ["com.acme.io.PayloadDeserializer.writePayload(Object)"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair applies ValidatingObjectInputStream class filtering.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "SONAR-CWE-611",
    rule_id: "SONAR-CWE-611",
    target_method: "com.acme.config.XmlConfigReader.loadXml(InputStream)",
    method_key: "demo@v1:XmlConfigReader.java#loadXml",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/config/XmlConfigReader.java",
    severity: "HIGH",
    reason: "Universal SAST (SonarQube): XML External Entity (XXE) vulnerability in DocumentBuilderFactory.",
    description: "DocumentBuilderFactory instantiated without disabling external general entities (CWE-611 / Sonar java:S2755).",
    code_snippet: `public Document loadXml(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    return dbf.newDocumentBuilder().parse(in);
}`,
    snippet_start_line: 14,
    snippet_end_line: 17,
    control_metadata: {
      standard: "SAST-SARIF",
      control: "CWE-611",
      title: "Universal SAST: XML External Entity (XXE)",
      cwes: ["CWE-611"],
    },
    evidence: {
      imported_from_sarif: true,
      source_code: `public Document loadXml(InputStream in) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    return dbf.newDocumentBuilder().parse(in);
}`,
      graph_context: {
        callers: ["com.acme.config.AppConfigLoader.init()"],
      },
      vector_context: ["com.acme.config.XmlConfigReader.writeXml(Document)"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair sets disallow-doctype-decl and external-general-entities feature flags.",
      safe_refusal_possible: true,
    },
  },
  {
    violation_id: "SEMGREP-CWE-352",
    rule_id: "SEMGREP-CWE-352",
    target_method: "com.acme.controller.ProfileUpdateController.updateEmail(String)",
    method_key: "demo@v1:ProfileUpdateController.java#updateEmail",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/controller/ProfileUpdateController.java",
    severity: "MEDIUM",
    reason: "Universal SAST (Semgrep): State-changing POST endpoint missing CSRF token check.",
    description: "Sensitive account mutation endpoint does not enforce CSRF protection (CWE-352 / Semgrep java.spring.csrf-disabled).",
    code_snippet: `@PostMapping("/user/update-email")
public ResponseEntity<Void> updateEmail(@RequestParam String email) {
    userProfileService.changeEmail(email);
    return ResponseEntity.ok().build();
}`,
    snippet_start_line: 22,
    snippet_end_line: 26,
    control_metadata: {
      standard: "SAST-SARIF",
      control: "CWE-352",
      title: "Universal SAST: Cross-Site Request Forgery (CSRF)",
      cwes: ["CWE-352"],
    },
    evidence: {
      imported_from_sarif: true,
      source_code: `@PostMapping("/user/update-email")
public ResponseEntity<Void> updateEmail(@RequestParam String email) {
    userProfileService.changeEmail(email);
    return ResponseEntity.ok().build();
}`,
      graph_context: {
        annotations: ["PostMapping"],
        callers: [],
      },
      vector_context: ["com.acme.controller.ProfileUpdateController.getProfile()"],
    },
    remediation: {
      supported: true,
      support_tier: "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair ensures CSRF token requirement.",
      safe_refusal_possible: true,
    },
  },
];

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

export const DEMO_EXPLANATION: PolicyExplainOneResponse = {
  status: "OK",
  explanation:
    "### Neurosymbolic Root Cause Analysis\n\nThe target method `com.acme.security.AuthService.hashPassword(String)` instantiates `MessageDigest.getInstance(\"MD5\")` on line 43. MD5 is cryptographically broken due to practical collision attacks, violating **ISO 27001 A.10.1** and **OWASP A02:2021**.\n\n### Call Graph Context\n- Invoked directly by `UserController.register()` and `AuthController.login()`.\n- Replacing with SHA-256 preserves the return type (`String` hex digest) while restoring cryptographic preimage resistance.",
  explanation_structured: {
    evidence_id: "E1-SRC-HASH",
    citation: "AuthService.java:43 -> MessageDigest.getInstance(\"MD5\")",
    why: "MD5 cryptographic hash is prone to collision and preimage attacks.",
    fix: "Replace MessageDigest algorithm with SHA-256 and update digest length expectations.",
  },
  model: "claude-sonnet-3.7 (demo)",
  include_graph_context: true,
};

export const DEMO_DIFFS: Record<string, string> = {
  "ISO-A.10-WEAK-HASH": `@@ -42,5 +42,5 @@
 public String hashPassword(String password) throws Exception {
-    MessageDigest md = MessageDigest.getInstance("MD5");
+    MessageDigest md = MessageDigest.getInstance("SHA-256");
     byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));
     return HexFormat.of().formatHex(digest);
 }`,
  "ISO-A.10-WEAK-CRYPTO": `@@ -78,5 +78,6 @@
 public byte[] encryptPayload(byte[] data, SecretKey key) throws Exception {
-    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
-    cipher.init(Cipher.ENCRYPT_MODE, key);
+    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
+    GCMParameterSpec spec = new GCMParameterSpec(128, getSecureIV());
+    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
     return cipher.doFinal(data);
 }`,
  "ISO-A.8-SQL-INJECTION": `@@ -34,4 +34,4 @@
 public User findByUsername(String username) {
-    String sql = "SELECT * FROM accounts WHERE username = '" + username + "'";
-    return jdbcTemplate.queryForObject(sql, new UserRowMapper());
+    String sql = "SELECT * FROM accounts WHERE username = ?";
+    return jdbcTemplate.queryForObject(sql, new UserRowMapper(), username);
 }`,
  "ISO-A.8-PATH-TRAVERSAL": `@@ -19,4 +19,8 @@
 public File loadFile(String filename) {
     File baseDir = new File("/var/app/data");
-    return new File(baseDir, filename);
+    File target = new File(baseDir, filename);
+    if (!target.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
+        throw new SecurityException("Invalid path traversal sequence");
+    }
+    return target;
 }`,
};

export const DEMO_PREVIEWS: Record<string, RemediationPreviewResponse> = {
  "ISO-A.10-WEAK-HASH": {
    status: "OK",
    violation_id: "ISO-A.10-WEAK-HASH",
    rule_id: "ISO-A.10-WEAK-HASH",
    target_method: "com.acme.security.AuthService.hashPassword(String)",
    file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/security/AuthService.java",
    diff: DEMO_DIFFS["ISO-A.10-WEAK-HASH"],
    confidence: {
      score: 0.95,
      band: "apply",
      threshold_apply: 0.75,
      threshold_review: 0.5,
      rationale: "High-confidence bounded replacement: standard SHA-256 API equivalence verified.",
    },
    error: null,
  },
};

export const DEMO_APPLY_RESULT: RemediationApplyResponse = {
  status: "OK",
  violation_id: "ISO-A.10-WEAK-HASH",
  rule_id: "ISO-A.10-WEAK-HASH",
  target_method: "com.acme.security.AuthService.hashPassword(String)",
  file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/security/AuthService.java",
  diff: DEMO_DIFFS["ISO-A.10-WEAK-HASH"],
  verification: {
    overall_status: "PASS",
    target_rule_status: "PASS",
    remaining_violations: [],
    new_violations: [],
  },
  compilation: {
    attempted: true,
    success: true,
  },
  generation: {
    raw_response_valid: true,
    decision: "apply_edits",
    reason: "Weak MD5 hash algorithm successfully replaced with SHA-256. Code compiles with 0 errors and passes OPA symbolic re-verification.",
  },
  confidence: {
    score: 0.95,
    band: "apply",
    threshold_apply: 0.75,
    threshold_review: 0.5,
    rationale: "High-confidence bounded replacement.",
  },
  error: null,
};

export const DEMO_SEARCH_MATCHES: SearchResponse = {
  matches: [
    "demo@v1:AuthService.java#hashPassword",
    "demo@v1:CipherUtil.java#encryptPayload",
    "demo@v1:AccountRepository.java#findByUsername",
    "demo@v1:FileStorageService.java#loadFile",
  ],
  contexts: [
    [
      {
        method: "com.acme.security.AuthService.hashPassword(String)",
        neighbors: [
          { name: "UserController.register", type: "CALLER" },
          { name: "AuthController.login", type: "CALLER" },
        ],
      },
    ],
    [
      {
        method: "com.acme.crypto.CipherUtil.encryptPayload(byte[], SecretKey)",
        neighbors: [
          { name: "PaymentGateway.processPayment", type: "CALLER" },
        ],
      },
    ],
    [
      {
        method: "com.acme.repository.AccountRepository.findByUsername(String)",
        neighbors: [
          { name: "AccountService.getUserProfile", type: "CALLER" },
        ],
      },
    ],
    [
      {
        method: "com.acme.storage.FileStorageService.loadFile(String)",
        neighbors: [
          { name: "DocumentController.download", type: "CALLER" },
        ],
      },
    ],
  ],
};

export const DEMO_UPLOAD_RESPONSE: UploadResponse = {
  status: "Codebase processed successfully in demo mode.",
  java_root: "/tmp/uploaded_code/app/src/main/java",
  java_roots: [
    "/tmp/uploaded_code/app/src/main/java",
    "/tmp/uploaded_code/core/src/main/java",
  ],
  request_id: "demo-upload-req-1",
};

export const DEMO_UPLOAD_STATUS: UploadStatus = {
  phase: "complete",
  message: "Demo workspace indexed: 42 methods, 4 policy violations detected.",
  progress: 100,
  complete: true,
  error: null,
  updated_at: new Date().toISOString(),
  started_at: new Date(Date.now() - 5000).toISOString(),
  request_id: "demo-upload-req-1",
};

export const DEMO_AGENTIC_RESULT: AgenticRemediationResponse = {
  status: "SUCCESS",
  rule_id: "ISO-A.8-SQL-INJECTION",
  method_key: "demo@v1:AccountRepository.java#findByUsername",
  target_method: "com.acme.repository.AccountRepository.findByUsername(String)",
  workspace_root: "/tmp/uploaded_code/app",
  modified_files: [
    "src/main/java/com/acme/repository/AccountRepository.java",
  ],
  diff: `--- a/src/main/java/com/acme/repository/AccountRepository.java
+++ b/src/main/java/com/acme/repository/AccountRepository.java
@@ -4,6 +4,7 @@
 import java.sql.ResultSet;
 import java.sql.Statement;
+import java.sql.PreparedStatement;
 
 public class AccountRepository {
     public User findByUsername(Connection conn, String username) throws SQLException {
-        Statement stmt = conn.createStatement();
-        String sql = "SELECT * FROM accounts WHERE username = '" + username + "'";
-        ResultSet rs = stmt.executeQuery(sql);
+        String sql = "SELECT * FROM accounts WHERE username = ?";
+        PreparedStatement stmt = conn.prepareStatement(sql);
+        stmt.setString(1, username);
+        ResultSet rs = stmt.executeQuery();
         if (rs.next()) {
             return new User(rs.getString("username"), rs.getString("email"));
         }`,
  verification: {
    all_passed: true,
    compile_passed: true,
    compile_output: "0 compilation errors",
    tests_passed: true,
    test_output: "All 18 project unit tests passed",
    policy_passed: true,
    remaining_violations: [],
    policy_findings: [],
  },
  reason: "Autonomous multi-turn agent successfully refactored string-concatenated SQL query into a parameterized PreparedStatement with typed parameter bindings, verified with Eclipse JDT compilation + project unit tests + OPA policy clearance.",
  iterations: 3,
  turns_count: 3,
  error: null,
};

export const DEMO_SARIF_DOCUMENT: SarifExportResponse = {
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "CodeGraph Policy Engine",
          version: "0.6.0",
          informationUri: "https://github.com/daniel-volpin/codegraph-rego",
          rules: [
            {
              id: "ISO-A.10-WEAK-HASH",
              name: "WeakHashAlgorithm",
              shortDescription: { text: "Weak Hash Algorithm (MD5/SHA-1)" },
              defaultConfiguration: { level: "error" },
            },
            {
              id: "ISO-A.10-WEAK-CRYPTO",
              name: "WeakCryptographicCipher",
              shortDescription: { text: "Broken / Deprecated Cryptographic Cipher (DES/ECB)" },
              defaultConfiguration: { level: "error" },
            },
            {
              id: "ISO-A.8-SQL-INJECTION",
              name: "SqlInjectionConcatenation",
              shortDescription: { text: "SQL Injection via Concatenation" },
              defaultConfiguration: { level: "error" },
            },
            {
              id: "ISO-A.8-PATH-TRAVERSAL",
              name: "PathTraversal",
              shortDescription: { text: "Arbitrary Path Traversal via User Input" },
              defaultConfiguration: { level: "error" },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "ISO-A.10-WEAK-HASH",
          level: "error",
          message: { text: "Weak MD5 hash algorithm detected." },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/main/java/com/acme/security/AuthService.java" },
                region: { startLine: 42, endLine: 45 },
              },
            },
          ],
        },
        {
          ruleId: "ISO-A.8-SQL-INJECTION",
          level: "error",
          message: { text: "Dynamic SQL query constructed via raw string concatenation." },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/main/java/com/acme/repository/AccountRepository.java" },
                region: { startLine: 34, endLine: 37 },
              },
            },
          ],
        },
      ],
    },
  ],
};

export const DEMO_POLICY_PACKS = {
  status: "OK",
  packs: [
    {
      pack_id: "iso-27001",
      name: "ISO/IEC 27001 Benchmark Security Policy Pack",
      standard: "ISO-27001",
      version: "1.0.0",
      query_entrypoints: ["data.iso27001.violations"],
      enabled: true,
      description: "Default security and compliance rules for OWASP Benchmark controls.",
      rules_count: 8,
      rules: [],
    },
    {
      pack_id: "pci-dss-4.0",
      name: "Payment Card Industry Data Security Standard (PCI-DSS) v4.0",
      standard: "PCI-DSS-4.0",
      version: "4.0.0",
      query_entrypoints: ["data.iso27001.violations"],
      enabled: true,
      description: "Compliance rules enforcing PCI-DSS v4.0 secure software development standards.",
      rules_count: 6,
      rules: [],
    },
    {
      pack_id: "owasp-top10-2021",
      name: "OWASP Top 10 Application Security Risks (2021)",
      standard: "OWASP-2021",
      version: "2021.1.0",
      query_entrypoints: ["data.iso27001.violations"],
      enabled: true,
      description: "Compliance rules aligned with the OWASP Top 10 (2021) standard categories.",
      rules_count: 8,
      rules: [],
    },
    {
      pack_id: "nist-sp-800-53",
      name: "NIST SP 800-53 Rev 5 Security Controls",
      standard: "NIST-800-53",
      version: "5.1.0",
      query_entrypoints: ["data.iso27001.violations"],
      enabled: true,
      description: "Security and privacy controls for federal and enterprise information systems.",
      rules_count: 5,
      rules: [],
    },
  ],
};

export const DEMO_SARIF_IMPORT = {
  status: "OK",
  count: 2,
  violations: DEMO_VIOLATIONS.slice(0, 2),
};
