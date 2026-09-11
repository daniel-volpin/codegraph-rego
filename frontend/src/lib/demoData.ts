import type {
  HealthCheckResponse,
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  PolicyExplainOneResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  SearchResponse,
  UploadResponse,
  UploadStatus,
  Violation,
} from "./schemas";

export const DEMO_HEALTH: HealthCheckResponse = {
  status: "ok",
  startup_ready: true,
  neo4j: true,
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
      rego_rules: ["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-CRYPTO"],
    },
    {
      control_id: "ISO-A.8.2",
      title: "Privileged Access and Injection Prevention",
      rego_rules: ["ISO-A.8-SQL-INJECTION", "ISO-A.8-PATH-TRAVERSAL"],
    },
  ],
  rules: [
    {
      rule_id: "ISO-A.10-WEAK-HASH",
      title: "Weak Hash Algorithm (MD5/SHA-1)",
      severity: "HIGH",
      cwe: "CWE-328",
      frameworks: ["ISO 27001", "OWASP A02:2021"],
      remediation_strategy: "replace_weak_hash",
      remediation_tier: "full",
    },
    {
      rule_id: "ISO-A.10-WEAK-CRYPTO",
      title: "Broken / Deprecated Cryptographic Cipher (DES/ECB)",
      severity: "HIGH",
      cwe: "CWE-327",
      frameworks: ["ISO 27001", "OWASP A02:2021"],
      remediation_strategy: "upgrade_aes_gcm",
      remediation_tier: "full",
    },
    {
      rule_id: "ISO-A.8-SQL-INJECTION",
      title: "SQL Injection via Concatenation",
      severity: "CRITICAL",
      cwe: "CWE-89",
      frameworks: ["ISO 27001", "OWASP A03:2021"],
      remediation_strategy: "parameterize_jdbc_query",
      remediation_tier: "guarded",
    },
    {
      rule_id: "ISO-A.8-PATH-TRAVERSAL",
      title: "Arbitrary Path Traversal via User Input",
      severity: "HIGH",
      cwe: "CWE-22",
      frameworks: ["ISO 27001", "OWASP A01:2021"],
      remediation_strategy: "validate_canonical_path",
      remediation_tier: "guarded",
    },
  ],
  benchmark_categories: [
    {
      category_id: "crypto-compliance",
      label: "Cryptographic Compliance",
      cwes: ["CWE-328", "CWE-327"],
      rego_rule_ids: ["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-CRYPTO"],
      control_ids: ["ISO-A.10.1"],
      remediation_tier: "full",
      framework_demo: true,
    },
    {
      category_id: "injection-compliance",
      label: "Injection & Input Validation",
      cwes: ["CWE-89", "CWE-22"],
      rego_rule_ids: ["ISO-A.8-SQL-INJECTION", "ISO-A.8-PATH-TRAVERSAL"],
      control_ids: ["ISO-A.8.2"],
      remediation_tier: "guarded",
      framework_demo: true,
    },
  ],
  framework_demo_rule_ids: [
    "ISO-A.10-WEAK-HASH",
    "ISO-A.10-WEAK-CRYPTO",
    "ISO-A.8-SQL-INJECTION",
    "ISO-A.8-PATH-TRAVERSAL",
  ],
};

export const DEMO_VIOLATIONS: Violation[] = [
  {
    violation_id: "ISO-A.10-WEAK-HASH",
    rule_id: "ISO-A.10-WEAK-HASH",
    target_method: "com.acme.security.AuthService.hashPassword(String)",
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
];

export const DEMO_POLICY_EVALUATION: PolicyEvaluateResponse = {
  violations: DEMO_VIOLATIONS,
  opa_output: {
    evaluated_rules: 4,
    passed_rules: 0,
    violated_rules: 4,
    execution_time_ms: 18.4,
  },
  enriched: DEMO_VIOLATIONS.map((v) => ({
    violation_id: v.violation_id,
    cwe: v.rule_id === "ISO-A.10-WEAK-HASH" ? "CWE-328" : "CWE-327",
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
    "com.acme.security.AuthService.hashPassword(String)",
    "com.acme.crypto.CipherUtil.encryptPayload(byte[], SecretKey)",
    "com.acme.repository.AccountRepository.findByUsername(String)",
    "com.acme.storage.FileStorageService.loadFile(String)",
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
