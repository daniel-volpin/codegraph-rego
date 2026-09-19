import type {
  AgenticRemediationResponse,
  PolicyExplainOneResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  SarifExportResponse,
  SarifImportResponse,
  SearchResponse,
  UploadResponse,
  UploadStatus,
} from "../schemas";
import { DEMO_VIOLATIONS } from "./violations";

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
     cipher.init(Cipher.ENCRYPT_MODE, key, spec);
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
        throw new SecurityException("Invalid path traversal sequence");
     }
     return target;
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
         ResultSet rs = stmt.executeQuery();
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

export const DEMO_EXPLANATION: PolicyExplainOneResponse = {
  status: "OK",
  explanation:
    "### Neurosymbolic Root Cause Analysis\n\nThe target method `com.acme.security.AuthService.hashPassword(String)` instantiates `MessageDigest.getInstance(\"MD5\")` on line 42. MD5 is cryptographically broken due to practical collision attacks, violating **ISO 27001 Control A.10** and **OWASP A02:2021**.\n\n### Call Graph Context\n- Invoked directly by `AuthController.register()` and `AuthController.login()`.\n- Replacing with SHA-256 preserves the return type (`String` hex digest) while restoring cryptographic preimage resistance.",
  explanation_structured: {
    evidence_id: "E1-SRC-HASH",
    citation: "AuthService.java:42 -> MessageDigest.getInstance(\"MD5\")",
    why: "MD5 cryptographic hash is prone to collision and preimage attacks.",
    fix: "Replace MessageDigest algorithm with SHA-256 and update digest length expectations.",
  },
  model: "qwen/qwen3.8-27b (demo)",
  include_graph_context: true,
};

export const DEMO_SEARCH_MATCHES: SearchResponse = {
  matches: [
    "demo@v1:AuthService.java#hashPassword",
    "demo@v1:CipherUtil.java#encryptPayload",
    "demo@v1:AccountRepository.java#findByUsername",
    "demo@v1:FileStorageService.java#loadFile",
  ],
  contexts: [
    [{ method: "com.acme.security.AuthService.hashPassword(String)", neighbors: [{ name: "AuthController.login", type: "CALLER" }] }],
    [{ method: "com.acme.crypto.CipherUtil.encryptPayload(byte[], SecretKey)", neighbors: [{ name: "PaymentGateway.processPayment", type: "CALLER" }] }],
    [{ method: "com.acme.repository.AccountRepository.findByUsername(String)", neighbors: [{ name: "AccountService.getUserProfile", type: "CALLER" }] }],
    [{ method: "com.acme.storage.FileStorageService.loadFile(String)", neighbors: [{ name: "DocumentController.download", type: "CALLER" }] }],
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
  message: "Demo workspace indexed: 42 methods, 24 policy violations detected across 4 compliance standards.",
  progress: 100,
  complete: true,
  error: null,
  updated_at: new Date().toISOString(),
  started_at: new Date(Date.now() - 5000).toISOString(),
  request_id: "demo-upload-req-1",
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
            { id: "ISO-A.10-WEAK-HASH", name: "WeakHashAlgorithm", shortDescription: { text: "Weak Cryptographic Hash (MD5/SHA-1)" }, defaultConfiguration: { level: "error" } },
            { id: "ISO-A.10-WEAK-CRYPTO", name: "WeakCryptographicCipher", shortDescription: { text: "Insecure Cryptographic Cipher (DES/ECB)" }, defaultConfiguration: { level: "error" } },
            { id: "ISO-A.8-SQL-INJECTION", name: "SqlInjectionConcatenation", shortDescription: { text: "Dynamic SQL Injection via Concatenation" }, defaultConfiguration: { level: "error" } },
            { id: "ISO-A.8-PATH-TRAVERSAL", name: "PathTraversal", shortDescription: { text: "Arbitrary Path Traversal via Unvalidated Path" }, defaultConfiguration: { level: "error" } },
          ],
        },
      },
      results: [
        {
          ruleId: "ISO-A.10-WEAK-HASH",
          level: "error",
          message: { text: "Weak MD5 hash algorithm detected." },
          locations: [{ physicalLocation: { artifactLocation: { uri: "src/main/java/com/acme/security/AuthService.java" }, region: { startLine: 42, endLine: 45 } } }],
        },
        {
          ruleId: "ISO-A.8-SQL-INJECTION",
          level: "error",
          message: { text: "Dynamic SQL query constructed via raw string concatenation." },
          locations: [{ physicalLocation: { artifactLocation: { uri: "src/main/java/com/acme/repository/AccountRepository.java" }, region: { startLine: 34, endLine: 37 } } }],
        },
      ],
    },
  ],
};

export const DEMO_SARIF_IMPORT: SarifImportResponse = {
  status: "OK",
  count: 2,
  violations: DEMO_VIOLATIONS.slice(0, 2),
};
