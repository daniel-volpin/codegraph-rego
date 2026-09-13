import type {
  AgenticRemediationResponse,
  HealthCheckResponse,
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  PolicyExplainOneResponse,
  PolicyPackRule,
  PolicyPacksResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  SarifExportResponse,
  SarifImportResponse,
  SearchResponse,
  UploadResponse,
  UploadStatus,
  Violation,
} from "./schemas";

// Helper factory to generate concise, rich demo violations without boilerplate

interface DemoFindingSpec {
  id: string;
  method: string;
  file: string;
  line: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  standard: string;
  control: string;
  cwes: string[];
  reason: string;
  code: string;
  callers?: string[];
  neighbors?: string[];
  isSarif?: boolean;
}

const makeFinding = (spec: DemoFindingSpec): Violation => {
  const shortMethod = spec.method.split("(")[0].split(".").pop() || "method";
  return {
    violation_id: spec.id,
    rule_id: spec.id,
    target_method: spec.method,
    method_key: `demo@v1:${spec.file.split("/").pop()}#${shortMethod}`,
    file_path: spec.file,
    severity: spec.severity,
    reason: spec.reason,
    description: `${spec.reason} (${spec.cwes.join(", ")} / ${spec.standard} ${spec.control}).`,
    code_snippet: spec.code,
    snippet_start_line: spec.line,
    snippet_end_line: spec.line + spec.code.split("\n").length - 1,
    control_metadata: {
      standard: spec.standard,
      control: spec.control,
      title: `${spec.standard}: ${spec.id}`,
      cwes: spec.cwes,
    },
    evidence: {
      imported_from_sarif: spec.isSarif || undefined,
      source_code: spec.code,
      graph_context: { callers: spec.callers || [] },
      vector_context: spec.neighbors || [],
    },
    remediation: {
      supported: true,
      support_tier: spec.severity === "MEDIUM" || spec.id.includes("HASH") || spec.id.includes("RANDOM") ? "full" : "guarded",
      reason_code: "supported_rule_for_auto_fix",
      strategy: "agentic_graph_repair",
      preview_available: true,
      verify_available: true,
      ui_apply_mode: "dry_run",
      rationale: "Autonomous 3-gate agentic repair applies AST refactoring verified against compilation, regressions, and policy clearance.",
      safe_refusal_possible: spec.severity === "CRITICAL",
    },
  };
};

// 1. Health & Startup Fixtures

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
    version: "0.6.0-demo",
  },
};

// 2. Curated Multi-Standard Violations Dataset (24 Findings)

export const DEMO_VIOLATIONS: Violation[] = [
// ISO-27001
  makeFinding({
    id: "ISO-A.10-WEAK-HASH",
    method: "com.acme.security.AuthService.hashPassword(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/security/AuthService.java",
    line: 42,
    severity: "HIGH",
    standard: "ISO-27001",
    control: "Control A.10",
    cwes: ["CWE-328"],
    reason: "Cryptographically weak MD5 hashing used for credential storage.",
    code: `public String hashPassword(String password) throws Exception {\n    MessageDigest md = MessageDigest.getInstance("MD5");\n    byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));\n    return HexFormat.of().formatHex(digest);\n}`,
    callers: ["com.acme.controller.AuthController.register(UserRegistrationRequest)", "com.acme.controller.AuthController.login(LoginRequest)"],
    neighbors: ["com.acme.security.TokenService.verifyHash(String, String)"],
  }),
  makeFinding({
    id: "ISO-A.10-WEAK-CRYPTO",
    method: "com.acme.crypto.CipherUtil.encryptPayload(byte[], SecretKey)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/crypto/CipherUtil.java",
    line: 78,
    severity: "HIGH",
    standard: "ISO-27001",
    control: "Control A.10",
    cwes: ["CWE-327"],
    reason: "Insecure DES/ECB cipher mode used without integrity authentication.",
    code: `public byte[] encryptPayload(byte[] data, SecretKey key) throws Exception {\n    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");\n    cipher.init(Cipher.ENCRYPT_MODE, key);\n    return cipher.doFinal(data);\n}`,
    callers: ["com.acme.service.PayloadEncryptionService.protectPayload(byte[])"],
    neighbors: ["com.acme.crypto.KeyManager.deriveKey()"],
  }),
  makeFinding({
    id: "ISO-A.10-WEAK-RANDOM",
    method: "com.acme.security.TokenService.generateSessionToken()",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/security/TokenService.java",
    line: 23,
    severity: "MEDIUM",
    standard: "ISO-27001",
    control: "Control A.10",
    cwes: ["CWE-330"],
    reason: "Predictable java.util.Random used to generate session tokens.",
    code: `public String generateSessionToken() {\n    Random rng = new Random();\n    byte[] tokenBytes = new byte[24];\n    rng.nextBytes(tokenBytes);\n    return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);\n}`,
    callers: ["com.acme.security.SessionManager.createSession(User)"],
  }),
  makeFinding({
    id: "ISO-A.8-SQL-INJECTION",
    method: "com.acme.repository.AccountRepository.findByUsername(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/repository/AccountRepository.java",
    line: 34,
    severity: "CRITICAL",
    standard: "ISO-27001",
    control: "Control A.8",
    cwes: ["CWE-89"],
    reason: "Dynamic SQL query constructed via raw string concatenation.",
    code: `public User findByUsername(String username) {\n    String sql = "SELECT * FROM accounts WHERE username = '" + username + "'";\n    return jdbcTemplate.queryForObject(sql, new UserRowMapper());\n}`,
    callers: ["com.acme.service.AccountService.getUserProfile(String)"],
    neighbors: ["com.acme.repository.AccountRepository.findAll()"],
  }),
  makeFinding({
    id: "ISO-A.8-PATH-TRAVERSAL",
    method: "com.acme.storage.FileStorageService.loadFile(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/storage/FileStorageService.java",
    line: 19,
    severity: "HIGH",
    standard: "ISO-27001",
    control: "Control A.8",
    cwes: ["CWE-22"],
    reason: "Unvalidated filename passed to file system resolver without path normalization.",
    code: `public File loadFile(String filename) {\n    File baseDir = new File("/var/app/data");\n    return new File(baseDir, filename);\n}`,
    callers: ["com.acme.controller.DocumentController.download(String)"],
  }),
  makeFinding({
    id: "ISO-A.8-CMD-INJECTION",
    method: "com.acme.system.DiagnosticService.runPing(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/system/DiagnosticService.java",
    line: 25,
    severity: "CRITICAL",
    standard: "ISO-27001",
    control: "Control A.8",
    cwes: ["CWE-78"],
    reason: "Untrusted host parameter concatenated into system command execution.",
    code: `public String runPing(String host) throws Exception {\n    Process p = Runtime.getRuntime().exec("ping -c 3 " + host);\n    return new String(p.getInputStream().readAllBytes());\n}`,
    callers: ["com.acme.controller.DiagnosticsController.ping(String)"],
  }),
  makeFinding({
    id: "ISO-A.9.4.1",
    method: "com.acme.controller.AdminController.deleteCustomer(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/controller/AdminController.java",
    line: 52,
    severity: "HIGH",
    standard: "ISO-27001",
    control: "Control A.9.4.1",
    cwes: ["CWE-284"],
    reason: "Privileged administration endpoint exposed without role-based access authorization.",
    code: `@PostMapping("/api/v1/admin/customers/{id}/delete")\npublic ResponseEntity<Void> deleteCustomer(@PathVariable String id) {\n    customerService.purgeCustomerData(id);\n    return ResponseEntity.noContent().build();\n}`,
  }),
  makeFinding({
    id: "ISO-A.12.4.1",
    method: "com.acme.payment.PaymentService.charge(PaymentRequest)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/payment/PaymentService.java",
    line: 61,
    severity: "HIGH",
    standard: "ISO-27001",
    control: "Control A.12.4.1",
    cwes: ["CWE-778"],
    reason: "Critical state-changing financial operation missing audit log event.",
    code: `public PaymentReceipt charge(PaymentRequest request) {\n    PaymentReceipt receipt = paymentGateway.execute(request);\n    return receipt;\n}`,
  }),

// PCI-DSS 4.0
  makeFinding({
    id: "PCI-6.2.4.1-SQL-INJECTION",
    method: "com.acme.card.CardStore.queryCard(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/card/CardStore.java",
    line: 29,
    severity: "CRITICAL",
    standard: "PCI-DSS-4.0",
    control: "Requirement 6.2.4.1",
    cwes: ["CWE-89"],
    reason: "PCI-DSS 4.0 Req 6.2.4.1: SQL injection in cardholder data repository.",
    code: `public CardRecord queryCard(String pan) {\n    String q = "SELECT * FROM cardholder_data WHERE pan = '" + pan + "'";\n    return db.queryForObject(q, CardRecord.class);\n}`,
    callers: ["com.acme.card.PaymentProcessor.process(CardRecord)"],
  }),
  makeFinding({
    id: "PCI-6.2.4.2-PATH-TRAVERSAL",
    method: "com.acme.card.StatementService.exportStatement(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/card/StatementService.java",
    line: 38,
    severity: "HIGH",
    standard: "PCI-DSS-4.0",
    control: "Requirement 6.2.4.2",
    cwes: ["CWE-22"],
    reason: "PCI-DSS 4.0 Req 6.2.4.2: Path traversal in card statement file delivery.",
    code: `public File exportStatement(String accountId) {\n    File root = new File("/var/statements");\n    return new File(root, accountId + ".pdf");\n}`,
  }),
  makeFinding({
    id: "PCI-6.2.4.3-CMD-INJECTION",
    method: "com.acme.card.BatchSettlement.runBatch(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/card/BatchSettlement.java",
    line: 45,
    severity: "CRITICAL",
    standard: "PCI-DSS-4.0",
    control: "Requirement 6.2.4.3",
    cwes: ["CWE-78"],
    reason: "PCI-DSS 4.0 Req 6.2.4.3: Command injection in settlement batch script.",
    code: `public void runBatch(String batchId) throws Exception {\n    new ProcessBuilder("sh", "-c", "/opt/settle.sh " + batchId).start();\n}`,
  }),
  makeFinding({
    id: "PCI-3.4.1-WEAK-CRYPTO",
    method: "com.acme.card.PanCipher.encryptPan(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/card/PanCipher.java",
    line: 18,
    severity: "CRITICAL",
    standard: "PCI-DSS-4.0",
    control: "Requirement 3.4.1",
    cwes: ["CWE-327"],
    reason: "PCI-DSS 4.0 Req 3.4.1: Cardholder PAN encrypted using deprecated DES cipher.",
    code: `public byte[] encryptPan(String pan) throws Exception {\n    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");\n    c.init(Cipher.ENCRYPT_MODE, secretKey);\n    return c.doFinal(pan.getBytes());\n}`,
  }),
  makeFinding({
    id: "PCI-3.4.2-WEAK-HASH",
    method: "com.acme.card.PanHasher.hashPan(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/card/PanHasher.java",
    line: 12,
    severity: "HIGH",
    standard: "PCI-DSS-4.0",
    control: "Requirement 3.4.2",
    cwes: ["CWE-328"],
    reason: "PCI-DSS 4.0 Req 3.4.2: Deprecated MD5 used for transaction integrity verification.",
    code: `public String hashPan(String pan) throws Exception {\n    MessageDigest md = MessageDigest.getInstance("MD5");\n    return HexFormat.of().formatHex(md.digest(pan.getBytes()));\n}`,
  }),
  makeFinding({
    id: "PCI-8.3.1-WEAK-RANDOM",
    method: "com.acme.card.MfaService.generateOtp()",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/card/MfaService.java",
    line: 15,
    severity: "HIGH",
    standard: "PCI-DSS-4.0",
    control: "Requirement 8.3.1",
    cwes: ["CWE-330"],
    reason: "PCI-DSS 4.0 Req 8.3.1: Non-cryptographic random generator used for MFA authentication code.",
    code: `public String generateOtp() {\n    Random r = new Random();\n    int otp = 100000 + r.nextInt(900000);\n    return String.valueOf(otp);\n}`,
  }),

// OWASP Top 10
  makeFinding({
    id: "A03:2021-SQL-INJECTION",
    method: "com.acme.dao.UserDao.findUser(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/dao/UserDao.java",
    line: 22,
    severity: "CRITICAL",
    standard: "OWASP-2021",
    control: "A03:2021-Injection",
    cwes: ["CWE-89"],
    reason: "OWASP A03:2021: SQL Injection via unescaped string parameter in statement.",
    code: `public User findUser(String id) throws SQLException {\n    Statement st = conn.createStatement();\n    ResultSet rs = st.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");\n    return rs.next() ? new User(rs.getString(1)) : null;\n}`,
  }),
  makeFinding({
    id: "A03:2021-CMD-INJECTION",
    method: "com.acme.util.ShellRunner.execute(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/util/ShellRunner.java",
    line: 14,
    severity: "CRITICAL",
    standard: "OWASP-2021",
    control: "A03:2021-Injection",
    cwes: ["CWE-78"],
    reason: "OWASP A03:2021: OS Command Injection via shell execution.",
    code: `public void execute(String script) throws IOException {\n    Runtime.getRuntime().exec("sh -c " + script);\n}`,
  }),
  makeFinding({
    id: "A03:2021-LDAP-INJECTION",
    method: "com.acme.directory.LdapAuthenticator.findUser(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/directory/LdapAuthenticator.java",
    line: 28,
    severity: "HIGH",
    standard: "OWASP-2021",
    control: "A03:2021-Injection",
    cwes: ["CWE-90"],
    reason: "OWASP A03:2021: Unsanitized user string interpolated into LDAP search filter.",
    code: `public SearchResult findUser(String username) throws NamingException {\n    String filter = "(&(objectClass=user)(sAMAccountName=" + username + "))";\n    return dirContext.search("dc=acme,dc=com", filter, new SearchControls());\n}`,
  }),
  makeFinding({
    id: "A03:2021-XPATH-INJECTION",
    method: "com.acme.xml.XmlReportParser.extractUserNode(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/xml/XmlReportParser.java",
    line: 20,
    severity: "HIGH",
    standard: "OWASP-2021",
    control: "A03:2021-Injection",
    cwes: ["CWE-643"],
    reason: "OWASP A03:2021: Dynamic XPath query concatenated with untrusted user input.",
    code: `public Node extractUserNode(String role) throws XPathExpressionException {\n    String query = "/users/user[@role='" + role + "']";\n    return (Node) xpath.evaluate(query, doc, XPathConstants.NODE);\n}`,
  }),
  makeFinding({
    id: "A01:2021-PATH-TRAVERSAL",
    method: "com.acme.avatar.AvatarService.loadAvatar(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/avatar/AvatarService.java",
    line: 30,
    severity: "HIGH",
    standard: "OWASP-2021",
    control: "A01:2021-Broken Access Control",
    cwes: ["CWE-22"],
    reason: "OWASP A01:2021: Path traversal allows accessing files outside the avatar folder.",
    code: `public File loadAvatar(String name) {\n    return new File("/var/avatars/" + name);\n}`,
  }),

// NIST SP 800-53
  makeFinding({
    id: "NIST-SI-10-SQL-INJECTION",
    method: "com.gov.tax.TaxRecordRepo.fetch(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/gov/tax/TaxRecordRepo.java",
    line: 35,
    severity: "CRITICAL",
    standard: "NIST-800-53",
    control: "SI-10 Information Input Validation",
    cwes: ["CWE-89"],
    reason: "NIST SP 800-53 Rev 5 SI-10: Database query lacking input sanitization.",
    code: `public TaxRecord fetch(String ssn) {\n    return db.query("SELECT * FROM records WHERE ssn = '" + ssn + "'");\n}`,
  }),
  makeFinding({
    id: "AU-2-EVENT-LOGGING",
    method: "com.acme.transfer.TransferAuditService.executeTransfer(TransferRequest)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/transfer/TransferAuditService.java",
    line: 32,
    severity: "MEDIUM",
    standard: "NIST-800-53",
    control: "AU-2 Event Logging",
    cwes: ["CWE-778"],
    reason: "NIST SP 800-53 Rev 5 AU-2: Financial transfer transaction missing security event audit log.",
    code: `public TransferResult executeTransfer(TransferRequest req) {\n    accountService.debit(req.getFrom(), req.getAmount());\n    accountService.credit(req.getTo(), req.getAmount());\n    return TransferResult.success();\n}`,
  }),

// Universal SAST (SARIF)
  makeFinding({
    id: "SEMGREP-CWE-79",
    method: "com.acme.controller.CommentController.renderComment(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/controller/CommentController.java",
    line: 18,
    severity: "HIGH",
    standard: "SAST-SARIF",
    control: "CWE-79",
    cwes: ["CWE-79"],
    reason: "Universal SAST (Semgrep): Unescaped user comment written directly to HTTP response stream.",
    code: `@GetMapping("/comment")\npublic void renderComment(@RequestParam String comment, HttpServletResponse resp) throws IOException {\n    resp.getWriter().write("<div>" + comment + "</div>");\n}`,
    isSarif: true,
  }),
  makeFinding({
    id: "CODEQL-CWE-502",
    method: "com.acme.messaging.QueueConsumer.readPayload(byte[])",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/messaging/QueueConsumer.java",
    line: 24,
    severity: "CRITICAL",
    standard: "SAST-SARIF",
    control: "CWE-502",
    cwes: ["CWE-502"],
    reason: "Universal SAST (CodeQL): Insecure Java deserialization from untrusted message queue.",
    code: `public Object readPayload(byte[] bytes) throws Exception {\n    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));\n    return ois.readObject();\n}`,
    isSarif: true,
  }),
  makeFinding({
    id: "SONAR-CWE-611",
    method: "com.acme.config.XmlConfigReader.loadXml(InputStream)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/config/XmlConfigReader.java",
    line: 14,
    severity: "HIGH",
    standard: "SAST-SARIF",
    control: "CWE-611",
    cwes: ["CWE-611"],
    reason: "Universal SAST (SonarQube): XML External Entity (XXE) vulnerability in DocumentBuilderFactory.",
    code: `public Document loadXml(InputStream in) throws Exception {\n    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n    return dbf.newDocumentBuilder().parse(in);\n}`,
    isSarif: true,
  }),
  makeFinding({
    id: "SEMGREP-CWE-352",
    method: "com.acme.controller.ProfileUpdateController.updateEmail(String)",
    file: "/tmp/uploaded_code/app/src/main/java/com/acme/controller/ProfileUpdateController.java",
    line: 22,
    severity: "MEDIUM",
    standard: "SAST-SARIF",
    control: "CWE-352",
    cwes: ["CWE-352"],
    reason: "Universal SAST (Semgrep): State-changing POST endpoint missing CSRF token check.",
    code: `@PostMapping("/user/update-email")\npublic ResponseEntity<Void> updateEmail(@RequestParam String email) {\n    userProfileService.changeEmail(email);\n    return ResponseEntity.ok().build();\n}`,
    isSarif: true,
  }),
];

// 3. Policy Evaluation Response Fixture

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

// 4. Policy Catalog and Benchmark Categories

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

// 5. Pluggable Policy Packs Specifications

const makePackRule = (id: string, control: string, title: string, summary: string, severity: string, category: string): PolicyPackRule => ({
  id,
  control,
  title,
  summary,
  rego_module: "policy/main.rego",
  rego_rule: "violations",
  category,
  severity,
  reference: "https://codegraph.io/standards",
  description: summary,
  alias_ids: [],
});

export const DEMO_POLICY_PACKS: PolicyPacksResponse = {
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
      rules_count: 10,
      rules: [
        makePackRule("ISO-A.10-WEAK-HASH", "Control A.10", "Weak Cryptographic Hash (MD5/SHA-1)", "Disallows MD5 and SHA-1 in security-sensitive password hashing and signature routines.", "high", "Cryptography"),
        makePackRule("ISO-A.10-WEAK-CRYPTO", "Control A.10", "Insecure Cryptographic Cipher (DES/ECB)", "Flags broken block ciphers and unauthenticated modes (DES, 3DES, Blowfish, ECB).", "high", "Cryptography"),
        makePackRule("ISO-A.10-WEAK-RANDOM", "Control A.10", "Insecure Random Number Generator", "Requires SecureRandom instead of java.util.Random for token and nonce generation.", "medium", "Cryptography"),
        makePackRule("ISO-A.8-SQL-INJECTION", "Control A.8", "Dynamic SQL Injection via Concatenation", "Detects unescaped request input interpolated into JDBC/ORM queries.", "high", "Injection"),
        makePackRule("ISO-A.8-PATH-TRAVERSAL", "Control A.8", "Arbitrary Path Traversal via Unvalidated Path", "Identifies file system calls with untrusted path arguments missing canonicalization.", "high", "File Operations"),
        makePackRule("ISO-A.8-CMD-INJECTION", "Control A.8", "Operating System Command Injection", "Flags ProcessBuilder / Runtime.exec calls with unsanitized command strings.", "high", "Command Execution"),
        makePackRule("ISO-A.8-LDAP-INJECTION", "Control A.8", "LDAP Search Filter Injection", "Prevents concatenation of user input into LDAP query expressions.", "high", "Directory Services"),
        makePackRule("ISO-A.8-XPATH-INJECTION", "Control A.8", "Dynamic XPath Query Injection", "Flags dynamically concatenated XPath expressions.", "high", "XML Processing"),
        makePackRule("ISO-A.9.4.1", "Control A.9.4.1", "Unrestricted Privileged Endpoint Execution", "Requires RBAC / authorization annotations on controller methods.", "high", "Access Control"),
        makePackRule("ISO-A.12.4.1", "Control A.12.4.1", "Missing Security Event Audit Logging", "Requires audit logging on critical state-changing service transactions.", "high", "Logging & Auditing"),
      ],
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
      rules: [
        makePackRule("PCI-6.2.4.1-SQL-INJECTION", "Requirement 6.2.4.1", "SQL Injection in Cardholder Data Store", "Enforces parameterized queries to protect cardholder data repositories.", "critical", "Injection Flaws"),
        makePackRule("PCI-6.2.4.2-PATH-TRAVERSAL", "Requirement 6.2.4.2", "Path Traversal in Cardholder Statement Export", "Disallows unvalidated path traversal in file delivery routines.", "high", "Input Validation"),
        makePackRule("PCI-6.2.4.3-CMD-INJECTION", "Requirement 6.2.4.3", "Payment Batch OS Command Injection", "Blocks raw shell process invocation in batch payment pipelines.", "critical", "Execution Control"),
        makePackRule("PCI-3.4.1-WEAK-CRYPTO", "Requirement 3.4.1", "Insecure Cipher for Cardholder PAN Encryption", "Mandates AES-GCM or AES-CBC with HMAC for stored Primary Account Numbers (PAN).", "critical", "Protect Cardholder Data"),
        makePackRule("PCI-3.4.2-WEAK-HASH", "Requirement 3.4.2", "Insecure Cryptographic Hash for Verification", "Prohibits MD5/SHA-1 for payment verification tokens and message integrity.", "high", "Protect Cardholder Data"),
        makePackRule("PCI-8.3.1-WEAK-RANDOM", "Requirement 8.3.1", "Non-Cryptographic MFA Code Random Generator", "Requires cryptographically strong pseudorandom generation for one-time authentication codes.", "high", "Identity & Authentication"),
      ],
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
      rules: [
        makePackRule("A03:2021-SQL-INJECTION", "A03:2021-Injection", "A03:2021 SQL Injection Flaw", "Prevents dynamic SQL query construction without parameter binding.", "critical", "A03:2021-Injection"),
        makePackRule("A03:2021-CMD-INJECTION", "A03:2021-Injection", "A03:2021 OS Command Injection", "Blocks command execution constructed via string concatenation.", "critical", "A03:2021-Injection"),
        makePackRule("A03:2021-LDAP-INJECTION", "A03:2021-Injection", "A03:2021 LDAP Search Filter Injection", "Enforces LDAP filter escaping on directory queries.", "high", "A03:2021-Injection"),
        makePackRule("A03:2021-XPATH-INJECTION", "A03:2021-Injection", "A03:2021 Dynamic XPath Query Injection", "Requires parameterized XPath queries with variable resolvers.", "high", "A03:2021-Injection"),
        makePackRule("A01:2021-PATH-TRAVERSAL", "A01:2021-Broken Access Control", "A01:2021 Broken Access Control / Path Traversal", "Identifies file system access vulnerable to directory traversal.", "high", "A01:2021-Broken Access Control"),
        makePackRule("A02:2021-WEAK-CRYPTO", "A02:2021-Cryptographic Failures", "A02:2021 Deprecated Cryptographic Cipher (DES/ECB)", "Flags broken block ciphers and insecure ECB mode.", "critical", "A02:2021-Cryptographic Failures"),
        makePackRule("A02:2021-WEAK-HASH", "A02:2021-Cryptographic Failures", "A02:2021 Broken Cryptographic Hash (MD5)", "Disallows MD5 for password hashing and data integrity.", "high", "A02:2021-Cryptographic Failures"),
        makePackRule("A02:2021-WEAK-RANDOM", "A02:2021-Cryptographic Failures", "A02:2021 Predictable Pseudorandom Number Generator", "Requires SecureRandom for cryptographic key and token generation.", "high", "A02:2021-Cryptographic Failures"),
      ],
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
      rules: [
        makePackRule("NIST-SI-10-SQL-INJECTION", "SI-10 Information Input Validation", "SI-10 SQL Input Validation and Sanitization", "Validates all database inputs against structured query rules.", "critical", "System & Information Integrity"),
        makePackRule("NIST-SI-10-CMD-INJECTION", "SI-10 Information Input Validation", "SI-10 Command Execution Input Validation", "Restricts process command execution parameters.", "critical", "System & Information Integrity"),
        makePackRule("NIST-SI-10-PATH-TRAVERSAL", "SI-10 Information Input Validation", "SI-10 File Path Input Sanitization", "Sanitizes file path parameters against directory traversal.", "high", "System & Information Integrity"),
        makePackRule("NIST-SC-13-CRYPTOGRAPHIC-PROTECTION", "SC-13 Cryptographic Protection", "SC-13 FIPS-Compliant Cryptographic Ciphers", "Enforces FIPS 140-3 approved cryptographic algorithms (AES-GCM, AES-CBC).", "critical", "System & Communications Protection"),
        makePackRule("NIST-SC-28-PROTECTION-AT-REST", "SC-28 Protection of Information at Rest", "SC-28 Strong Hashing for Information at Rest", "Requires SHA-256 or SHA-512 for data integrity and password storage.", "high", "System & Communications Protection"),
      ],
    },
  ],
};

// 6. Remediation, Diffs, Previews & Agentic Execution Results

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

// 7. Search, Upload & SARIF Bridge Fixtures

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
