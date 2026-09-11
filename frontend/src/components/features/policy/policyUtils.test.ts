import {
  categorizeApplyOutcome,
  formatCitationDisplay,
  groupViolationsByRule,
  normalizeViolation,
} from "./policyUtils";

describe("policyUtils", () => {
  it("preserves the exact parser-selected snippet without scanning braces", () => {
    const snippet = [
      "  @Override",
      "  public void vulnerable(String input) {",
      '    String closing = "}";',
      "    sink(input);",
      "  }",
      "",
    ].join("\n");

    const row = normalizeViolation({
      method_key: "test@revision:Demo.java#vulnerable",
      target_method: "com.acme.Demo.vulnerable(String)",
      code_snippet: snippet,
    });
    expect(row.snippet).toBe(snippet);
  });

  it("normalizes a violation into a stable row shape", () => {
    const row = normalizeViolation({
      violation_id: "ISO-A.10-WEAK-HASH",
      target_method: "com.acme.Demo.hash(String)",
      method_key: "test@revision:Demo.java#hash",
      file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java",
      severity: "high",
      reason: "Weak hash usage detected",
      code_snippet: "public void hash(String input) {\n  md5(input);\n}",
      remediation: {
        supported: true,
        support_tier: "full",
        reason_code: "supported_rule_for_auto_fix",
        preview_available: true,
        verify_available: true,
        ui_apply_mode: "dry_run",
        rationale: "Bounded replacement is supported.",
        safe_refusal_possible: false,
      },
    });

    expect(row.id).toBe(
      "ISO-A.10-WEAK-HASH:test@revision:Demo.java#hash",
    );
    expect(row.methodKey).toBe("test@revision:Demo.java#hash");
    expect(normalizeViolation({
      ...row.raw,
      method_key: "test@next-revision:Demo.java#hash",
    }).id).not.toBe(row.id);
    expect(row.severity).toBe("HIGH");
    expect(row.ruleId).toBe("ISO-A.10-WEAK-HASH");
    expect(row.remediation.support_tier).toBe("full");
  });

  it("groups violations by rule and counts support tiers", () => {
    const findings = [
      normalizeViolation({
        violation_id: "ISO-A.10-WEAK-HASH",
        target_method: "a.A.one()",
        method_key: "test@revision:A.java#one",
        file_path: "/tmp/A.java",
        severity: "high",
        code_snippet: "void one() {}",
        remediation: {
          supported: true,
          support_tier: "full",
          reason_code: "supported_rule_for_auto_fix",
          preview_available: true,
          verify_available: true,
          ui_apply_mode: "dry_run",
          rationale: "Bounded replacement is supported.",
          safe_refusal_possible: false,
        },
      }),
      normalizeViolation({
        violation_id: "ISO-A.10-WEAK-HASH",
        target_method: "a.A.two()",
        method_key: "test@revision:B.java#two",
        file_path: "/tmp/B.java",
        severity: "medium",
        code_snippet: "void two() {}",
        remediation: {
          supported: true,
          support_tier: "guarded",
          reason_code: "guarded_rule_for_auto_fix",
          preview_available: true,
          verify_available: true,
          ui_apply_mode: "dry_run",
          rationale: "Guarded replacement requires review.",
          safe_refusal_possible: true,
        },
      }),
    ];

    const groups = groupViolationsByRule(findings);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.findingCount).toBe(2);
    expect(groups[0]?.fileCount).toBe(2);
    expect(groups[0]?.fullSupportCount).toBe(1);
    expect(groups[0]?.guardedSupportCount).toBe(1);
  });

  it("formats citations for uploaded workspace paths", () => {
    expect(
      formatCitationDisplay("/tmp/work/uploaded_code/app/src/main/java/com/acme/Demo.java:42"),
    ).toEqual({
      display: "app/src/main/java/com/acme/Demo.java:42",
      full: "/tmp/work/uploaded_code/app/src/main/java/com/acme/Demo.java:42",
    });
  });

  it("categorizes apply outcomes correctly across all backend states", () => {
    // 1. Clean NO_FIX abstention
    expect(
      categorizeApplyOutcome({
        status: "OK",
        generation: { decision: "no_fix", reason: "Context insufficient." },
      }).category,
    ).toBe("no_fix");

    // 2. Generation error
    expect(
      categorizeApplyOutcome({
        status: "GENERATION_ERROR",
        error: "Schema validation failed",
      }).category,
    ).toBe("generation_error");

    // 3. Build compilation failure
    expect(
      categorizeApplyOutcome({
        status: "OK",
        compilation: { attempted: true, success: false, skipped_reason: "Compiler syntax error" },
      }).category,
    ).toBe("build_failed");

    // 4. Fully verified PASS
    expect(
      categorizeApplyOutcome({
        status: "OK",
        compilation: { attempted: true, success: true },
        verification: {
          overall_status: "PASS",
          target_rule_status: "PASS",
          remaining_violations: [],
          new_violations: [],
        },
      }).category,
    ).toBe("fully_verified");

    // 5. Policy still violated
    expect(
      categorizeApplyOutcome({
        status: "OK",
        compilation: { attempted: true, success: true },
        verification: {
          overall_status: "FAIL",
          target_rule_status: "FAIL",
          remaining_violations: [],
          new_violations: [],
        },
      }).category,
    ).toBe("policy_violated");
  });
});
