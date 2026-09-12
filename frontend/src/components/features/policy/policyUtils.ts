import {
  RemediationCapabilitySchema,
  type PolicyExplainOneResponse,
  type RemediationApplyResponse,
  type RemediationCapability,
  type RemediationConfidence,
  type RemediationPreviewResponse,
  type Violation,
} from "../../../lib/schemas";
import { deriveModuleLabel, relativeToUploadedWorkspace } from "../../../lib/workspace";

// Shared default for violations whose wire payload omits the optional
// `remediation` block. Frozen so the shared reference can't be mutated.
const DEFAULT_REMEDIATION: RemediationCapability = Object.freeze(
  RemediationCapabilitySchema.parse({}),
);

// ---- Types ----

// A wire-shape violation kept loose so the explain endpoint still receives
// the full original payload when we send `violationRow.raw` back.
export type RawViolation = Violation;

export interface ViolationRow {
  id: string;
  ruleId: string;
  severity: string;
  controlLabel: string;
  cweLabel: string;
  citation: string;
  module: string;
  targetMethod: string;
  methodKey: string;
  filePath: string;
  reason: string;
  snippet: string;
  remediation: RemediationCapability;
  raw: RawViolation;
}

export interface ViolationGroupRow {
  id: string;
  ruleId: string;
  severity: string;
  findingCount: number;
  fileCount: number;
  fullSupportCount: number;
  guardedSupportCount: number;
  manualCount: number;
  findings: ViolationRow[];
}

export type PolicyViewPreset = "all" | "framework_demo";
export type PendingAction = "explain" | "preview" | "apply";
export type ConfidenceBandLabel = "abstain" | "review" | "apply" | "pending";

// Re-export response types so consumers can import everything from one place
export type { PolicyExplainOneResponse, RemediationPreviewResponse, RemediationApplyResponse };

// ---- Constants ----

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

// ---- Display helpers ----

export interface ParsedMethodInfo {
  raw: string;
  className: string;
  methodName: string;
  shortSignature: string;
  compactSignature: string;
  paramTypes: string[];
  filePath?: string;
  packageName?: string;
}

export const parseMethodKey = (raw: string): ParsedMethodInfo => {
  if (!raw || typeof raw !== "string" || !raw.trim() || raw === "—") {
    return {
      raw: raw || "",
      className: "—",
      methodName: "—",
      shortSignature: raw || "—",
      compactSignature: raw || "—",
      paramTypes: [],
    };
  }

  const trimmed = raw.trim();

  // Handle AST Node Keys with #type: / #method: / #file:
  if (trimmed.includes("#method:") || trimmed.includes("#type:")) {
    let typeName = "";
    const typeMatch = trimmed.match(/#type:([^#]+)/);
    if (typeMatch) {
      typeName = typeMatch[1];
    }

    let methodName = "";
    let paramsStr = "";
    const methodMatch = trimmed.match(/#method:([^#/]+)(?:\/(\d+)\/([^#]*))?/);
    if (methodMatch) {
      methodName = methodMatch[1];
      paramsStr = methodMatch[3] || "";
    } else {
      const fallbackMethod = trimmed.match(/#method:([^#]+)/);
      if (fallbackMethod) {
        const parts = fallbackMethod[1].split("/");
        methodName = parts[0] || "method";
        paramsStr = parts[2] || "";
      }
    }

    let filePath: string | undefined;
    const fileMatch = trimmed.match(/#file:([^#]+)/);
    if (fileMatch) {
      filePath = formatCitationDisplay(fileMatch[1]).display;
    } else {
      const colonIndex = trimmed.indexOf(":");
      const hashIndex = trimmed.indexOf("#");
      if (colonIndex >= 0 && hashIndex > colonIndex) {
        filePath = formatCitationDisplay(trimmed.slice(colonIndex + 1, hashIndex)).display;
      }
    }

    const typeSegments = typeName.split(".").filter(Boolean);
    const className = typeSegments.length > 0 ? typeSegments[typeSegments.length - 1] : "Class";
    const packageName = typeSegments.length > 1 ? typeSegments.slice(0, -1).join(".") : undefined;

    const rawParams = paramsStr ? paramsStr.split(",").map((p) => p.trim()).filter(Boolean) : [];
    const paramTypes = rawParams.map((p) => {
      const segs = p.split(".").filter(Boolean);
      return segs.length > 0 ? segs[segs.length - 1] : p;
    });

    const cleanMethodName = methodName || "method";
    const shortSignature = `${className}.${cleanMethodName}(${paramTypes.join(", ")})`;
    const compactSignature = `${className}.${cleanMethodName}(${paramTypes.length > 0 ? "…" : ""})`;

    return {
      raw: trimmed,
      className,
      methodName: cleanMethodName,
      shortSignature,
      compactSignature,
      paramTypes,
      filePath,
      packageName,
    };
  }

  // Handle standard Java method signature: pkg.Class.method(params)
  const openParen = trimmed.indexOf("(");
  const closeParen = trimmed.lastIndexOf(")");
  const methodPrefix = openParen >= 0 ? trimmed.slice(0, openParen) : trimmed;
  const paramBlock = openParen >= 0 && closeParen > openParen ? trimmed.slice(openParen + 1, closeParen) : "";

  const prefixParts = methodPrefix.split(".").filter(Boolean);
  let className = "Class";
  let methodName = methodPrefix;
  let packageName: string | undefined;

  if (prefixParts.length >= 2) {
    methodName = prefixParts[prefixParts.length - 1];
    className = prefixParts[prefixParts.length - 2];
    if (prefixParts.length > 2) {
      packageName = prefixParts.slice(0, -2).join(".");
    }
  } else if (prefixParts.length === 1) {
    methodName = prefixParts[0];
  }

  const rawParams = paramBlock ? paramBlock.split(",").map((p) => p.trim()).filter(Boolean) : [];
  const paramTypes = rawParams.map((p) => {
    const base = p.replace(/<.*>/, "");
    const segs = base.split(".").filter(Boolean);
    return segs.length > 0 ? segs[segs.length - 1] : p;
  });

  const shortSignature = `${className !== "Class" ? className + "." : ""}${methodName}(${paramTypes.join(", ")})`;
  const compactSignature = `${className !== "Class" ? className + "." : ""}${methodName}(${paramTypes.length > 0 ? "…" : ""})`;

  return {
    raw: trimmed,
    className,
    methodName,
    shortSignature,
    compactSignature,
    paramTypes,
    packageName,
  };
};

export const compactTargetMethod = (value: string) => {
  if (!value || value === "—") return value;
  const parsed = parseMethodKey(value);
  return parsed.shortSignature;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const stringValue = (value: unknown): string | null =>
  typeof value === "string" && value.trim() ? value.trim() : null;

const stringListValue = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];

const firstPresentString = (...values: unknown[]) => {
  for (const value of values) {
    const text = stringValue(value);
    if (text) return text;
  }
  return null;
};

const controlMetadataFor = (item: RawViolation) =>
  isRecord(item.control_metadata) ? item.control_metadata : null;

const citationFor = (item: RawViolation, filePath: string) => {
  const startLine = typeof item.snippet_start_line === "number" ? item.snippet_start_line : null;
  const endLine = typeof item.snippet_end_line === "number" ? item.snippet_end_line : null;
  if (startLine != null && endLine != null) return `${filePath}:${startLine}-${endLine}`;
  if (startLine != null) return `${filePath}:${startLine}`;
  return filePath;
};

const labelsForViolation = (item: RawViolation, ruleId: string) => {
  const metadata = controlMetadataFor(item);
  const controlIds = stringListValue(metadata?.control_ids ?? metadata?.iso_controls);
  const cwes = stringListValue(metadata?.cwes);
  const controlLabel =
    controlIds.length > 0
      ? controlIds.join(", ")
      : firstPresentString(metadata?.control, metadata?.control_id, metadata?.category_id, ruleId) ?? ruleId;
  const cweLabel = cwes.length > 0 ? cwes.join(", ") : "CWE not provided";
  return { controlLabel, cweLabel };
};

// `item` is already validated at the API boundary (PolicyEvaluateResponseSchema
// parses each violation through ViolationSchema, applying defaults and
// capability normalization). We read typed fields directly rather than
// re-parsing — this runs once per violation on every evaluation, so the
// avoided parse matters at OWASP-benchmark scale (hundreds of findings).
export const normalizeViolation = (item: RawViolation): ViolationRow => {
  const ruleId = item.violation_id ?? item.rule_id ?? "—";
  const targetMethod = item.target_method ?? "—";
  const filePath = item.file_path ?? "—";
  const severity = (item.severity ?? "MEDIUM").toUpperCase();
  const { controlLabel, cweLabel } = labelsForViolation(item, ruleId);
  // `remediation` is optional on the wire; fall back to schema defaults.
  const remediation = item.remediation ?? DEFAULT_REMEDIATION;
  const rawSnippet =
    item.code_snippet ?? item.evidence?.source_code ?? item.updated_source_code ?? "";
  return {
    id: `${ruleId}:${item.method_key}`,
    ruleId,
    severity,
    controlLabel,
    cweLabel,
    citation: citationFor(item, filePath),
    module: deriveModuleLabel(filePath),
    targetMethod,
    methodKey: item.method_key,
    filePath,
    reason: item.reason ?? item.description ?? "—",
    snippet: rawSnippet,
    remediation,
    raw: item,
  };
};

// ---- Display helpers (severity / remediation / status) ----

export const severityVariant = (severity: string): "destructive" | "warning" | "secondary" => {
  if (severity === "HIGH") return "destructive";
  if (severity === "MEDIUM") return "warning";
  return "secondary";
};

export const severityRank = (severity: string) => {
  if (severity === "HIGH") return 3;
  if (severity === "MEDIUM") return 2;
  if (severity === "LOW") return 1;
  return 0;
};

export const remediationSummaryText = (capability: RemediationCapability) =>
  capability.support_tier === "full"
    ? "Preview suggests a bounded fix without compilation. Verify fix (dry run) runs compile and policy re-checks without persisting changes."
    : capability.support_tier === "guarded"
      ? "This rule supports guarded remediation with 3-gate safety verification (Compilation, Regression, and Policy re-evaluation)."
      : "Autonomous 3-gate agentic repair is available for this finding.";

export const remediationBadgeLabel = (capability: RemediationCapability) => {
  if (capability.support_tier === "full") return "Auto-fix available";
  if (capability.support_tier === "guarded") return "Auto-fix with safety checks";
  return "Agent fix ready";
};

export const remediationBadgeVariant = (capability: RemediationCapability): "success" | "secondary" => {
  void capability;
  return "success";
};

export const confidenceBandVariant = (
  band: ConfidenceBandLabel,
): "destructive" | "warning" | "success" | "secondary" => {
  if (band === "apply") return "success";
  if (band === "review") return "warning";
  if (band === "abstain") return "destructive";
  return "secondary";
};

export const confidenceBandLabel = (band: ConfidenceBandLabel) => {
  if (band === "apply") return "Apply";
  if (band === "review") return "Review";
  if (band === "abstain") return "Abstain";
  return "Pending";
};

export interface ConfidenceSurface {
  score: number | null;
  band: ConfidenceBandLabel;
  thresholdApply: number;
  thresholdReview: number;
  rationale: string | null;
}

export const deriveConfidenceSurface = (
  confidence: RemediationConfidence | null | undefined,
): ConfidenceSurface => {
  const score = typeof confidence?.score === "number" ? confidence.score : null;
  const thresholdApply =
    typeof confidence?.threshold_apply === "number" ? confidence.threshold_apply : 0.75;
  const thresholdReview =
    typeof confidence?.threshold_review === "number" ? confidence.threshold_review : 0.5;

  const bandFromScore: ConfidenceBandLabel =
    score == null ? "pending"
    : score >= thresholdApply ? "apply"
    : score >= thresholdReview ? "review"
    : "abstain";

  const band =
    confidence?.band === "apply" || confidence?.band === "review" || confidence?.band === "abstain"
      ? confidence.band
      : bandFromScore;

  return {
    score,
    band,
    thresholdApply,
    thresholdReview,
    rationale: confidence?.rationale ?? null,
  };
};

export const ruleGroupStatusLabel = (group: ViolationGroupRow) => {
  if (group.fullSupportCount > 0 && group.guardedSupportCount > 0) {
    return `${group.fullSupportCount} auto-fixable, ${group.guardedSupportCount} guarded`;
  }
  if (group.fullSupportCount > 0) return `${group.fullSupportCount} auto-fixable`;
  if (group.guardedSupportCount > 0) return `${group.guardedSupportCount} with safety checks`;
  return `${group.findingCount} with safety checks`;
};

export const ruleGroupStatusVariant = (group: ViolationGroupRow): "success" | "secondary" => {
  void group;
  return "success";
};

export const artifactStatusVariant = (
  status: "idle" | "running" | "ready" | "error",
): "secondary" | "warning" | "success" | "destructive" => {
  if (status === "running") return "warning";
  if (status === "ready") return "success";
  if (status === "error") return "destructive";
  return "secondary";
};

export const artifactStatusLabel = (status: "idle" | "running" | "ready" | "error") => {
  if (status === "running") return "Running";
  if (status === "ready") return "Ready";
  if (status === "error") return "Error";
  return "Not started";
};

export const colWidthClass = (colId: string) => {
  if (colId === "expander") return "w-9 text-center px-2";
  if (colId === "ruleId") return "w-[44%]";
  if (colId === "severity") return "w-[14%]";
  if (colId === "findingCount") return "w-[10%]";
  if (colId === "fileCount") return "w-[10%]";
  if (colId === "status") return "w-[22%]";
  return "";
};

export const formatCitationDisplay = (citation: string) => {
  const trimmed = citation.trim();
  if (!trimmed) return { display: citation, full: citation };
  const match = trimmed.match(/^(.*?)(:\d+(?:-\d+)?)$/);
  const rawPath = match?.[1] ?? trimmed;
  const suffix = match?.[2] ?? "";
  const normalizedPath = rawPath.replace(/\\/g, "/");
  let displayPath = normalizedPath;
  const srcIndex = normalizedPath.indexOf("/src/");
  if (normalizedPath.includes("/uploaded_code/") || normalizedPath.startsWith("uploaded_code/")) {
    displayPath = relativeToUploadedWorkspace(normalizedPath);
  } else if (srcIndex >= 0) {
    displayPath = normalizedPath.slice(srcIndex + 1);
  } else {
    const parts = normalizedPath.split("/").filter(Boolean);
    if (parts.length > 4) displayPath = parts.slice(-4).join("/");
  }
  return { display: `${displayPath}${suffix}`, full: trimmed };
};

export const readPolicyViewPreset = (): PolicyViewPreset => {
  try {
    const saved = localStorage.getItem(POLICY_VIEW_PRESET_STORAGE_KEY);
    return saved === "framework_demo" ? "framework_demo" : "all";
  } catch {
    return "all";
  }
};

export const uniqueRuleIds = (ruleIds: string[]) =>
  Array.from(new Set(ruleIds.filter((ruleId) => ruleId.trim())));

export const groupViolationsByRule = (violations: ViolationRow[]): ViolationGroupRow[] => {
  const groups = new Map<string, ViolationRow[]>();
  for (const violation of violations) {
    const key = violation.ruleId || "unknown-rule";
    const current = groups.get(key);
    if (current) {
      current.push(violation);
    } else {
      groups.set(key, [violation]);
    }
  }
  return Array.from(groups.entries()).map(([ruleId, findings]) => {
    const sortedFindings = [...findings].sort((left, right) => {
      const severityDiff = severityRank(right.severity) - severityRank(left.severity);
      if (severityDiff !== 0) return severityDiff;
      const fileDiff = left.filePath.localeCompare(right.filePath);
      if (fileDiff !== 0) return fileDiff;
      return left.targetMethod.localeCompare(right.targetMethod);
    });
    const fileCount = new Set(sortedFindings.map((f) => f.filePath)).size;
    const fullSupportCount = sortedFindings.filter((f) => f.remediation.support_tier === "full").length;
    const guardedSupportCount = sortedFindings.filter((f) => f.remediation.support_tier === "guarded").length;
    const manualCount = sortedFindings.filter((f) => f.remediation.support_tier === "manual").length;
    const highestSeverity = sortedFindings.reduce(
      (current, f) => (severityRank(f.severity) > severityRank(current) ? f.severity : current),
      sortedFindings[0]?.severity ?? "LOW",
    );
    return { id: ruleId, ruleId, severity: highestSeverity, findingCount: sortedFindings.length, fileCount, fullSupportCount, guardedSupportCount, manualCount, findings: sortedFindings };
  });
};

export type RemediationOutcomeCategory =
  | "fully_verified"
  | "build_failed"
  | "policy_violated"
  | "no_fix"
  | "generation_error"
  | "verification_error"
  | "unknown";

export interface CategorizedApplyOutcome {
  category: RemediationOutcomeCategory;
  title: string;
  badgeLabel: string;
  badgeVariant: "success" | "destructive" | "warning" | "secondary";
  detailMessage: string;
}

export const categorizeApplyOutcome = (applyResult: RemediationApplyResponse): CategorizedApplyOutcome => {
  const isOk = applyResult.status === "OK";
  const verification = applyResult.verification;
  const compilation = applyResult.compilation;
  const generation = applyResult.generation;

  if (generation?.decision === "no_fix") {
    return {
      category: "no_fix",
      title: "Remediation Abstained (NO_FIX)",
      badgeLabel: "Abstained / No Fix",
      badgeVariant: "secondary",
      detailMessage: generation.reason || "The remediation engine concluded that no safe automated fix could be generated for this context.",
    };
  }

  if (!isOk) {
    if (applyResult.status === "GENERATION_ERROR" || generation?.raw_response_valid === false) {
      return {
        category: "generation_error",
        title: "Generation Error",
        badgeLabel: "Generation Error",
        badgeVariant: "destructive",
        detailMessage: applyResult.error || generation?.schema_error || "LLM patch generation payload failed schema validation.",
      };
    }
    return {
      category: "verification_error",
      title: "Verification Error",
      badgeLabel: "Verification Error",
      badgeVariant: "destructive",
      detailMessage: applyResult.error || `Verification attempt returned status ${applyResult.status}.`,
    };
  }

  if (compilation?.attempted && !compilation.success) {
    return {
      category: "build_failed",
      title: "Build Verification Failed",
      badgeLabel: "Build Failed",
      badgeVariant: "destructive",
      detailMessage: compilation.skipped_reason || applyResult.error || "Compilation of the proposed patch failed.",
    };
  }

  if (
    isOk &&
    verification?.overall_status === "PASS" &&
    verification?.target_rule_status === "PASS" &&
    (verification.remaining_violations?.length ?? 0) === 0 &&
    (verification.new_violations?.length ?? 0) === 0
  ) {
    return {
      category: "fully_verified",
      title: "Fix Fully Verified",
      badgeLabel: "Fully Verified",
      badgeVariant: "success",
      detailMessage: "Patch applied cleanly in dry-run mode, compilation succeeded, and 0 policy violations remain.",
    };
  }

  if (
    verification?.overall_status === "FAIL" ||
    verification?.target_rule_status === "FAIL" ||
    (verification?.remaining_violations?.length ?? 0) > 0 ||
    (verification?.new_violations?.length ?? 0) > 0
  ) {
    const remainingCount = verification?.remaining_violations?.length ?? 0;
    const newCount = verification?.new_violations?.length ?? 0;
    return {
      category: "policy_violated",
      title: "Policy Still Violated",
      badgeLabel: "Policy Check Failed",
      badgeVariant: "warning",
      detailMessage: `Re-verification reported ${remainingCount} remaining violation${remainingCount === 1 ? "" : "s"} and ${newCount} new violation${newCount === 1 ? "" : "s"}.`,
    };
  }

  return {
    category: "unknown",
    title: "Apply Outcome Unverified",
    badgeLabel: "Unverified Outcome",
    badgeVariant: "secondary",
    detailMessage: applyResult.error || "Apply response requires manual inspection.",
  };
};
