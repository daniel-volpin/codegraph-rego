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
  module: string;
  targetMethod: string;
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
];

// ---- Display helpers ----

export const compactTargetMethod = (value: string) => {
  if (!value || value === "—") return value;
  const openParen = value.indexOf("(");
  const prefix = openParen >= 0 ? value.slice(0, openParen) : value;
  const suffix = openParen >= 0 ? value.slice(openParen) : "";
  const parts = prefix.split(".").filter(Boolean);
  if (parts.length < 2) return value;
  const methodName = parts[parts.length - 1];
  const className = parts[parts.length - 2];
  return `${className}.${methodName}${suffix}`;
};

const extractMethodNameFromSignature = (targetMethod: string) => {
  const match = targetMethod.match(/([A-Za-z_][A-Za-z0-9_]*)\s*\(/);
  return match ? match[1] : "";
};

export const trimSnippetToMethod = (snippet: string, targetMethod: string) => {
  if (!snippet.trim()) return "";
  const methodName = extractMethodNameFromSignature(targetMethod);
  if (!methodName) return snippet.trimEnd();
  const lines = snippet.split("\n");
  const declarationIndex = lines.findIndex((line) => new RegExp(`\\b${methodName}\\s*\\(`).test(line));
  if (declarationIndex < 0) return snippet.trimEnd();
  let start = declarationIndex;
  while (start > 0) {
    const previous = lines[start - 1].trim();
    if (!previous || previous.startsWith("@")) {
      start -= 1;
      continue;
    }
    break;
  }
  let sawOpeningBrace = false;
  let depth = 0;
  let end = lines.length - 1;
  for (let i = declarationIndex; i < lines.length; i += 1) {
    const line = lines[i];
    for (const char of line) {
      if (char === "{") {
        sawOpeningBrace = true;
        depth += 1;
      } else if (char === "}") {
        depth -= 1;
        if (sawOpeningBrace && depth === 0) {
          end = i;
          return lines.slice(start, end + 1).join("\n").trimEnd();
        }
      }
    }
  }
  return lines.slice(start, end + 1).join("\n").trimEnd();
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
  // `remediation` is optional on the wire; fall back to schema defaults.
  const remediation = item.remediation ?? DEFAULT_REMEDIATION;
  const rawSnippet =
    item.code_snippet ?? item.evidence?.source_code ?? item.updated_source_code ?? "";
  return {
    id: `${ruleId}:${targetMethod}:${filePath}`,
    ruleId,
    severity,
    module: deriveModuleLabel(filePath),
    targetMethod,
    filePath,
    reason: item.reason ?? item.description ?? "—",
    snippet: trimSnippetToMethod(rawSnippet, targetMethod),
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
      ? "This rule supports guarded remediation. The system may safely return NO_FIX when a minimal secure change is not evident from method-local context."
      : "This rule is explanation-first and remains manual review only. Automatic remediation is intentionally disabled for this category.";

export const remediationBadgeLabel = (capability: RemediationCapability) => {
  if (capability.support_tier === "full") return "Auto-fix available";
  if (capability.support_tier === "guarded") return "Auto-fix with safety checks";
  return "Manual review required";
};

export const remediationBadgeVariant = (capability: RemediationCapability): "success" | "secondary" =>
  capability.support_tier === "manual" ? "secondary" : "success";

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
  return "Manual review only";
};

export const ruleGroupStatusVariant = (group: ViolationGroupRow): "success" | "secondary" =>
  group.fullSupportCount > 0 || group.guardedSupportCount > 0 ? "success" : "secondary";

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
  if (colId === "expander") return "w-[4%]";
  if (colId === "ruleId") return "w-[24%]";
  if (colId === "severity") return "w-[10%]";
  if (colId === "findingCount") return "w-[12%]";
  if (colId === "fileCount") return "w-[12%]";
  if (colId === "status") return "w-[24%]";
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
