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

export const remediationBadgeVariant = (capability: RemediationCapability): "success" | "secondary" =>
  "success";

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

export const ruleGroupStatusVariant = (group: ViolationGroupRow): "success" | "secondary" =>
  "success";

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
