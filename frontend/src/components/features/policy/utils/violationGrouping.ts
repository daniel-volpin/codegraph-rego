import {
  RemediationCapabilitySchema,
  type RemediationCapability,
  type Violation,
} from "../../../../lib/schemas";
import { deriveModuleLabel } from "../../../../lib/workspace";
import { POLICY_VIEW_PRESET_STORAGE_KEY } from "./policyRuleTitles";

// Shared default for violations whose wire payload omits the optional
// `remediation` block. Frozen so the shared reference can't be mutated.
const DEFAULT_REMEDIATION: RemediationCapability = Object.freeze(
  RemediationCapabilitySchema.parse({}),
);

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

export const normalizeViolation = (item: RawViolation): ViolationRow => {
  const ruleId = item.violation_id ?? item.rule_id ?? "—";
  const targetMethod = item.target_method ?? "—";
  const filePath = item.file_path ?? "—";
  const severity = (item.severity ?? "MEDIUM").toUpperCase();
  const { controlLabel, cweLabel } = labelsForViolation(item, ruleId);
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
    return {
      id: ruleId,
      ruleId,
      severity: highestSeverity,
      findingCount: sortedFindings.length,
      fileCount,
      fullSupportCount,
      guardedSupportCount,
      manualCount,
      findings: sortedFindings,
    };
  });
};
