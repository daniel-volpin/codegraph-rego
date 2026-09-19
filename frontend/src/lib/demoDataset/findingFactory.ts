import type { Violation } from "../schemas";

export interface DemoFindingSpec {
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

export const makeFinding = (spec: DemoFindingSpec): Violation => {
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
