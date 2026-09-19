import {
  AgenticRemediationResponseSchema,
  RemediationApplyResponseSchema,
  RemediationPreviewResponseSchema,
  type AgenticRemediationResponse,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
  type Violation,
} from "../schemas";
import { getRuntimeApiBase } from "../runtimeConfig";
import {
  DEMO_AGENTIC_RESULT,
  DEMO_APPLY_RESULT,
  DEMO_DIFFS,
  DEMO_PREVIEWS,
} from "../demoDataset";
import { defaultHeaders, isDemoMode, parseApiResponse, withTimeoutSignal } from "./client";

export async function previewRemediation(
  violationId: string,
  methodKey: string,
  filePath?: string,
  signal?: AbortSignal,
): Promise<RemediationPreviewResponse> {
  if (isDemoMode()) {
    return (
      DEMO_PREVIEWS[violationId] ?? {
        status: "OK",
        violation_id: violationId,
        rule_id: violationId,
        method_key: methodKey,
        file_path: filePath,
        diff: DEMO_DIFFS[violationId] ?? DEMO_DIFFS["ISO-A.10-WEAK-HASH"],
        confidence: {
          score: 0.9,
          band: "apply",
          threshold_apply: 0.75,
          threshold_review: 0.5,
          rationale: "Demo mode bounded remediation preview.",
        },
        error: null,
      }
    );
  }

  const response = await fetch(`${getRuntimeApiBase()}/remediation/preview`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      violation_id: violationId,
      method_key: methodKey,
      file_path: filePath,
    }),
    signal: withTimeoutSignal(signal, 300_000),
  });
  return parseApiResponse(response, RemediationPreviewResponseSchema);
}

export interface ApplyRemediationPayload {
  violation_id: string;
  method_key: string;
  file_path?: string;
  max_attempts?: number;
}

export async function applyRemediation(
  payload: ApplyRemediationPayload,
  signal?: AbortSignal,
): Promise<RemediationApplyResponse> {
  if (isDemoMode()) {
    return {
      ...DEMO_APPLY_RESULT,
      violation_id: payload.violation_id,
      method_key: payload.method_key,
      file_path: payload.file_path,
    };
  }

  const response = await fetch(`${getRuntimeApiBase()}/remediation/apply`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      ...payload,
      mode: "dry_run",
    }),
    signal: withTimeoutSignal(signal, 300_000),
  });

  return parseApiResponse(response, RemediationApplyResponseSchema);
}

export interface AgenticRemediationPayload {
  finding: Violation | Record<string, unknown>;
  workspace_root?: string;
  max_turns?: number;
  model?: string;
}

export async function runAgenticRemediation(
  payload: AgenticRemediationPayload,
  signal?: AbortSignal,
): Promise<AgenticRemediationResponse> {
  if (isDemoMode()) {
    const raw = payload.finding as Record<string, unknown>;
    const ruleId = (raw.violation_id as string) ?? (raw.rule_id as string) ?? "ISO-A.8-SQL-INJECTION";
    return {
      ...DEMO_AGENTIC_RESULT,
      rule_id: ruleId,
      method_key: (raw.method_key as string) ?? DEMO_AGENTIC_RESULT.method_key,
      target_method: (raw.target_method as string) ?? DEMO_AGENTIC_RESULT.target_method,
    };
  }

  const response = await fetch(`${getRuntimeApiBase()}/remediation/agentic`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: withTimeoutSignal(signal, 300_000),
  });

  return parseApiResponse(response, AgenticRemediationResponseSchema);
}
