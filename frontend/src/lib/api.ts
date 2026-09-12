import { z } from "zod";
import {
  AgenticRemediationResponseSchema,
  HealthCheckResponseSchema,
  PolicyCatalogResponseSchema,
  PolicyEvaluateResponseSchema,
  PolicyExplainOneResponseSchema,
  PolicyPacksResponseSchema,
  PolicyReviewCreateResponseSchema,
  PolicyReviewListResponseSchema,
  RemediationApplyResponseSchema,
  RemediationPreviewResponseSchema,
  SarifExportResponseSchema,
  SarifImportResponseSchema,
  SearchResponseSchema,
  UploadResponseSchema,
  UploadStatusSchema,
  type AgenticRemediationResponse,
  type HealthCheckResponse,
  type PolicyCatalogResponse,
  type PolicyEvaluateResponse,
  type PolicyExplainOneResponse,
  type PolicyPacksResponse,
  type PolicyReviewCreateResponse,
  type PolicyReviewListResponse,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
  type SarifExportResponse,
  type SarifImportResponse,
  type SearchResponse,
  type UploadResponse,
  type UploadStatus,
  type Violation,
} from "./schemas";
import { buildRuntimeApiUrl, getRuntimeApiBase } from "./runtimeConfig";
import {
  DEMO_AGENTIC_RESULT,
  DEMO_APPLY_RESULT,
  DEMO_DIFFS,
  DEMO_EXPLANATION,
  DEMO_HEALTH,
  DEMO_POLICY_CATALOG,
  DEMO_POLICY_EVALUATION,
  DEMO_PREVIEWS,
  DEMO_POLICY_PACKS,
  DEMO_SARIF_DOCUMENT,
  DEMO_SARIF_IMPORT,
  DEMO_SEARCH_MATCHES,
  DEMO_UPLOAD_RESPONSE,
  DEMO_UPLOAD_STATUS,
} from "./demoData";

const defaultHeaders = {
  Accept: "application/json",
};

export const DEMO_MODE_STORAGE_KEY = "codegraph_demo_mode";

export function isDemoMode(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("demo") === "true") return true;
    return localStorage.getItem(DEMO_MODE_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function setDemoMode(enabled: boolean): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(DEMO_MODE_STORAGE_KEY, enabled ? "true" : "false");
    window.dispatchEvent(new Event("demo-mode-changed"));
  } catch {
    // Ignore storage errors
  }
}

// ---- Error classes ----

export class ApiError extends Error {
  status: number;
  payload: unknown;
  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export class SchemaValidationError extends Error {
  zodError: z.ZodError;
  payload: unknown;
  constructor(zodError: z.ZodError, payload: unknown) {
    const issues = zodError.issues
      .slice(0, 3)
      .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
      .join("; ");
    super(`Response failed schema validation: ${issues}`);
    this.name = "SchemaValidationError";
    this.zodError = zodError;
    this.payload = payload;
  }
}

// ---- Unified response parser ----
//
// Strategy:
// 1. Parse JSON if Content-Type advertises it.
// 2. If the payload validates against the schema, accept it regardless of
//    HTTP status. This subsumes the previous three handle*Response variants:
//    endpoints that return structured envelopes on 4xx (remediation,
//    explain, reviews, health) succeed if their schema matches.
// 3. Otherwise, if !ok, throw ApiError carrying the server's `error` field
//    when present, else statusText.
// 4. If ok but the schema doesn't match, throw SchemaValidationError. This
//    is a real backend/frontend drift and must surface, not be swallowed.

async function parseApiResponse<S extends z.ZodType>(
  response: Response,
  schema: S,
): Promise<z.infer<S>> {
  const contentType = response.headers.get("content-type");
  const isJson = contentType?.includes("application/json") ?? false;
  const payload: unknown = isJson ? await response.json() : null;

  const result = schema.safeParse(payload);
  if (result.success) return result.data;

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && payload !== null && "error" in payload
        ? String((payload as { error: unknown }).error ?? response.statusText)
        : response.statusText || "Request failed";
    throw new ApiError(message, response.status, payload);
  }

  throw new SchemaValidationError(result.error, payload);
}

// Merges an externally-provided AbortSignal with an internal timeout signal so
// callers can cancel a request from React Query while we still cap LLM-bound
// requests at 5 minutes.
function withTimeoutSignal(external: AbortSignal | undefined, ms: number): AbortSignal {
  if (!external) return AbortSignal.timeout(ms);
  // AbortSignal.any is supported in all modern browsers (Chrome 116+, Firefox 124+, Safari 17.4+).
  const anyFn = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFn === "function") {
    return anyFn([external, AbortSignal.timeout(ms)]);
  }
  return external;
}

// ---- Endpoints ----

export async function uploadZip(file: File, signal?: AbortSignal): Promise<UploadResponse> {
  if (isDemoMode()) {
    return DEMO_UPLOAD_RESPONSE;
  }

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${getRuntimeApiBase()}/upload`, {
    method: "POST",
    body: formData,
    signal,
  });

  return parseApiResponse(response, UploadResponseSchema);
}

export async function searchCode(query: string, signal?: AbortSignal): Promise<SearchResponse> {
  if (isDemoMode()) {
    const q = query.toLowerCase();
    const filteredMatches = DEMO_SEARCH_MATCHES.matches.filter((m) =>
      m.toLowerCase().includes(q) || q.includes("hash") || q.includes("crypto") || q.includes("pass") || q.includes("sql") || q.length === 0,
    );
    return {
      matches: filteredMatches.length > 0 ? filteredMatches : DEMO_SEARCH_MATCHES.matches,
      contexts: DEMO_SEARCH_MATCHES.contexts,
    };
  }

  const response = await fetch(`${getRuntimeApiBase()}/search`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query }),
    signal,
  });

  const data = await parseApiResponse(response, SearchResponseSchema);
  if (!response.ok) {
    throw new ApiError(data.error || response.statusText || "Search failed", response.status, data);
  }
  return data;
}

export interface PolicyEvaluateOptions {
  maxBundles?: number;
  maxTotalViolations?: number;
  maxPerViolationId?: number;
  ruleIds?: string[];
}

export async function evaluatePolicies(
  args?: PolicyEvaluateOptions,
  signal?: AbortSignal,
): Promise<PolicyEvaluateResponse> {
  if (isDemoMode()) {
    if (args?.ruleIds && args.ruleIds.length > 0) {
      const allowed = new Set(args.ruleIds);
      const filtered = (DEMO_POLICY_EVALUATION.violations ?? []).filter((v) =>
        v.rule_id ? allowed.has(v.rule_id) : true,
      );
      return {
        ...DEMO_POLICY_EVALUATION,
        violations: filtered,
      };
    }
    return DEMO_POLICY_EVALUATION;
  }

  const params = new URLSearchParams();
  if (typeof args?.maxBundles === "number") {
    params.set("max_bundles", String(args.maxBundles));
  }
  if (typeof args?.maxTotalViolations === "number") {
    params.set("max_total_violations", String(args.maxTotalViolations));
  }
  if (typeof args?.maxPerViolationId === "number") {
    params.set("max_per_violation_id", String(args.maxPerViolationId));
  }
  for (const ruleId of args?.ruleIds ?? []) {
    if (ruleId.trim()) {
      params.append("rule_ids", ruleId.trim());
    }
  }
  const qs = params.toString();
  const response = await fetch(
    `${getRuntimeApiBase()}/policy/evaluate${qs ? `?${qs}` : ""}`,
    {
      method: "GET",
      headers: defaultHeaders,
      signal,
    },
  );

  const data = await parseApiResponse(response, PolicyEvaluateResponseSchema);
  if (!response.ok) {
    throw new ApiError(data.error || response.statusText || "Policy evaluation failed", response.status, data);
  }
  return data;
}

export async function evaluatePoliciesWithLLM(
  payload: {
    limit: number;
    model?: string;
    maxBundles?: number;
    maxTotalViolations?: number;
    maxPerViolationId?: number;
    ruleIds?: string[];
  },
  signal?: AbortSignal,
): Promise<PolicyEvaluateResponse> {
  if (isDemoMode()) {
    return DEMO_POLICY_EVALUATION;
  }

  const response = await fetch(`${getRuntimeApiBase()}/policy/evaluate_with_llm`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      limit: payload.limit,
      model: payload.model,
      max_bundles: payload.maxBundles,
      max_total_violations: payload.maxTotalViolations,
      max_per_violation_id: payload.maxPerViolationId,
      rule_ids: payload.ruleIds,
    }),
    signal,
  });

  const data = await parseApiResponse(response, PolicyEvaluateResponseSchema);
  if (!response.ok) {
    throw new ApiError(data.error || response.statusText || "Policy evaluation failed", response.status, data);
  }
  return data;
}

export async function fetchPolicyCatalog(
  signal?: AbortSignal,
): Promise<PolicyCatalogResponse> {
  if (isDemoMode()) {
    return DEMO_POLICY_CATALOG;
  }

  const response = await fetch(`${getRuntimeApiBase()}/policy/catalog`, {
    method: "GET",
    headers: defaultHeaders,
    signal,
  });

  return parseApiResponse(response, PolicyCatalogResponseSchema);
}

export interface PolicySarifExportOptions {
  ruleIds?: string[];
}

export async function exportPolicySarif(
  args?: PolicySarifExportOptions,
  signal?: AbortSignal,
): Promise<SarifExportResponse> {
  if (isDemoMode()) {
    if (args?.ruleIds && args.ruleIds.length > 0) {
      const allowed = new Set(args.ruleIds);
      const runs = (DEMO_SARIF_DOCUMENT.runs ?? []).map((run) => {
        const results = (run.results as Array<{ ruleId?: string }> ?? []).filter((r) =>
          r.ruleId ? allowed.has(r.ruleId) : true,
        );
        return {
          ...run,
          results,
        };
      });
      return {
        ...DEMO_SARIF_DOCUMENT,
        runs,
      };
    }
    return DEMO_SARIF_DOCUMENT;
  }

  const params = new URLSearchParams();
  for (const ruleId of args?.ruleIds ?? []) {
    if (ruleId.trim()) {
      params.append("rule_ids", ruleId.trim());
    }
  }
  const qs = params.toString();
  const response = await fetch(
    `${getRuntimeApiBase()}/policy/export/sarif${qs ? `?${qs}` : ""}`,
    {
      method: "GET",
      headers: defaultHeaders,
      signal,
    },
  );

  const data = await parseApiResponse(response, SarifExportResponseSchema);
  if (!response.ok) {
    throw new ApiError(
      typeof data === "object" && data && "error" in data ? String(data.error) : response.statusText || "SARIF export failed",
      response.status,
      data,
    );
  }
  return data;
}

export async function fetchPolicyPacks(
  signal?: AbortSignal,
): Promise<PolicyPacksResponse> {
  if (isDemoMode()) {
    return DEMO_POLICY_PACKS;
  }

  const response = await fetch(`${getRuntimeApiBase()}/policy/packs`, {
    method: "GET",
    headers: defaultHeaders,
    signal,
  });

  return parseApiResponse(response, PolicyPacksResponseSchema);
}

export async function importSarifReport(
  sarifData: Record<string, unknown> | string,
  signal?: AbortSignal,
): Promise<SarifImportResponse> {
  if (isDemoMode()) {
    return DEMO_SARIF_IMPORT;
  }

  const payload = typeof sarifData === "string" ? JSON.parse(sarifData) : sarifData;
  const response = await fetch(`${getRuntimeApiBase()}/policy/import/sarif`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: withTimeoutSignal(signal, 120_000),
  });

  return parseApiResponse(response, SarifImportResponseSchema);
}

export interface PolicyExplainOneRequest {
  violation: Violation;
  include_graph_context?: boolean;
  model?: string | null;
}

export async function explainPolicyViolationOne(
  payload: PolicyExplainOneRequest,
  signal?: AbortSignal,
): Promise<PolicyExplainOneResponse> {
  if (isDemoMode()) {
    return DEMO_EXPLANATION;
  }

  const response = await fetch(`${getRuntimeApiBase()}/policy/explain_one`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: withTimeoutSignal(signal, 300_000),
  });

  return parseApiResponse(response, PolicyExplainOneResponseSchema);
}

export type PolicyReviewLabel = "TP" | "FP" | "UNCLEAR";

export interface PolicyReviewCreateRequest {
  label: PolicyReviewLabel;
  notes?: string | null;
  violation: Violation;
  explanation?: string | null;
  llm_model?: string | null;
  include_graph_context?: boolean;
  remediation_preview?: Record<string, unknown> | null;
  remediation_apply?: Record<string, unknown> | null;
}

export async function saveViolationReview(
  payload: PolicyReviewCreateRequest,
  signal?: AbortSignal,
): Promise<PolicyReviewCreateResponse> {
  if (isDemoMode()) {
    return {
      status: "OK",
      review_id: "demo-review-1",
      scrub_warnings: [],
    };
  }

  const response = await fetch(`${getRuntimeApiBase()}/policy/reviews`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal,
  });

  return parseApiResponse(response, PolicyReviewCreateResponseSchema);
}

export async function fetchViolationReviews(
  args: { violationKey?: string; limit?: number } = {},
  signal?: AbortSignal,
): Promise<PolicyReviewListResponse> {
  if (isDemoMode()) {
    return {
      status: "OK",
      reviews: [],
    };
  }

  const params = new URLSearchParams();
  if (args.violationKey) {
    params.set("violation_key", args.violationKey);
  }
  if (typeof args.limit === "number") {
    params.set("limit", String(args.limit));
  }
  const qs = params.toString();
  const response = await fetch(
    `${getRuntimeApiBase()}/policy/reviews${qs ? `?${qs}` : ""}`,
    {
      method: "GET",
      headers: defaultHeaders,
      signal,
    },
  );

  return parseApiResponse(response, PolicyReviewListResponseSchema);
}

export async function fetchHealth(signal?: AbortSignal): Promise<HealthCheckResponse> {
  if (isDemoMode()) {
    return DEMO_HEALTH;
  }

  const response = await fetch(`${getRuntimeApiBase()}/health`, {
    method: "GET",
    headers: defaultHeaders,
    signal,
  });

  return parseApiResponse(response, HealthCheckResponseSchema);
}

export async function fetchUploadStatus(
  requestId?: string | null,
  signal?: AbortSignal,
): Promise<UploadStatus> {
  if (isDemoMode()) {
    return DEMO_UPLOAD_STATUS;
  }

  const url = buildRuntimeApiUrl("/upload/status");
  if (requestId) {
    url.searchParams.set("request_id", requestId);
  }
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: defaultHeaders,
    signal,
  });

  return parseApiResponse(response, UploadStatusSchema);
}

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

