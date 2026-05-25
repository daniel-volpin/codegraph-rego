import { z } from "zod";
import {
  HealthCheckResponseSchema,
  PolicyCatalogResponseSchema,
  PolicyEvaluateResponseSchema,
  PolicyExplainOneResponseSchema,
  PolicyReviewCreateResponseSchema,
  PolicyReviewListResponseSchema,
  RemediationApplyResponseSchema,
  RemediationPreviewResponseSchema,
  SearchResponseSchema,
  UploadResponseSchema,
  UploadStatusSchema,
  type HealthCheckResponse,
  type PolicyCatalogResponse,
  type PolicyEvaluateResponse,
  type PolicyExplainOneResponse,
  type PolicyReviewCreateResponse,
  type PolicyReviewListResponse,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
  type SearchResponse,
  type UploadResponse,
  type UploadStatus,
} from "./schemas";

const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://127.0.0.1:8000";

const defaultHeaders = {
  Accept: "application/json",
};

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
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload`, {
    method: "POST",
    body: formData,
    signal,
  });

  return parseApiResponse(response, UploadResponseSchema);
}

export async function searchCode(query: string, signal?: AbortSignal): Promise<SearchResponse> {
  const response = await fetch(`${API_BASE_URL}/search`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query }),
    signal,
  });

  return parseApiResponse(response, SearchResponseSchema);
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
    `${API_BASE_URL}/policy/evaluate${qs ? `?${qs}` : ""}`,
    {
      method: "GET",
      headers: defaultHeaders,
      signal,
    },
  );

  return parseApiResponse(response, PolicyEvaluateResponseSchema);
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
  const response = await fetch(`${API_BASE_URL}/policy/evaluate_with_llm`, {
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

  return parseApiResponse(response, PolicyEvaluateResponseSchema);
}

export async function fetchPolicyCatalog(
  signal?: AbortSignal,
): Promise<PolicyCatalogResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/catalog`, {
    method: "GET",
    headers: defaultHeaders,
    signal,
  });

  return parseApiResponse(response, PolicyCatalogResponseSchema);
}

export interface PolicyExplainOneRequest {
  violation: Record<string, unknown>;
  include_graph_context?: boolean;
  model?: string | null;
}

export async function explainPolicyViolationOne(
  payload: PolicyExplainOneRequest,
  signal?: AbortSignal,
): Promise<PolicyExplainOneResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/explain_one`, {
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
  violation: Record<string, unknown>;
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
  const response = await fetch(`${API_BASE_URL}/policy/reviews`, {
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
  const params = new URLSearchParams();
  if (args.violationKey) {
    params.set("violation_key", args.violationKey);
  }
  if (typeof args.limit === "number") {
    params.set("limit", String(args.limit));
  }
  const qs = params.toString();
  const response = await fetch(
    `${API_BASE_URL}/policy/reviews${qs ? `?${qs}` : ""}`,
    {
      method: "GET",
      headers: defaultHeaders,
      signal,
    },
  );

  return parseApiResponse(response, PolicyReviewListResponseSchema);
}

export async function fetchHealth(signal?: AbortSignal): Promise<HealthCheckResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
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
  const url = new URL(`${API_BASE_URL}/upload/status`);
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
  targetMethod?: string,
  filePath?: string,
  signal?: AbortSignal,
): Promise<RemediationPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/remediation/preview`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      violation_id: violationId,
      target_method: targetMethod,
      file_path: filePath,
    }),
    signal: withTimeoutSignal(signal, 300_000),
  });
  return parseApiResponse(response, RemediationPreviewResponseSchema);
}

export interface ApplyRemediationPayload {
  violation_id: string;
  target_method?: string;
  file_path?: string;
  max_attempts?: number;
}

export async function applyRemediation(
  payload: ApplyRemediationPayload,
  signal?: AbortSignal,
): Promise<RemediationApplyResponse> {
  const response = await fetch(`${API_BASE_URL}/remediation/apply`, {
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
