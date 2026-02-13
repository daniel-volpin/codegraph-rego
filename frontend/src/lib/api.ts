import {
  HealthCheckResponse,
  PolicyExplainOneRequest,
  PolicyExplainOneResponse,
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  PolicyReviewCreateRequest,
  PolicyReviewCreateResponse,
  PolicyReviewListResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  SearchResponse,
  UploadResponse,
  UploadStatus,
} from "./types";

const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://127.0.0.1:8000";

const defaultHeaders = {
  Accept: "application/json",
};

async function handleResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type");
  const isJson = contentType && contentType.includes("application/json");
  const payload = isJson ? await response.json() : null;

  if (!response.ok) {
    const detail =
      payload && typeof payload === "object" && "error" in payload
        ? (payload.error as string)
        : response.statusText;
    throw new Error(detail || "Request failed");
  }

  return payload as T;
}

async function handleRemediationResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type");
  const isJson = contentType && contentType.includes("application/json");
  const payload = isJson ? await response.json() : null;

  if (response.ok) {
    return payload as T;
  }

  // Remediation endpoints return structured JSON even on 4xx/5xx (e.g. status=INVALID).
  if (
    payload &&
    typeof payload === "object" &&
    "status" in payload &&
    "violation_id" in payload
  ) {
    return payload as T;
  }

  const detail =
    payload && typeof payload === "object" && "error" in payload
      ? (payload.error as string)
      : response.statusText;
  throw new Error(detail || "Request failed");
}

async function handleStatusPayloadResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type");
  const isJson = contentType && contentType.includes("application/json");
  const payload = isJson ? await response.json() : null;

  if (response.ok) {
    return payload as T;
  }

  if (payload && typeof payload === "object" && "status" in payload) {
    return payload as T;
  }

  const detail =
    payload && typeof payload === "object" && "error" in payload
      ? (payload.error as string)
      : response.statusText;
  throw new Error(detail || "Request failed");
}

export async function uploadZip(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload`, {
    method: "POST",
    body: formData,
  });

  return handleResponse<UploadResponse>(response);
}

export async function searchCode(query: string): Promise<SearchResponse> {
  const response = await fetch(`${API_BASE_URL}/search`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query }),
  });

  return handleResponse<SearchResponse>(response);
}

export async function evaluatePolicies(args?: {
  maxBundles?: number;
  maxTotalViolations?: number;
  maxPerViolationId?: number;
}): Promise<PolicyEvaluateResponse> {
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
  const qs = params.toString();
  const response = await fetch(
    `${API_BASE_URL}/policy/evaluate${qs ? `?${qs}` : ""}`,
    {
      method: "GET",
      headers: defaultHeaders,
    },
  );

  return handleResponse<PolicyEvaluateResponse>(response);
}

export async function evaluatePoliciesWithLLM(payload: {
  limit: number;
  model?: string;
  maxBundles?: number;
  maxTotalViolations?: number;
  maxPerViolationId?: number;
}): Promise<PolicyEvaluateResponse> {
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
    }),
  });

  return handleResponse<PolicyEvaluateResponse>(response);
}

export async function fetchPolicyCatalog(): Promise<PolicyCatalogResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/catalog`, {
    method: "GET",
    headers: defaultHeaders,
  });

  return handleResponse<PolicyCatalogResponse>(response);
}

export async function explainPolicyViolationOne(
  payload: PolicyExplainOneRequest,
): Promise<PolicyExplainOneResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/explain_one`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  return handleStatusPayloadResponse<PolicyExplainOneResponse>(response);
}

export async function saveViolationReview(
  payload: PolicyReviewCreateRequest,
): Promise<PolicyReviewCreateResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/reviews`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  return handleStatusPayloadResponse<PolicyReviewCreateResponse>(response);
}

export async function fetchViolationReviews(
  args: { violationKey?: string; limit?: number } = {},
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
    },
  );

  return handleStatusPayloadResponse<PolicyReviewListResponse>(response);
}

export async function fetchHealth(): Promise<HealthCheckResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    method: "GET",
    headers: defaultHeaders,
  });

  return handleResponse<HealthCheckResponse>(response);
}

export async function fetchUploadStatus(): Promise<UploadStatus> {
  const response = await fetch(`${API_BASE_URL}/upload/status`, {
    method: "GET",
    headers: defaultHeaders,
  });

  return handleResponse<UploadStatus>(response);
}

export async function previewRemediation(
  violationId: string,
  targetMethod?: string,
  filePath?: string,
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
  });
  return handleRemediationResponse<RemediationPreviewResponse>(response);
}

export interface ApplyRemediationPayload {
  violation_id: string;
  target_method?: string;
  file_path?: string;
  max_attempts?: number;
}

export async function applyRemediation(
  payload: ApplyRemediationPayload,
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
  });

  return handleRemediationResponse<RemediationApplyResponse>(response);
}
