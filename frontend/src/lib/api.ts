import {
  HealthCheckResponse,
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  SearchResponse,
  UploadResponse,
  UploadStatus
} from "./types";

const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://127.0.0.1:8000";

const defaultHeaders = {
  Accept: "application/json"
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

export async function uploadZip(file: File): Promise<UploadResponse> {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload`, {
    method: "POST",
    body: formData
  });

  return handleResponse<UploadResponse>(response);
}

export async function searchCode(query: string): Promise<SearchResponse> {
  const response = await fetch(`${API_BASE_URL}/search`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ query })
  });

  return handleResponse<SearchResponse>(response);
}

export async function evaluatePolicies(): Promise<PolicyEvaluateResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/evaluate`, {
    method: "GET",
    headers: defaultHeaders
  });

  return handleResponse<PolicyEvaluateResponse>(response);
}

export async function evaluatePoliciesWithLLM(
  limit: number,
  model?: string
): Promise<PolicyEvaluateResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/evaluate_with_llm`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ limit, model })
  });

  return handleResponse<PolicyEvaluateResponse>(response);
}

export async function fetchPolicyCatalog(): Promise<PolicyCatalogResponse> {
  const response = await fetch(`${API_BASE_URL}/policy/catalog`, {
    method: "GET",
    headers: defaultHeaders
  });

  return handleResponse<PolicyCatalogResponse>(response);
}

export async function fetchHealth(): Promise<HealthCheckResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    method: "GET",
    headers: defaultHeaders
  });

  return handleResponse<HealthCheckResponse>(response);
}

export async function fetchUploadStatus(): Promise<UploadStatus> {
  const response = await fetch(`${API_BASE_URL}/upload/status`, {
    method: "GET",
    headers: defaultHeaders
  });

  return handleResponse<UploadStatus>(response);
}

export async function previewRemediation(
  violationId: string,
  targetMethod?: string,
  filePath?: string
): Promise<RemediationPreviewResponse> {
  const response = await fetch(`${API_BASE_URL}/remediation/preview`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      violation_id: violationId,
      target_method: targetMethod,
      file_path: filePath
    })
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
  payload: ApplyRemediationPayload
): Promise<RemediationApplyResponse> {
  const response = await fetch(`${API_BASE_URL}/remediation/apply`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      ...payload,
      mode: "dry_run"
    })
  });

  return handleRemediationResponse<RemediationApplyResponse>(response);
}
