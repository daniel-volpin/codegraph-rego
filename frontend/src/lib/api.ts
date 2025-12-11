import {
  HealthCheckResponse,
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  RemediationResponse,
  RemediationRun,
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

export async function remediateViolation(
  violationId: string
): Promise<RemediationResponse> {
  const response = await fetch(`${API_BASE_URL}/remediation/fix`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ violation_id: violationId })
  });
  return handleResponse<RemediationResponse>(response);
}

export async function startRemediationRun(
  violationId: string,
  maxAttempts?: number
): Promise<RemediationRun> {
  const response = await fetch(`${API_BASE_URL}/remediation/run`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      violation_id: violationId,
      max_attempts: maxAttempts ?? 3
    })
  });
  return handleResponse<RemediationRun>(response);
}

export async function getRemediationRun(runId: string): Promise<RemediationRun> {
  const response = await fetch(`${API_BASE_URL}/remediation/run/${runId}`, {
    method: "GET",
    headers: defaultHeaders
  });
  return handleResponse<RemediationRun>(response);
}
