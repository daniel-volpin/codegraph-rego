import {
  UploadResponseSchema,
  UploadStatusSchema,
  type UploadResponse,
  type UploadStatus,
} from "../schemas";
import { buildRuntimeApiUrl, getRuntimeApiBase } from "../runtimeConfig";
import { DEMO_UPLOAD_RESPONSE, DEMO_UPLOAD_STATUS } from "../demoDataset";
import { defaultHeaders, isDemoMode, parseApiResponse } from "./client";

export async function uploadZip(
  file: File,
  signal?: AbortSignal,
  requestId?: string,
): Promise<UploadResponse> {
  if (isDemoMode()) {
    return DEMO_UPLOAD_RESPONSE;
  }

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${getRuntimeApiBase()}/upload`, {
    method: "POST",
    body: formData,
    headers: requestId ? { "X-Request-Id": requestId } : undefined,
    signal,
  });

  return parseApiResponse(response, UploadResponseSchema);
}

export async function ingestFromGitUrl(
  repoUrl: string,
  ref?: string,
  signal?: AbortSignal,
  requestId?: string,
): Promise<UploadResponse> {
  if (isDemoMode()) {
    return DEMO_UPLOAD_RESPONSE;
  }

  const response = await fetch(`${getRuntimeApiBase()}/upload/git`, {
    method: "POST",
    headers: {
      ...defaultHeaders,
      ...(requestId ? { "X-Request-Id": requestId } : {}),
    },
    body: JSON.stringify({ repo_url: repoUrl, ref: ref?.trim() ? ref.trim() : null }),
    signal,
  });

  return parseApiResponse(response, UploadResponseSchema);
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
