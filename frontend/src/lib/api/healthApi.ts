import {
  HealthCheckResponseSchema,
  type HealthCheckResponse,
} from "../schemas";
import { getRuntimeApiBase } from "../runtimeConfig";
import { DEMO_HEALTH } from "../demoDataset";
import { defaultHeaders, isDemoMode, parseApiResponse } from "./client";

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
