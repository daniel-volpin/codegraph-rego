import {
  PolicyReviewCreateResponseSchema,
  PolicyReviewListResponseSchema,
  type PolicyReviewCreateResponse,
  type PolicyReviewListResponse,
  type Violation,
} from "../schemas";
import { getRuntimeApiBase } from "../runtimeConfig";
import { defaultHeaders, isDemoMode, parseApiResponse } from "./client";

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
