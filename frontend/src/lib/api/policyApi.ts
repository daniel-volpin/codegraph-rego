import {
  PolicyCatalogResponseSchema,
  PolicyEvaluateResponseSchema,
  PolicyExplainOneResponseSchema,
  type PolicyCatalogResponse,
  type PolicyEvaluateResponse,
  type PolicyExplainOneResponse,
  type Violation,
} from "../schemas";
import { getRuntimeApiBase } from "../runtimeConfig";
import {
  DEMO_EXPLANATION,
  DEMO_POLICY_CATALOG,
  DEMO_POLICY_EVALUATION,
} from "../demoDataset";
import { defaultHeaders, isDemoMode, parseApiResponse, withTimeoutSignal, ApiError } from "./client";

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
      const filtered = (DEMO_POLICY_EVALUATION.violations ?? []).filter((v) => {
        const id = v.violation_id ?? v.rule_id;
        return id ? allowed.has(id) : true;
      });
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

