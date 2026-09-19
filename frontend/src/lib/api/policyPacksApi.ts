import {
  PolicyPacksResponseSchema,
  SarifExportResponseSchema,
  SarifImportResponseSchema,
  type PolicyPacksResponse,
  type SarifExportResponse,
  type SarifImportResponse,
} from "../schemas";
import { getRuntimeApiBase } from "../runtimeConfig";
import {
  DEMO_POLICY_PACKS,
  DEMO_SARIF_DOCUMENT,
  DEMO_SARIF_IMPORT,
} from "../demoDataset";
import { defaultHeaders, isDemoMode, parseApiResponse, withTimeoutSignal, ApiError } from "./client";

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
