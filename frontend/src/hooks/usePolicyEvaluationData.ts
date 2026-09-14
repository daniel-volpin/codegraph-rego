import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { evaluatePolicies, fetchPolicyCatalog, fetchPolicyPacks } from "../lib/api";
import type { PolicyCatalogResponse, PolicyEvaluateResponse, PolicyPacksResponse } from "../lib/types";
import {
  persistPolicyEvaluation,
  readPersistedUploadedModules,
  readPersistedPolicyEvaluation,
} from "../lib/persistence";
import { messageMentionsBackendDependency } from "../lib/dependencies";
import { normalizeViolation } from "../components/features/policy/policyUtils";

export const evalQueryKey = () => ["policyEvaluation:last", "all"] as const;

export const evaluationErrorTitle = (message: string | null) =>
  messageMentionsBackendDependency(message)
    ? "Backend dependency unavailable."
    : "Policy evaluation failed.";

/**
 * Owns the policy catalog/packs/evaluation queries, their IndexedDB
 * hydration and persistence, and the derived evaluation-outcome state.
 */
export function usePolicyEvaluationData() {
  const queryClient = useQueryClient();
  const [uploadedModules, setUploadedModules] = useState<string[]>([]);

  const policyCatalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: ({ signal }) => fetchPolicyCatalog(signal),
  });

  const policyPacksQuery = useQuery<PolicyPacksResponse, Error>({
    queryKey: ["policyPacks"],
    queryFn: ({ signal }) => fetchPolicyPacks(signal),
  });

  // Track the most recent toast-emit timestamps so we don't double-fire on
  // IDB hydration vs. fresh fetches. Initialized after hydration completes.
  const lastEvalToastAtRef = useRef(0);
  const lastEvalErrorToastAtRef = useRef(0);

  const evalQuery = useQuery<PolicyEvaluateResponse, Error>({
    queryKey: evalQueryKey(),
    queryFn: async ({ signal }) => {
      const result = await evaluatePolicies(undefined, signal);
      return (
        result ?? {
          violations: [],
        }
      );
    },
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
    retry: false,
  });

  // Async hydrate the eval cache from IndexedDB. Avoids the previous
  // localStorage main-thread JSON.parse on multi-MB OPA payloads.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const persisted = await readPersistedPolicyEvaluation("all");
      if (cancelled || !persisted) return;
      // Only hydrate if we don't already have fresher data (e.g. a fetch
      // raced the hydration).
      const existing = queryClient.getQueryState(evalQueryKey());
      if (existing?.data && (existing.dataUpdatedAt ?? 0) >= persisted.savedAt) return;
      queryClient.setQueryData(evalQueryKey(), persisted.data, {
        updatedAt: persisted.savedAt,
      });
      lastEvalToastAtRef.current = persisted.savedAt;
    })();
    return () => {
      cancelled = true;
    };
  }, [queryClient]);

  useEffect(() => {
    if (!evalQuery.data) return;
    // fire-and-forget; ignore IDB errors (handled inside persistence module)
    void persistPolicyEvaluation(evalQuery.data, "all");
  }, [evalQuery.data]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const modules = await readPersistedUploadedModules();
      if (!cancelled) {
        setUploadedModules(modules);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!evalQuery.errorUpdatedAt || !evalQuery.isError || !evalQuery.error) return;
    if (lastEvalErrorToastAtRef.current === evalQuery.errorUpdatedAt) return;
    lastEvalErrorToastAtRef.current = evalQuery.errorUpdatedAt;
    toast.error(`Evaluation failed: ${evalQuery.error.message}`);
  }, [evalQuery.error, evalQuery.errorUpdatedAt, evalQuery.isError]);

  const findings = useMemo(
    () => (evalQuery.data?.violations ?? []).map((v) => normalizeViolation(v)),
    [evalQuery.data],
  );

  const hasEvaluationResult = Boolean(evalQuery.data || evalQuery.dataUpdatedAt);
  const evaluation = evalQuery.data?.evaluation;
  const evaluationError =
    evalQuery.error?.message ??
    (evalQuery.data?.error ||
      (evaluation?.status === "failed" ? "Policy evaluation failed for every selected bundle." : null));
  const responseIsPartial =
    Boolean(evalQuery.data) &&
    (evaluation
      ? evaluation.status !== "complete" || evaluation.truncated || evaluation.scope_limited
      : Boolean(evalQuery.data?.truncated) ||
        (evalQuery.data?.failed_bundle_count ?? 0) > 0 ||
        !Object.prototype.hasOwnProperty.call(evalQuery.data, "opa_output") ||
        !Object.prototype.hasOwnProperty.call(evalQuery.data, "enriched"));

  return {
    policyCatalogQuery,
    policyPacksQuery,
    evalQuery,
    uploadedModules,
    findings,
    hasEvaluationResult,
    evaluationError,
    responseIsPartial,
  };
}
