import { useEffect, useMemo, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { evaluatePolicies, fetchPolicyCatalog } from "../../../../lib/api";
import type { PolicyCatalogResponse, PolicyEvaluateResponse } from "../../../../lib/types";
import {
  type PolicyViewPreset,
  type ViolationRow,
  LEGACY_FRAMEWORK_DEMO_RULE_IDS,
  POLICY_VIEW_PRESET_STORAGE_KEY,
  normalizeViolation,
  persistPolicyEvaluation,
  readPersistedPolicyEvaluation,
  uniqueRuleIds,
} from "../policyUtils";

export interface UsePolicyEvalReturn {
  findings: ViolationRow[];
  hasEvaluationResult: boolean;
  frameworkDemoReady: boolean;
  frameworkDemoScopeSource: "catalog" | "benchmark_categories" | "legacy_fallback";
  evalIsFetching: boolean;
  onEvalRefetch: () => void;
  policyCatalogIsLoading: boolean;
  policyCatalogIsError: boolean;
}

export function usePolicyEval(viewPreset: PolicyViewPreset): UsePolicyEvalReturn {
  const initialEvalSnapshotRef = useRef<Record<PolicyViewPreset, ReturnType<typeof readPersistedPolicyEvaluation>>>({
    all: readPersistedPolicyEvaluation("all"),
    framework_demo: readPersistedPolicyEvaluation("framework_demo"),
  });

  const policyCatalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: fetchPolicyCatalog,
  });

  const frameworkDemoRuleIds = useMemo(() => {
    const explicit = uniqueRuleIds(policyCatalogQuery.data?.framework_demo_rule_ids ?? []);
    if (explicit.length > 0) return explicit;
    const derivedFromCategories = uniqueRuleIds(
      (policyCatalogQuery.data?.benchmark_categories ?? [])
        .filter((category) => category.framework_demo)
        .flatMap((category) => category.rego_rule_ids ?? []),
    );
    if (derivedFromCategories.length > 0) return derivedFromCategories;
    return LEGACY_FRAMEWORK_DEMO_RULE_IDS;
  }, [policyCatalogQuery.data?.benchmark_categories, policyCatalogQuery.data?.framework_demo_rule_ids]);

  const lastEvalToastAtRef = useRef(initialEvalSnapshotRef.current[viewPreset]?.savedAt ?? 0);
  const lastEvalErrorToastAtRef = useRef(0);

  const evalQuery = useQuery<PolicyEvaluateResponse, Error>({
    queryKey: ["policyEvaluation:last", viewPreset],
    queryFn: () => evaluatePolicies({ ruleIds: viewPreset === "framework_demo" ? frameworkDemoRuleIds : undefined }),
    enabled: false,
    initialData: initialEvalSnapshotRef.current[viewPreset]?.data,
    initialDataUpdatedAt: initialEvalSnapshotRef.current[viewPreset]?.savedAt,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
    retry: false,
  });

  const frameworkDemoReady = viewPreset !== "framework_demo" || frameworkDemoRuleIds.length > 0;
  const frameworkDemoScopeSource: "catalog" | "benchmark_categories" | "legacy_fallback" =
    (policyCatalogQuery.data?.framework_demo_rule_ids?.length ?? 0) > 0
      ? "catalog"
      : (policyCatalogQuery.data?.benchmark_categories?.some((category) => category.framework_demo) ?? false)
        ? "benchmark_categories"
        : "legacy_fallback";

  useEffect(() => {
    if (!evalQuery.data) return;
    persistPolicyEvaluation(evalQuery.data, viewPreset);
  }, [evalQuery.data, viewPreset]);

  useEffect(() => {
    try {
      localStorage.setItem(POLICY_VIEW_PRESET_STORAGE_KEY, viewPreset);
    } catch {
      /* ignore storage errors */
    }
  }, [viewPreset]);

  useEffect(() => {
    if (!evalQuery.dataUpdatedAt || !evalQuery.data) return;
    if (lastEvalToastAtRef.current === evalQuery.dataUpdatedAt) return;
    lastEvalToastAtRef.current = evalQuery.dataUpdatedAt;
    toast.success(`${evalQuery.data.violations?.length ?? 0} violations loaded.`);
  }, [evalQuery.data, evalQuery.dataUpdatedAt]);

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

  return {
    findings,
    hasEvaluationResult,
    frameworkDemoReady,
    frameworkDemoScopeSource,
    evalIsFetching: evalQuery.isFetching,
    onEvalRefetch: () => evalQuery.refetch(),
    policyCatalogIsLoading: policyCatalogQuery.isLoading,
    policyCatalogIsError: policyCatalogQuery.isError,
  };
}
