import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type ColumnDef,
  type ExpandedState,
  type SortingState,
  useTable,
} from "@tanstack/react-table";
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { evaluatePolicies, fetchPolicyCatalog } from "../lib/api";
import type { PolicyCatalogResponse, PolicyEvaluateResponse } from "../lib/types";
import {
  persistPolicyEvaluation,
  readPersistedUploadedModules,
  readPersistedPolicyEvaluation,
} from "../lib/persistence";
import { uniqueSortedModuleLabels } from "../lib/workspace";
import { messageMentionsBackendDependency } from "../lib/dependencies";
import { Badge } from "../components/ui/badge";
import ControlsPanel from "../components/features/policy/ControlsPanel";
import FindingDetailPanel from "../components/features/policy/FindingDetailPanel";
import SummaryCards from "../components/features/policy/SummaryCards";
import ViolationGroupTable from "../components/features/policy/ViolationGroupTable";
import {
  type PolicyViewPreset,
  type ViolationGroupRow,
  LEGACY_FRAMEWORK_DEMO_RULE_IDS,
  POLICY_VIEW_PRESET_STORAGE_KEY,
  groupViolationsByRule,
  normalizeViolation,
  readPolicyViewPreset,
  ruleGroupStatusLabel,
  ruleGroupStatusVariant,
  severityVariant,
  uniqueRuleIds,
} from "../components/features/policy/policyUtils";
import { type PolicyTableFeatures, policyTableFeatures } from "../components/features/policy/tableFeatures";
import { Card } from "../components/ui/card";

const evalQueryKey = (preset: PolicyViewPreset) =>
  ["policyEvaluation:last", preset] as const;

const evaluationErrorTitle = (message: string | null) =>
  messageMentionsBackendDependency(message)
    ? "Backend dependency unavailable."
    : "Policy evaluation failed.";

interface EvaluationStatusCardProps {
  isFetching: boolean;
  hasEvaluationResult: boolean;
  findingCount: number;
  totalFindingCount: number;
  ruleCount: number;
  errorMessage: string | null;
  responseIsPartial: boolean;
}

const EvaluationStatusCard = ({
  isFetching,
  hasEvaluationResult,
  findingCount,
  totalFindingCount,
  ruleCount,
  errorMessage,
  responseIsPartial,
}: EvaluationStatusCardProps) => {
  if (errorMessage) return null;

  const status =
    isFetching ? "running"
    : responseIsPartial ? "partial"
    : hasEvaluationResult && totalFindingCount === 0 ? "empty"
    : hasEvaluationResult ? "findings"
    : "initial";

  const config = {
    running: {
      icon: <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin text-zinc-700 dark:text-zinc-300" />,
      title: "Policy evaluation is running.",
      body: "The backend is evaluating the current workspace. Findings will appear when the response is validated.",
      tone: "border-zinc-300 bg-zinc-50 text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100",
    },
    partial: {
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-600 dark:text-amber-400" />,
      title: "Evaluation response is partial.",
      body: "Some bundles failed, the scan scope or findings were limited, or completeness metadata is missing. Review the available evidence and rerun without limits before treating this as a complete workspace scan.",
      tone: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200",
    },
    empty: {
      icon: <CheckCircle2 aria-hidden="true" className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />,
      title: "Evaluation completed successfully.",
      body: "Zero findings were returned. This means the policy engine evaluated the current workspace and did not report violations for the selected scope.",
      tone: "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200",
    },
    findings: {
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-600 dark:text-amber-400" />,
      title: "Evaluation completed with findings.",
      body: `${findingCount} visible finding${findingCount === 1 ? "" : "s"} across ${ruleCount} rule group${ruleCount === 1 ? "" : "s"}. Use the table and case dossier for evidence, explanation, and remediation availability.`,
      tone: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200",
    },
    initial: {
      icon: <ChevronRight aria-hidden="true" className="h-4 w-4 text-zinc-400" />,
      title: "Policy evaluation has not run yet.",
      body: "Run a policy scan to evaluate the uploaded workspace. A zero finding result will be shown separately after a successful backend response.",
      tone: "border-zinc-200 bg-zinc-50/70 text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300",
    },
  }[status];

  return (
    <Card
      role="status"
      aria-label="Policy evaluation status"
      aria-live={isFetching ? "polite" : "off"}
      className={`p-3.5 text-xs shadow-2xs ${config.tone}`}
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0">{config.icon}</div>
        <div>
          <p className="font-semibold text-xs">{config.title}</p>
          <p className="mt-0.5 leading-relaxed">{config.body}</p>
        </div>
      </div>
    </Card>
  );
};

const PolicyPage = () => {
  const queryClient = useQueryClient();
  const initialViewPreset = readPolicyViewPreset();

  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [expandedFindingByGroup, setExpandedFindingByGroup] = useState<Record<string, string | null>>({});
  const [viewPreset, setViewPreset] = useState<PolicyViewPreset>(initialViewPreset);
  const [uploadedModules, setUploadedModules] = useState<string[]>([]);
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const toggleFindingExpanded = (groupId: string, findingId: string) => {
    setExpandedFindingByGroup((prev) => ({
      ...prev,
      [groupId]: prev[groupId] === findingId ? null : findingId,
    }));
  };

  // ---- Policy catalog + eval queries ----

  const policyCatalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: ({ signal }) => fetchPolicyCatalog(signal),
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

  // Track the most recent toast-emit timestamps so we don't double-fire on
  // IDB hydration vs. fresh fetches. Initialized after hydration completes.
  const lastEvalToastAtRef = useRef(0);
  const lastEvalErrorToastAtRef = useRef(0);

  const evalQuery = useQuery<PolicyEvaluateResponse, Error>({
    queryKey: evalQueryKey(viewPreset),
    queryFn: ({ signal }) =>
      evaluatePolicies(
        { ruleIds: viewPreset === "framework_demo" ? frameworkDemoRuleIds : undefined },
        signal,
      ),
    enabled: false,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
    retry: false,
  });

  // Async hydrate the eval cache from IndexedDB. Avoids the previous
  // localStorage main-thread JSON.parse on multi-MB OPA payloads.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const persisted = await readPersistedPolicyEvaluation(viewPreset);
      if (cancelled || !persisted) return;
      // Only hydrate if we don't already have fresher data (e.g. a fetch
      // raced the hydration).
      const existing = queryClient.getQueryState(evalQueryKey(viewPreset));
      if (existing?.data && (existing.dataUpdatedAt ?? 0) >= persisted.savedAt) return;
      queryClient.setQueryData(evalQueryKey(viewPreset), persisted.data, {
        updatedAt: persisted.savedAt,
      });
      lastEvalToastAtRef.current = persisted.savedAt;
    })();
    return () => {
      cancelled = true;
    };
  }, [queryClient, viewPreset]);

  const frameworkDemoReady = viewPreset !== "framework_demo" || frameworkDemoRuleIds.length > 0;
  const frameworkDemoScopeSource =
    (policyCatalogQuery.data?.framework_demo_rule_ids?.length ?? 0) > 0
      ? "catalog"
      : (policyCatalogQuery.data?.benchmark_categories?.some((category) => category.framework_demo) ?? false)
        ? "benchmark_categories"
        : "legacy_fallback";

  // ---- Effects ----

  useEffect(() => {
    if (!evalQuery.data) return;
    // fire-and-forget; ignore IDB errors (handled inside persistence module)
    void persistPolicyEvaluation(evalQuery.data, viewPreset);
  }, [evalQuery.data, viewPreset]);

  useEffect(() => {
    try {
      localStorage.setItem(POLICY_VIEW_PRESET_STORAGE_KEY, viewPreset);
    } catch {
      /* ignore storage errors */
    }
  }, [viewPreset]);

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

  // ---- Derived data ----

  const findings = useMemo(
    () => (evalQuery.data?.violations ?? []).map((v) => normalizeViolation(v)),
    [evalQuery.data],
  );

  const availableModules = useMemo(
    () => uniqueSortedModuleLabels([...uploadedModules, ...findings.map((f) => f.filePath)]),
    [findings, uploadedModules],
  );

  const effectiveModuleFilter =
    moduleFilter === "all" || availableModules.includes(moduleFilter) ? moduleFilter : "all";

  const filteredFindings = useMemo(
    () => (effectiveModuleFilter === "all" ? findings : findings.filter((f) => f.module === effectiveModuleFilter)),
    [effectiveModuleFilter, findings],
  );

  const effectiveSelectedFindingId =
    selectedFindingId && filteredFindings.some((f) => f.id === selectedFindingId)
      ? selectedFindingId
      : (filteredFindings[0]?.id ?? null);

  const selectedFinding = useMemo(
    () => filteredFindings.find((f) => f.id === effectiveSelectedFindingId) ?? null,
    [effectiveSelectedFindingId, filteredFindings],
  );

  const visibleModules = useMemo(
    () =>
      effectiveModuleFilter === "all"
        ? availableModules
        : availableModules.includes(effectiveModuleFilter)
          ? [effectiveModuleFilter]
          : [],
    [availableModules, effectiveModuleFilter],
  );

  const data = useMemo(() => groupViolationsByRule(filteredFindings), [filteredFindings]);

  const summary = useMemo(
    () => ({
      findingCount: filteredFindings.length,
      ruleCount: data.length,
      moduleCount: visibleModules.length,
      fullSupportCount: filteredFindings.filter((f) => f.remediation.support_tier === "full").length,
      guardedSupportCount: filteredFindings.filter((f) => f.remediation.support_tier === "guarded").length,
      manualReviewCount: filteredFindings.filter((f) => f.remediation.support_tier === "manual").length,
    }),
    [data.length, filteredFindings, visibleModules.length],
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
  const tableEmptyMessage =
    !hasEvaluationResult
      ? "No policy evaluation has run yet. Run a scan to see rule groups."
      : responseIsPartial || evaluationError
        ? "No findings are available from this incomplete evaluation."
      : findings.length === 0
        ? "Evaluation completed successfully with zero findings for the selected scope."
        : "No findings match the current module filter.";

  // ---- Table ----

  const columns = useMemo<ColumnDef<PolicyTableFeatures, ViolationGroupRow>[]>(
    () => [
      {
        id: "expander",
        header: () => <span className="sr-only">Expand rule group</span>,
        enableSorting: false,
        cell: ({ row }) => (
          <button
            type="button"
            className="p-1"
            aria-label={row.getIsExpanded() ? "Collapse rule group" : "Expand rule group"}
            aria-expanded={row.getIsExpanded()}
            onClick={row.getToggleExpandedHandler()}
          >
            {row.getIsExpanded() ? (
              <ChevronDown aria-hidden="true" className="h-4 w-4" />
            ) : (
              <ChevronRight aria-hidden="true" className="h-4 w-4" />
            )}
          </button>
        ),
      },
      {
        accessorKey: "ruleId",
        header: "Rule ID",
        cell: ({ row }) => (
          <span className="block min-w-0 truncate font-mono text-xs text-slate-800" title={row.original.ruleId}>
            {row.original.ruleId}
          </span>
        ),
      },
      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }) => <Badge variant={severityVariant(row.original.severity)}>{row.original.severity}</Badge>,
      },
      {
        accessorKey: "findingCount",
        header: "Findings",
        cell: ({ row }) => <span className="text-sm text-slate-800">{row.original.findingCount}</span>,
      },
      {
        accessorKey: "fileCount",
        header: "Files",
        cell: ({ row }) => <span className="text-sm text-slate-800">{row.original.fileCount}</span>,
      },
      {
        id: "status",
        header: "Remediation",
        cell: ({ row }) => (
          <Badge variant={ruleGroupStatusVariant(row.original)}>{ruleGroupStatusLabel(row.original)}</Badge>
        ),
      },
    ],
    [],
  );

  const table = useTable({
    data,
    columns,
    features: policyTableFeatures,
    state: { sorting, expanded },
    onSortingChange: setSorting,
    onExpandedChange: setExpanded,
    getRowCanExpand: () => true,
  });

  // ---- Render ----

  return (
    <div className="space-y-4">
      <Card className="p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">Policy Evaluation</h1>
        <p className="mt-1 max-w-3xl text-xs text-zinc-600 dark:text-zinc-400">
          Run benchmark-aligned compliance evaluations, review grouped violations, and inspect remediation support across your codebase.
        </p>
      </Card>

      <ControlsPanel
        viewPreset={viewPreset}
        onViewPresetChange={setViewPreset}
        moduleFilter={effectiveModuleFilter}
        onModuleFilterChange={setModuleFilter}
        availableModules={availableModules}
        evalIsFetching={evalQuery.isFetching}
        onEvalRefetch={() => evalQuery.refetch()}
        frameworkDemoReady={frameworkDemoReady}
        policyCatalogIsLoading={policyCatalogQuery.isLoading}
        policyCatalogIsError={policyCatalogQuery.isError}
        frameworkDemoScopeSource={frameworkDemoScopeSource}
      />

      <EvaluationStatusCard
        isFetching={evalQuery.isFetching}
        hasEvaluationResult={hasEvaluationResult}
        findingCount={filteredFindings.length}
        totalFindingCount={findings.length}
        ruleCount={data.length}
        errorMessage={evaluationError}
        responseIsPartial={responseIsPartial}
      />

      {evaluationError && (
        <Card
          role="alert"
          className="border-rose-200 bg-rose-50/80 p-4 text-xs text-rose-800 shadow-2xs dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-200"
        >
          <p className="font-semibold text-rose-900 dark:text-rose-100">{evaluationErrorTitle(evaluationError)}</p>
          <p className="mt-1 break-words leading-relaxed">{evaluationError}</p>
          <p className="mt-2 text-[11px] text-rose-700 dark:text-rose-400">
            Check the health indicator for missing backend dependencies, then rerun the evaluation.
          </p>
        </Card>
      )}

      <SummaryCards {...summary} />

      <div
        data-testid="policy-results-layout"
        className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(360px,440px)] 2xl:items-start"
      >
        <ViolationGroupTable
          table={table}
          columnCount={columns.length}
          viewPreset={viewPreset}
          selectedFindingId={effectiveSelectedFindingId}
          onSelectFinding={setSelectedFindingId}
          expandedFindingByGroup={expandedFindingByGroup}
          onToggleFinding={toggleFindingExpanded}
          hasEvaluationResult={hasEvaluationResult}
          emptyMessage={tableEmptyMessage}
        />

        <FindingDetailPanel key={selectedFinding?.id ?? "empty"} selectedFinding={selectedFinding} />
      </div>
    </div>
  );
};

export default PolicyPage;
