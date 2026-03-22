import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type ColumnDef,
  type ExpandedState,
  type SortingState,
  getCoreRowModel,
  getExpandedRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ChevronDown, ChevronRight } from "lucide-react";
import { toast } from "sonner";
import {
  applyRemediation,
  evaluatePolicies,
  explainPolicyViolationOne,
  fetchPolicyCatalog,
  previewRemediation,
} from "../lib/api";
import type { PolicyCatalogResponse, PolicyEvaluateResponse } from "../lib/types";
import { uniqueSortedModuleLabels } from "../lib/workspace";
import { Badge } from "../components/ui/badge";
import ControlsPanel from "../components/features/policy/ControlsPanel";
import FindingDetailPanel from "../components/features/policy/FindingDetailPanel";
import SummaryCards from "../components/features/policy/SummaryCards";
import ViolationGroupTable from "../components/features/policy/ViolationGroupTable";
import {
  type PendingAction,
  type PolicyExplainOneResponse,
  type PolicyViewPreset,
  type RawViolation,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
  type ViolationGroupRow,
  type ViolationRow,
  LEGACY_FRAMEWORK_DEMO_RULE_IDS,
  POLICY_VIEW_PRESET_STORAGE_KEY,
  groupViolationsByRule,
  normalizeViolation,
  persistPolicyEvaluation,
  readPersistedPolicyEvaluation,
  readPolicyViewPreset,
  readUploadedModules,
  ruleGroupStatusLabel,
  ruleGroupStatusVariant,
  severityVariant,
  uniqueRuleIds,
} from "../components/features/policy/policyUtils";

const PolicyPage = () => {
  const queryClient = useQueryClient();
  const initialViewPreset = readPolicyViewPreset();
  const initialEvalSnapshotRef = useRef<Record<PolicyViewPreset, ReturnType<typeof readPersistedPolicyEvaluation>>>({
    all: readPersistedPolicyEvaluation("all"),
    framework_demo: readPersistedPolicyEvaluation("framework_demo"),
  });

  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [expandedFindingByGroup, setExpandedFindingByGroup] = useState<Record<string, string | null>>({});
  const [viewPreset, setViewPreset] = useState<PolicyViewPreset>(initialViewPreset);
  const [uploadedModules, setUploadedModules] = useState<string[]>(() => readUploadedModules());
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<Record<string, PendingAction>>({});

  const markPending = useCallback((id: string, action: PendingAction) => {
    setPendingAction((prev) => ({ ...prev, [id]: action }));
  }, []);
  const clearPending = useCallback((id: string) => {
    setPendingAction((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }, []);
  const toggleFindingExpanded = useCallback((groupId: string, findingId: string) => {
    setExpandedFindingByGroup((prev) => ({
      ...prev,
      [groupId]: prev[groupId] === findingId ? null : findingId,
    }));
  }, []);

  // ---- Cache-as-state queries (manual updates only) ----

  const previewByIdQuery = useQuery<Record<string, RemediationPreviewResponse>>({
    queryKey: ["policy:previewById"],
    queryFn: async () => ({}),
    enabled: false,
    initialData: {},
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  });
  const explainByIdQuery = useQuery<Record<string, PolicyExplainOneResponse>>({
    queryKey: ["policy:explainById"],
    queryFn: async () => ({}),
    enabled: false,
    initialData: {},
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  });
  const applyByIdQuery = useQuery<Record<string, RemediationApplyResponse>>({
    queryKey: ["policy:applyById"],
    queryFn: async () => ({}),
    enabled: false,
    initialData: {},
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  });

  const previewById = previewByIdQuery.data;
  const explainById = explainByIdQuery.data;
  const applyById = applyByIdQuery.data;

  // ---- Policy catalog + eval queries ----

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
  const frameworkDemoScopeSource =
    (policyCatalogQuery.data?.framework_demo_rule_ids?.length ?? 0) > 0
      ? "catalog"
      : (policyCatalogQuery.data?.benchmark_categories?.some((category) => category.framework_demo) ?? false)
        ? "benchmark_categories"
        : "legacy_fallback";

  // ---- Effects ----

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
    setUploadedModules(readUploadedModules());
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

  // ---- Mutations ----

  const explainMutation = useMutation({
    mutationFn: (violation: RawViolation) =>
      explainPolicyViolationOne({ violation, include_graph_context: true }),
    onMutate: (violation) => {
      const row = normalizeViolation(violation);
      markPending(row.id, "explain");
    },
    onSuccess: (data, violation) => {
      const row = normalizeViolation(violation);
      queryClient.setQueryData<Record<string, PolicyExplainOneResponse>>(
        ["policy:explainById"],
        (prev) => ({ ...(prev ?? {}), [row.id]: data }),
      );
      if ((data.status || "").toUpperCase() === "OK" && data.explanation) {
        toast.success("LLM explanation ready.");
        return;
      }
      const msg =
        data.error ||
        (typeof data.explanation === "string" && data.explanation.startsWith("[LLM unavailable:")
          ? "LLM is unavailable. Start your local server (e.g. LM Studio) or configure the LLM provider."
          : "LLM explanation unavailable.");
      toast.error(msg);
    },
    onSettled: (_d, _e, violation) => {
      const row = normalizeViolation(violation);
      clearPending(row.id);
    },
    onError: (error: Error) => toast.error(`Explain failed: ${error.message}`),
  });

  const previewMutation = useMutation({
    mutationFn: (row: ViolationRow) => previewRemediation(row.ruleId, row.targetMethod, row.filePath),
    onMutate: (row) => markPending(row.id, "preview"),
    onSuccess: (data, row) => {
      queryClient.setQueryData<Record<string, RemediationPreviewResponse>>(
        ["policy:previewById"],
        (prev) => ({ ...(prev ?? {}), [row.id]: data }),
      );
      const status = (data.status || "").toUpperCase();
      if (status === "OK") {
        toast.success(`Preview complete for ${row.ruleId}.`);
      } else {
        toast.error(data.error || `Preview failed (${status}) for ${row.ruleId}.`);
      }
    },
    onSettled: (_d, _e, row) => clearPending(row.id),
    onError: (error: Error) => toast.error(`Preview failed: ${error.message}`),
  });

  const applyMutation = useMutation({
    mutationFn: (row: ViolationRow) =>
      applyRemediation({ violation_id: row.ruleId, target_method: row.targetMethod, file_path: row.filePath }),
    onMutate: (row) => markPending(row.id, "apply"),
    onSuccess: (data, row) => {
      queryClient.setQueryData<Record<string, RemediationApplyResponse>>(
        ["policy:applyById"],
        (prev) => ({ ...(prev ?? {}), [row.id]: data }),
      );
      const status = (data.status || "").toUpperCase();
      if (status === "OK") {
        toast.success(`Remediation applied for ${row.ruleId}.`);
      } else {
        toast.error(data.error || `Apply failed (${status}) for ${row.ruleId}.`);
      }
    },
    onSettled: (_d, _e, row) => clearPending(row.id),
    onError: (error: Error) => toast.error(`Apply failed: ${error.message}`),
  });

  // ---- Derived data ----

  const findings = useMemo(
    () => (evalQuery.data?.violations ?? []).map((v) => normalizeViolation(v)),
    [evalQuery.data],
  );

  const availableModules = useMemo(
    () => uniqueSortedModuleLabels([...uploadedModules, ...findings.map((f) => f.filePath)]),
    [findings, uploadedModules],
  );

  useEffect(() => {
    if (moduleFilter !== "all" && !availableModules.includes(moduleFilter)) {
      setModuleFilter("all");
    }
  }, [availableModules, moduleFilter]);

  const filteredFindings = useMemo(
    () => (moduleFilter === "all" ? findings : findings.filter((f) => f.module === moduleFilter)),
    [findings, moduleFilter],
  );

  useEffect(() => {
    if (filteredFindings.length === 0) {
      setSelectedFindingId(null);
      return;
    }
    if (!selectedFindingId || !filteredFindings.some((f) => f.id === selectedFindingId)) {
      setSelectedFindingId(filteredFindings[0].id);
    }
  }, [filteredFindings, selectedFindingId]);

  const selectedFinding = useMemo(
    () => filteredFindings.find((f) => f.id === selectedFindingId) ?? null,
    [filteredFindings, selectedFindingId],
  );

  const selectedPendingAction = selectedFinding ? pendingAction[selectedFinding.id] : undefined;
  const selectedExplain = selectedFinding ? explainById[selectedFinding.id] : undefined;
  const selectedPreview = selectedFinding ? previewById[selectedFinding.id] : undefined;

  const explainStatus: "idle" | "running" | "ready" | "error" =
    selectedPendingAction === "explain" ? "running"
    : selectedExplain?.status === "OK" ? "ready"
    : selectedExplain?.status === "ERROR" ? "error"
    : "idle";

  const previewStatus: "idle" | "running" | "ready" | "error" =
    selectedPendingAction === "preview" ? "running"
    : selectedPreview?.status === "OK" ? "ready"
    : selectedPreview?.status === "ERROR" ? "error"
    : "idle";

  const verifyStatus: "idle" | "running" | "ready" | "error" =
    selectedPendingAction === "apply" ? "running"
    : (selectedFinding ? applyById[selectedFinding.id] : undefined)?.status === "OK" ? "ready"
    : (selectedFinding ? applyById[selectedFinding.id] : undefined)?.status === "ERROR" ? "error"
    : "idle";

  const visibleModules = useMemo(
    () => (moduleFilter === "all" ? availableModules : availableModules.includes(moduleFilter) ? [moduleFilter] : []),
    [availableModules, moduleFilter],
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

  // ---- Table ----

  const columns = useMemo<ColumnDef<ViolationGroupRow>[]>(
    () => [
      {
        id: "expander",
        header: "",
        cell: ({ row }) => (
          <button type="button" className="p-1" onClick={row.getToggleExpandedHandler()}>
            {row.getIsExpanded() ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
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

  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table hook
  const table = useReactTable({
    data,
    columns,
    state: { sorting, expanded },
    onSortingChange: setSorting,
    onExpandedChange: setExpanded,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getExpandedRowModel: getExpandedRowModel(),
    getRowCanExpand: () => true,
  });

  // ---- Render ----

  return (
    <div className="space-y-4">
      <ControlsPanel
        viewPreset={viewPreset}
        onViewPresetChange={setViewPreset}
        moduleFilter={moduleFilter}
        onModuleFilterChange={setModuleFilter}
        availableModules={availableModules}
        evalIsFetching={evalQuery.isFetching}
        onEvalRefetch={() => evalQuery.refetch()}
        frameworkDemoReady={frameworkDemoReady}
        policyCatalogIsLoading={policyCatalogQuery.isLoading}
        policyCatalogIsError={policyCatalogQuery.isError}
        frameworkDemoScopeSource={frameworkDemoScopeSource}
      />

      <SummaryCards {...summary} />

      <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(360px,440px)] 2xl:items-start">
        <ViolationGroupTable
          table={table}
          columnCount={columns.length}
          viewPreset={viewPreset}
          selectedFindingId={selectedFindingId}
          onSelectFinding={setSelectedFindingId}
          expandedFindingByGroup={expandedFindingByGroup}
          onToggleFinding={toggleFindingExpanded}
          pendingAction={pendingAction}
          explainById={explainById}
          previewById={previewById}
          hasEvaluationResult={hasEvaluationResult}
          onExplain={(raw) => explainMutation.mutate(raw)}
          onPreview={(finding) => previewMutation.mutate(finding)}
          onApply={(finding) => applyMutation.mutate(finding)}
        />

        <FindingDetailPanel
          selectedFinding={selectedFinding}
          explainById={explainById}
          previewById={previewById}
          applyById={applyById}
          pendingAction={pendingAction}
          explainStatus={explainStatus}
          previewStatus={previewStatus}
          verifyStatus={verifyStatus}
          onExplain={(raw) => explainMutation.mutate(raw)}
          onPreview={(finding) => previewMutation.mutate(finding)}
          onApply={(finding) => applyMutation.mutate(finding)}
        />
      </div>
    </div>
  );
};

export default PolicyPage;
