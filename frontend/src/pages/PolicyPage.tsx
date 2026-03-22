import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { uniqueSortedModuleLabels } from "../lib/workspace";
import ControlsPanel from "../components/features/policy/ControlsPanel";
import FindingDetailPanel from "../components/features/policy/FindingDetailPanel";
import SummaryCards from "../components/features/policy/SummaryCards";
import ViolationGroupTable from "../components/features/policy/ViolationGroupTable";
import { usePolicyEval } from "../components/features/policy/hooks/usePolicyEval";
import { usePolicyMutations } from "../components/features/policy/hooks/usePolicyMutations";
import { useSelectionState } from "../components/features/policy/hooks/useSelectionState";
import { usePolicySummary } from "../components/features/policy/hooks/usePolicySummary";
import { useViolationTable } from "../components/features/policy/hooks/useViolationTable";
import {
  type PolicyExplainOneResponse,
  type PolicyViewPreset,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
  readPolicyViewPreset,
  readUploadedModules,
} from "../components/features/policy/policyUtils";

const PolicyPage = () => {
  const [viewPreset, setViewPreset] = useState<PolicyViewPreset>(() => readPolicyViewPreset());
  const [uploadedModules, setUploadedModules] = useState<string[]>(() => readUploadedModules());
  const [moduleFilter, setModuleFilter] = useState<string>("all");

  const {
    findings,
    hasEvaluationResult,
    frameworkDemoReady,
    frameworkDemoScopeSource,
    evalIsFetching,
    onEvalRefetch,
    policyCatalogIsLoading,
    policyCatalogIsError,
  } = usePolicyEval(viewPreset);

  const { explainMutation, previewMutation, applyMutation, pendingAction } = usePolicyMutations();

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

  // ---- Effects ----

  useEffect(() => {
    setUploadedModules(readUploadedModules());
  }, []);

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

  const {
    selectedFindingId,
    setSelectedFindingId,
    selectedFinding,
    expandedFindingByGroup,
    toggleFindingExpanded,
  } = useSelectionState(filteredFindings);

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

  const { table, columnCount, ruleCount } = useViolationTable(filteredFindings);
  const summary = usePolicySummary(filteredFindings, availableModules, moduleFilter, ruleCount);

  // ---- Render ----

  return (
    <div className="space-y-4">
      <ControlsPanel
        viewPreset={viewPreset}
        onViewPresetChange={setViewPreset}
        moduleFilter={moduleFilter}
        onModuleFilterChange={setModuleFilter}
        availableModules={availableModules}
        evalIsFetching={evalIsFetching}
        onEvalRefetch={onEvalRefetch}
        frameworkDemoReady={frameworkDemoReady}
        policyCatalogIsLoading={policyCatalogIsLoading}
        policyCatalogIsError={policyCatalogIsError}
        frameworkDemoScopeSource={frameworkDemoScopeSource}
      />

      <SummaryCards {...summary} />

      <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(360px,440px)] 2xl:items-start">
        <ViolationGroupTable
          table={table}
          columnCount={columnCount}
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
