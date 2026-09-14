import { useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { type ExpandedState, type SortingState, useTable } from "@tanstack/react-table";
import { evalQueryKey, evaluationErrorTitle, usePolicyEvaluationData } from "../hooks/usePolicyEvaluationData";
import { usePolicyFindingsFilter } from "../hooks/usePolicyFindingsFilter";
import { useSarifActions } from "../hooks/useSarifActions";
import ControlsPanel from "../components/features/policy/ControlsPanel";
import EvaluationStatusCard from "../components/features/policy/EvaluationStatusCard";
import FindingDetailPanel from "../components/features/policy/FindingDetailPanel";
import PolicyViewControls from "../components/features/policy/PolicyViewControls";
import StandardRulesCatalogView from "../components/features/policy/StandardRulesCatalogView";
import SummaryCards from "../components/features/policy/SummaryCards";
import ViolationGroupTable from "../components/features/policy/ViolationGroupTable";
import { createPolicyTableColumns } from "../components/features/policy/policyTableColumns";
import { policyTableFeatures } from "../components/features/policy/tableFeatures";
import { Card } from "../components/ui/card";

const PolicyPage = () => {
  const queryClient = useQueryClient();
  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [expandedFindingByGroup, setExpandedFindingByGroup] = useState<Record<string, string | null>>({});
  const [activeViewMode, setActiveViewMode] = useState<"findings" | "rules_catalog">("findings");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const toggleFindingExpanded = (groupId: string, findingId: string) => {
    setExpandedFindingByGroup((prev) => ({
      ...prev,
      [groupId]: prev[groupId] === findingId ? null : findingId,
    }));
  };

  const {
    policyCatalogQuery,
    policyPacksQuery,
    evalQuery,
    uploadedModules,
    findings,
    hasEvaluationResult,
    evaluationError,
    responseIsPartial,
  } = usePolicyEvaluationData();

  const {
    moduleFilter: effectiveModuleFilter,
    setModuleFilter,
    searchQuery,
    setSearchQuery,
    selectedStandard,
    setSelectedStandard,
    availableModules,
    standardCounts,
    filteredFindings,
    data,
    summary,
    tableEmptyMessage,
  } = usePolicyFindingsFilter(findings, uploadedModules, {
    hasEvaluationResult,
    evaluationError,
    responseIsPartial,
  });

  const {
    isExportingSarif,
    isImportingSarif,
    sarifFileInputRef,
    handleExportSarif,
    handleImportSarifClick,
    handleSarifFileChange,
  } = useSarifActions(evalQuery.data, (data) => queryClient.setQueryData(evalQueryKey(), data));

  const effectiveSelectedFindingId =
    selectedFindingId && filteredFindings.some((f) => f.id === selectedFindingId)
      ? selectedFindingId
      : (filteredFindings[0]?.id ?? null);

  const selectedFinding = useMemo(
    () => filteredFindings.find((f) => f.id === effectiveSelectedFindingId) ?? null,
    [effectiveSelectedFindingId, filteredFindings],
  );

  const columns = useMemo(() => createPolicyTableColumns(), []);

  const table = useTable({
    data,
    columns,
    features: policyTableFeatures,
    state: { sorting, expanded },
    onSortingChange: setSorting,
    onExpandedChange: setExpanded,
    getRowCanExpand: () => true,
  });

  return (
    <div className="space-y-4">
      <input
        type="file"
        ref={sarifFileInputRef}
        data-testid="sarif-file-input"
        accept=".json,.sarif"
        className="hidden"
        onChange={handleSarifFileChange}
      />
      <Card className="p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">Policy Evaluation</h1>
        <p className="mt-1 max-w-3xl text-xs text-zinc-600 dark:text-zinc-400">
          Run benchmark-aligned compliance evaluations, review grouped violations, and inspect remediation support across your codebase.
        </p>
      </Card>

      <ControlsPanel
        search={{
          searchQuery,
          onSearchQueryChange: setSearchQuery,
          moduleFilter: effectiveModuleFilter,
          onModuleFilterChange: setModuleFilter,
          availableModules,
        }}
        sarif={{
          onExportSarif: handleExportSarif,
          isExportingSarif,
          onImportSarif: handleImportSarifClick,
          isImportingSarif,
          disabled: evalQuery.isFetching,
        }}
        scan={{
          evalIsFetching: evalQuery.isFetching,
          onEvalRefetch: () => evalQuery.refetch(),
          policyCatalogIsLoading: policyCatalogQuery.isLoading,
        }}
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

      <PolicyViewControls
        selectedStandard={selectedStandard}
        onSelectedStandardChange={setSelectedStandard}
        standardCounts={standardCounts}
        activeViewMode={activeViewMode}
        onActiveViewModeChange={setActiveViewMode}
        filteredFindingsCount={filteredFindings.length}
      />

      {activeViewMode === "rules_catalog" ? (
        <StandardRulesCatalogView
          packs={policyPacksQuery.data?.packs ?? []}
          findings={findings}
          selectedStandard={selectedStandard}
          onSelectRuleInFindings={(ruleId) => {
            setSearchQuery(ruleId);
            setActiveViewMode("findings");
          }}
        />
      ) : (
        <>
          <SummaryCards {...summary} />

          <div
            data-testid="policy-results-layout"
            className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(420px,540px)] xl:items-start"
          >
            <ViolationGroupTable
              table={table}
              columnCount={columns.length}
              selectedFindingId={effectiveSelectedFindingId}
              onSelectFinding={setSelectedFindingId}
              expandedFindingByGroup={expandedFindingByGroup}
              onToggleFinding={toggleFindingExpanded}
              hasEvaluationResult={hasEvaluationResult}
              emptyMessage={tableEmptyMessage}
            />

            <FindingDetailPanel key={selectedFinding?.id ?? "empty"} selectedFinding={selectedFinding} />
          </div>
        </>
      )}
    </div>
  );
};

export default PolicyPage;
