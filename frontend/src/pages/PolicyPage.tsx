import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  type ColumnDef,
  type ExpandedState,
  type SortingState,
  useTable,
} from "@tanstack/react-table";
import { BookOpen, ChevronDown, ChevronRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { evaluatePolicies, exportPolicySarif, fetchPolicyCatalog, fetchPolicyPacks, importSarifReport } from "../lib/api";
import { cn } from "../lib/utils";
import { downloadSarifFile } from "../lib/sarif";
import type { PolicyCatalogResponse, PolicyEvaluateResponse, PolicyPacksResponse } from "../lib/types";
import {
  persistPolicyEvaluation,
  readPersistedUploadedModules,
  readPersistedPolicyEvaluation,
} from "../lib/persistence";
import { uniqueSortedModuleLabels } from "../lib/workspace";
import { messageMentionsBackendDependency } from "../lib/dependencies";
import { Badge } from "../components/ui/badge";
import ControlsPanel from "../components/features/policy/ControlsPanel";
import EvaluationStatusCard from "../components/features/policy/EvaluationStatusCard";
import FindingDetailPanel from "../components/features/policy/FindingDetailPanel";
import StandardRulesCatalogView from "../components/features/policy/StandardRulesCatalogView";
import SummaryCards from "../components/features/policy/SummaryCards";
import ViolationGroupTable from "../components/features/policy/ViolationGroupTable";
import {
  type PolicyViewPreset,
  type ViolationGroupRow,
  LEGACY_FRAMEWORK_DEMO_RULE_IDS,
  POLICY_VIEW_PRESET_STORAGE_KEY,
  deriveStandardFromRuleId,
  formatHumanRuleTitle,
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

const PolicyPage = () => {
  const queryClient = useQueryClient();
  const initialViewPreset = readPolicyViewPreset();

  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [expandedFindingByGroup, setExpandedFindingByGroup] = useState<Record<string, string | null>>({});
  const [viewPreset, setViewPreset] = useState<PolicyViewPreset>(initialViewPreset);
  const [uploadedModules, setUploadedModules] = useState<string[]>([]);
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedStandard, setSelectedStandard] = useState<string>("all");
  const [activeViewMode, setActiveViewMode] = useState<"findings" | "rules_catalog">("findings");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [isExportingSarif, setIsExportingSarif] = useState<boolean>(false);
  const [isImportingSarif, setIsImportingSarif] = useState<boolean>(false);
  const sarifFileInputRef = useRef<HTMLInputElement>(null);

  const toggleFindingExpanded = (groupId: string, findingId: string) => {
    setExpandedFindingByGroup((prev) => ({
      ...prev,
      [groupId]: prev[groupId] === findingId ? null : findingId,
    }));
  };

  // ---- Policy catalog + packs + eval queries ----

  const policyCatalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: ({ signal }) => fetchPolicyCatalog(signal),
  });

  const policyPacksQuery = useQuery<PolicyPacksResponse, Error>({
    queryKey: ["policyPacks"],
    queryFn: ({ signal }) => fetchPolicyPacks(signal),
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
    queryKey: evalQueryKey("all"),
    queryFn: ({ signal }) => evaluatePolicies(undefined, signal),
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
      const existing = queryClient.getQueryState(evalQueryKey("all"));
      if (existing?.data && (existing.dataUpdatedAt ?? 0) >= persisted.savedAt) return;
      queryClient.setQueryData(evalQueryKey("all"), persisted.data, {
        updatedAt: persisted.savedAt,
      });
      lastEvalToastAtRef.current = persisted.savedAt;
    })();
    return () => {
      cancelled = true;
    };
  }, [queryClient]);

  // ---- Effects ----

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

  const standardCounts = useMemo(() => {
    const base = effectiveModuleFilter === "all" ? findings : findings.filter((f) => f.module === effectiveModuleFilter);
    const countFor = (stdId: string) => {
      if (stdId === "all") return base.length;
      if (stdId === "sarif") return base.filter((f) => f.raw.evidence?.imported_from_sarif).length;
      return base.filter((f) => {
        const rule = (f.ruleId || "").toLowerCase();
        const std = stdId.toLowerCase();
        const rawMeta = (f.raw.control_metadata || {}) as Record<string, unknown>;
        const rawStd = String(rawMeta.standard || "").toLowerCase();
        return rule.includes(std) || rawStd.includes(std);
      }).length;
    };
    return {
      all: countFor("all"),
      iso: countFor("iso"),
      pci: countFor("pci"),
      owasp: countFor("owasp"),
      nist: countFor("nist"),
      sarif: countFor("sarif"),
    };
  }, [effectiveModuleFilter, findings]);

  const filteredFindings = useMemo(() => {
    let list = findings;
    if (effectiveModuleFilter !== "all") {
      list = list.filter((f) => f.module === effectiveModuleFilter);
    }
    if (selectedStandard !== "all") {
      if (selectedStandard === "sarif") {
        list = list.filter((f) => f.raw.evidence?.imported_from_sarif);
      } else {
        list = list.filter((f) => {
          const rule = (f.ruleId || "").toLowerCase();
          const std = selectedStandard.toLowerCase();
          const rawMeta = (f.raw.control_metadata || {}) as Record<string, unknown>;
          const rawStd = String(rawMeta.standard || "").toLowerCase();
          return rule.includes(std) || rawStd.includes(std);
        });
      }
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(
        (f) =>
          f.ruleId.toLowerCase().includes(q) ||
          f.targetMethod.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q) ||
          f.reason.toLowerCase().includes(q) ||
          f.controlLabel.toLowerCase().includes(q) ||
          f.cweLabel.toLowerCase().includes(q),
      );
    }
    return list;
  }, [effectiveModuleFilter, findings, searchQuery, selectedStandard]);

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
        header: "Rule / Standard",
        cell: ({ row }) => {
          const ruleId = row.original.ruleId;
          const humanTitle = formatHumanRuleTitle(ruleId);
          const standard = deriveStandardFromRuleId(ruleId);
          return (
            <div className="min-w-0">
              <span className="block min-w-0 truncate font-semibold text-xs text-zinc-900 dark:text-zinc-100" title={humanTitle}>
                {humanTitle}
              </span>
              <div className="mt-0.5 flex items-center gap-1.5">
                <span className="font-mono text-[10px] text-zinc-400 dark:text-zinc-500 truncate" title={ruleId}>
                  {ruleId}
                </span>
                <Badge variant="outline" className="px-1 py-0 text-[9px] text-zinc-500 border-zinc-200 dark:border-zinc-800 shrink-0">
                  {standard}
                </Badge>
              </div>
            </div>
          );
        },
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

  const handleExportSarif = async () => {
    try {
      setIsExportingSarif(true);
      const ruleIds = viewPreset === "framework_demo" ? frameworkDemoRuleIds : undefined;
      const doc = await exportPolicySarif({ ruleIds });
      const filename = `codegraph-${viewPreset === "framework_demo" ? "demo" : "full"}-findings.sarif.json`;
      const ok = downloadSarifFile(doc, filename);
      if (ok) {
        toast.success("SARIF v2.1.0 report exported.");
      } else {
        toast.error("Could not trigger file download.");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "SARIF export failed";
      toast.error(`SARIF export failed: ${msg}`);
    } finally {
      setIsExportingSarif(false);
    }
  };

  const handleImportSarifClick = () => {
    sarifFileInputRef.current?.click();
  };

  const handleSarifFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsImportingSarif(true);
    try {
      const text = await file.text();
      const res = await importSarifReport(text);
      if (res.count > 0) {
        toast.success(`Imported ${res.count} findings from SAST SARIF report.`);
        const existingData = evalQuery.data ?? {
          violations: [],
          catalog: [],
          rules_catalog: {},
          opa_runs: 1,
          bundle_count: 1,
          evaluation: {
            status: "complete",
            attempted_bundles: 1,
            evaluated_bundles: 1,
            failed_bundles: 0,
            omitted_findings: 0,
            excluded_findings: 0,
            truncated: false,
            scope_limited: false,
            rule_ids: [],
          },
        };

        const existingViolations = existingData.violations ?? [];
        const existingKeys = new Set(existingViolations.map((v) => `${v.violation_id ?? v.rule_id}:${v.method_key}`));
        const newViolations = res.violations.filter(
          (v) => !existingKeys.has(`${v.violation_id ?? v.rule_id}:${v.method_key}`),
        );

        queryClient.setQueryData(evalQueryKey(viewPreset), {
          ...existingData,
          violations: [...existingViolations, ...newViolations],
        });
      } else {
        toast.info("No findings found in the imported SARIF report.");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "SARIF import failed";
      toast.error(`SARIF import failed: ${msg}`);
    } finally {
      setIsImportingSarif(false);
      if (event.target) {
        event.target.value = "";
      }
    }
  };

  // ---- Render ----

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
        searchQuery={searchQuery}
        onSearchQueryChange={setSearchQuery}
        moduleFilter={effectiveModuleFilter}
        onModuleFilterChange={setModuleFilter}
        availableModules={availableModules}
        evalIsFetching={evalQuery.isFetching}
        onEvalRefetch={() => evalQuery.refetch()}
        policyCatalogIsLoading={policyCatalogQuery.isLoading}
        onExportSarif={handleExportSarif}
        isExportingSarif={isExportingSarif}
        onImportSarif={handleImportSarifClick}
        isImportingSarif={isImportingSarif}
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

      {/* Compliance Standard Filter Tabs + Dual Mode Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          {[
            { id: "all", label: "All Standards", count: standardCounts.all },
            { id: "iso", label: "ISO/IEC 27001", count: standardCounts.iso },
            { id: "pci", label: "PCI-DSS 4.0", count: standardCounts.pci },
            { id: "owasp", label: "OWASP Top 10", count: standardCounts.owasp },
            { id: "nist", label: "NIST SP 800-53", count: standardCounts.nist },
            { id: "sarif", label: "External SAST (SARIF)", count: standardCounts.sarif },
          ].map((tab) => {
            const active = selectedStandard === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setSelectedStandard(tab.id)}
                className={cn(
                  "rounded-lg px-3 py-1.5 font-medium transition-all cursor-pointer whitespace-nowrap text-xs flex items-center gap-1.5",
                  active
                    ? "bg-indigo-600 text-white shadow-xs font-semibold"
                    : "bg-white dark:bg-zinc-900 border border-slate-200/90 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800",
                )}
              >
                <span>{tab.label}</span>
                <span
                  className={cn(
                    "rounded-full px-1.5 py-0.2 text-[10px] font-mono",
                    active
                      ? "bg-indigo-700 text-indigo-100"
                      : "bg-slate-100 dark:bg-zinc-800 text-slate-600 dark:text-zinc-400",
                  )}
                >
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>

        {/* View Switcher: Active Findings vs Policy Rules Catalog */}
        <div className="flex items-center gap-1 bg-slate-100 dark:bg-zinc-800 p-1 rounded-lg text-xs shrink-0">
          <button
            type="button"
            onClick={() => setActiveViewMode("findings")}
            className={cn(
              "rounded-md px-3 py-1 text-xs font-medium transition cursor-pointer flex items-center gap-1.5",
              activeViewMode === "findings"
                ? "bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 shadow-2xs font-semibold"
                : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100",
            )}
          >
            <ShieldAlert className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
            <span>Active Violations ({filteredFindings.length})</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveViewMode("rules_catalog")}
            className={cn(
              "rounded-md px-3 py-1 text-xs font-medium transition cursor-pointer flex items-center gap-1.5",
              activeViewMode === "rules_catalog"
                ? "bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 shadow-2xs font-semibold"
                : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100",
            )}
          >
            <BookOpen className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400" />
            <span>Standards &amp; Rules Catalog</span>
          </button>
        </div>
      </div>

      {activeViewMode === "rules_catalog" ? (
        <StandardRulesCatalogView
          packs={policyPacksQuery.data?.packs ?? []}
          findings={findings}
          selectedStandard={selectedStandard}
          onSelectStandard={setSelectedStandard}
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
