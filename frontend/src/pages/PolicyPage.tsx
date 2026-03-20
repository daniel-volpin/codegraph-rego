import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ColumnDef,
  flexRender,
  getCoreRowModel,
  getExpandedRowModel,
  getSortedRowModel,
  SortingState,
  ExpandedState,
  useReactTable,
} from "@tanstack/react-table";
import { ChevronDown, ChevronRight, Copy, Loader2, Scale, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import {
  applyRemediation,
  evaluatePolicies,
  explainPolicyViolationOne,
  fetchPolicyCatalog,
  previewRemediation,
} from "../lib/api";
import type {
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  PolicyExplanationStructured,
  PolicyExplainOneResponse,
  RemediationCapability,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  UploadResponse,
} from "../lib/types";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import CodeHighlight from "../components/ui/CodeHighlight";
import {
  deriveModuleLabel,
  relativeToUploadedWorkspace,
  uniqueSortedModuleLabels,
} from "../lib/workspace";

type RawViolation = Record<string, unknown>;

interface ViolationRow {
  id: string;
  ruleId: string;
  severity: string;
  module: string;
  targetMethod: string;
  filePath: string;
  reason: string;
  snippet: string;
  remediation: RemediationCapability;
  raw: RawViolation;
}

interface ViolationGroupRow {
  id: string;
  ruleId: string;
  severity: string;
  findingCount: number;
  fileCount: number;
  fullSupportCount: number;
  guardedSupportCount: number;
  manualCount: number;
  findings: ViolationRow[];
}

interface PersistedPolicyEvaluation {
  data: PolicyEvaluateResponse;
  savedAt: number;
  preset: PolicyViewPreset;
}

type PolicyViewPreset = "all" | "framework_demo";
const LAST_UPLOAD_STORAGE_KEY = "codegraph:lastUpload";

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;

const asString = (value: unknown, fallback = "—") => (typeof value === "string" && value.trim() ? value : fallback);
const asBoolean = (value: unknown, fallback = false) => (typeof value === "boolean" ? value : fallback);

const compactTargetMethod = (value: string) => {
  if (!value || value === "—") return value;

  const openParen = value.indexOf("(");
  const prefix = openParen >= 0 ? value.slice(0, openParen) : value;
  const suffix = openParen >= 0 ? value.slice(openParen) : "";

  const parts = prefix.split(".").filter(Boolean);
  if (parts.length < 2) return value;

  const methodName = parts[parts.length - 1];
  const className = parts[parts.length - 2];
  return `${className}.${methodName}${suffix}`;
};

const normalizeRemediationCapability = (value: unknown): RemediationCapability => {
  const record = asRecord(value);
  return {
    supported: asBoolean(record?.supported, false),
    support_tier:
      record?.support_tier === "full" || record?.support_tier === "guarded" || record?.support_tier === "manual"
        ? record.support_tier
        : "manual",
    reason_code: asString(record?.reason_code ?? "unsupported_rule_for_auto_fix", "unsupported_rule_for_auto_fix"),
    strategy: typeof record?.strategy === "string" ? record.strategy : null,
    preview_available: asBoolean(record?.preview_available, false),
    verify_available: asBoolean(record?.verify_available, false),
    ui_apply_mode: record?.ui_apply_mode === "dry_run" ? "dry_run" : "dry_run",
    rationale: asString(record?.rationale ?? "Automatic remediation is not available for this rule.", "Automatic remediation is not available for this rule."),
    safe_refusal_possible: asBoolean(record?.safe_refusal_possible, false),
  };
};

const normalizeViolation = (item: RawViolation): ViolationRow => {
  const evidence = asRecord(item.evidence);
  const evidenceSnippet = evidence ? asString(evidence.source_code ?? "", "") : "";
  const remediation = normalizeRemediationCapability(item.remediation);
  const ruleId = asString(item.violation_id ?? item.rule_id);
  const targetMethod = asString(item.target_method);
  const filePath = asString(item.file_path);
  const severity = asString(item.severity, "MEDIUM").toUpperCase();
  return {
    id: `${ruleId}:${targetMethod}:${filePath}`,
    ruleId,
    severity,
    module: deriveModuleLabel(filePath),
    targetMethod,
    filePath,
    reason: asString(item.reason ?? item.description),
    // Prefer an empty string over the "—" placeholder so we can render an explicit
    // "snippet unavailable" message in the UI.
    snippet: asString(item.code_snippet ?? evidenceSnippet ?? item.updated_source_code ?? "", ""),
    remediation,
    raw: item,
  };
};

const severityVariant = (severity: string): "destructive" | "warning" | "secondary" => {
  if (severity === "HIGH") return "destructive";
  if (severity === "MEDIUM") return "warning";
  return "secondary";
};

const severityRank = (severity: string) => {
  if (severity === "HIGH") return 3;
  if (severity === "MEDIUM") return 2;
  if (severity === "LOW") return 1;
  return 0;
};

const readUploadedModules = (): string[] => {
  try {
    const raw = localStorage.getItem(LAST_UPLOAD_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as UploadResponse;
    const roots = parsed.java_roots?.length ? parsed.java_roots : parsed.java_root ? [parsed.java_root] : [];
    return uniqueSortedModuleLabels(roots.filter(Boolean));
  } catch {
    return [];
  }
};

const formatCitationDisplay = (citation: string) => {
  const trimmed = citation.trim();
  if (!trimmed) {
    return { display: citation, full: citation };
  }

  const match = trimmed.match(/^(.*?)(:\d+(?:-\d+)?)$/);
  const rawPath = match?.[1] ?? trimmed;
  const suffix = match?.[2] ?? "";
  const normalizedPath = rawPath.replace(/\\/g, "/");

  let displayPath = normalizedPath;
  const srcIndex = normalizedPath.indexOf("/src/");

  if (normalizedPath.includes("/uploaded_code/") || normalizedPath.startsWith("uploaded_code/")) {
    displayPath = relativeToUploadedWorkspace(normalizedPath);
  } else if (srcIndex >= 0) {
    displayPath = normalizedPath.slice(srcIndex + 1);
  } else {
    const parts = normalizedPath.split("/").filter(Boolean);
    if (parts.length > 4) {
      displayPath = parts.slice(-4).join("/");
    }
  }

  return {
    display: `${displayPath}${suffix}`,
    full: trimmed,
  };
};

const renderStructuredExplanation = (payload: PolicyExplanationStructured) => {
  const citation = formatCitationDisplay(payload.citation);
  return (
    <div className="space-y-3 rounded-md border border-indigo-200 bg-indigo-50 p-4 text-sm text-indigo-950">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Citation</p>
        <p className="mt-1 break-words font-mono text-xs text-indigo-900" title={citation.full}>
          {citation.display}
        </p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Why</p>
        <p className="mt-1 break-words">{payload.why}</p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Fix</p>
        <p className="mt-1 break-words">{payload.fix}</p>
      </div>
    </div>
  );
};

const remediationSummaryText = (capability: RemediationCapability) =>
  capability.support_tier === "full"
    ? "Preview suggests a bounded fix without compilation. Verify fix (dry run) runs compile and policy re-checks without persisting changes."
    : capability.support_tier === "guarded"
      ? "This rule supports guarded remediation. The system may safely return NO_FIX when a minimal secure change is not evident from method-local context."
      : "This rule is explanation-first and remains manual review only. Automatic remediation is intentionally disabled for this category.";

const remediationBadgeLabel = (capability: RemediationCapability) => {
  if (capability.support_tier === "full") return "Auto-fix available";
  if (capability.support_tier === "guarded") return "Auto-fix with safety checks";
  return "Manual review required";
};

const remediationBadgeVariant = (capability: RemediationCapability): "success" | "secondary" => {
  return capability.support_tier === "manual" ? "secondary" : "success";
};

const ruleGroupStatusLabel = (group: ViolationGroupRow) => {
  if (group.fullSupportCount > 0 && group.guardedSupportCount > 0) {
    return `${group.fullSupportCount} auto-fixable, ${group.guardedSupportCount} guarded`;
  }
  if (group.fullSupportCount > 0) {
    return `${group.fullSupportCount} auto-fixable`;
  }
  if (group.guardedSupportCount > 0) {
    return `${group.guardedSupportCount} with safety checks`;
  }
  return "Manual review only";
};

const ruleGroupStatusVariant = (group: ViolationGroupRow): "success" | "secondary" => {
  return group.fullSupportCount > 0 || group.guardedSupportCount > 0 ? "success" : "secondary";
};

const LEGACY_FRAMEWORK_DEMO_RULE_IDS = [
  "ISO-A.10-WEAK-HASH",
  "ISO-A.10-WEAK-RANDOM",
  "ISO-A.10-WEAK-CRYPTO",
  "ISO-A.8-SQL-INJECTION",
  "ISO-A.8-PATH-TRAVERSAL",
  "ISO-A.8-CMD-INJECTION",
  "ISO-A.8-LDAP-INJECTION",
  "ISO-A.8-XPATH-INJECTION",
];
const POLICY_EVALUATION_STORAGE_KEY = "codegraph:policy:lastEvaluation";
const POLICY_VIEW_PRESET_STORAGE_KEY = "codegraph:policy:viewPreset";

const readPolicyViewPreset = (): PolicyViewPreset => {
  try {
    const saved = localStorage.getItem(POLICY_VIEW_PRESET_STORAGE_KEY);
    return saved === "framework_demo" ? "framework_demo" : "all";
  } catch {
    return "all";
  }
};

const readPersistedPolicyEvaluation = (preset: PolicyViewPreset): PersistedPolicyEvaluation | null => {
  try {
    const saved = localStorage.getItem(POLICY_EVALUATION_STORAGE_KEY);
    if (!saved) return null;
    const parsed = JSON.parse(saved) as Partial<PersistedPolicyEvaluation>;
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !parsed.data ||
      typeof parsed.savedAt !== "number" ||
      (parsed.preset !== "all" && parsed.preset !== "framework_demo")
    ) {
      return null;
    }
    if (parsed.preset !== preset) return null;
    return {
      data: parsed.data as PolicyEvaluateResponse,
      savedAt: parsed.savedAt,
      preset: parsed.preset,
    };
  } catch {
    return null;
  }
};

const persistPolicyEvaluation = (data: PolicyEvaluateResponse, preset: PolicyViewPreset) => {
  try {
    const payload: PersistedPolicyEvaluation = {
      data,
      savedAt: Date.now(),
      preset,
    };
    localStorage.setItem(POLICY_EVALUATION_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    /* ignore storage errors */
  }
};

const uniqueRuleIds = (ruleIds: string[]) => Array.from(new Set(ruleIds.filter((ruleId) => ruleId.trim())));

const groupViolationsByRule = (violations: ViolationRow[]): ViolationGroupRow[] => {
  const groups = new Map<string, ViolationRow[]>();
  for (const violation of violations) {
    const key = violation.ruleId || "unknown-rule";
    const current = groups.get(key);
    if (current) {
      current.push(violation);
    } else {
      groups.set(key, [violation]);
    }
  }

  return Array.from(groups.entries()).map(([ruleId, findings]) => {
    const sortedFindings = [...findings].sort((left, right) => {
      const severityDiff = severityRank(right.severity) - severityRank(left.severity);
      if (severityDiff !== 0) return severityDiff;
      const fileDiff = left.filePath.localeCompare(right.filePath);
      if (fileDiff !== 0) return fileDiff;
      return left.targetMethod.localeCompare(right.targetMethod);
    });

    const fileCount = new Set(sortedFindings.map((finding) => finding.filePath)).size;
    const fullSupportCount = sortedFindings.filter((finding) => finding.remediation.support_tier === "full").length;
    const guardedSupportCount = sortedFindings.filter((finding) => finding.remediation.support_tier === "guarded").length;
    const manualCount = sortedFindings.filter((finding) => finding.remediation.support_tier === "manual").length;
    const highestSeverity = sortedFindings.reduce(
      (current, finding) => (severityRank(finding.severity) > severityRank(current) ? finding.severity : current),
      sortedFindings[0]?.severity ?? "LOW",
    );

    return {
      id: ruleId,
      ruleId,
      severity: highestSeverity,
      findingCount: sortedFindings.length,
      fileCount,
      fullSupportCount,
      guardedSupportCount,
      manualCount,
      findings: sortedFindings,
    };
  });
};

type PendingAction = "explain" | "preview" | "apply";

const PolicyPage = () => {
  const queryClient = useQueryClient();
  const initialViewPreset = readPolicyViewPreset();
  const initialEvalSnapshotRef = useRef<Record<PolicyViewPreset, PersistedPolicyEvaluation | null>>({
    all: readPersistedPolicyEvaluation("all"),
    framework_demo: readPersistedPolicyEvaluation("framework_demo"),
  });
  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [expandedFindingByGroup, setExpandedFindingByGroup] = useState<Record<string, string | null>>({});
  const [viewPreset, setViewPreset] = useState<PolicyViewPreset>(initialViewPreset);
  const [uploadedModules, setUploadedModules] = useState<string[]>(() => readUploadedModules());
  const [moduleFilter, setModuleFilter] = useState<string>("all");
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

  // Cache per-violation side-results (preview/apply/explain) in React Query so they
  // persist across route navigation, but still GC after a while.
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

  const previewById = previewByIdQuery.data;
  const explainById = explainByIdQuery.data;
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

  // Keep the last evaluation results in the React Query cache so they survive route navigation.
  const evalQuery = useQuery<PolicyEvaluateResponse, Error>({
    queryKey: ["policyEvaluation:last", viewPreset],
    queryFn: () =>
      evaluatePolicies({
        ruleIds: viewPreset === "framework_demo" ? frameworkDemoRuleIds : undefined,
      }),
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
    mutationFn: (row: ViolationRow) => applyRemediation({ violation_id: row.ruleId, target_method: row.targetMethod, file_path: row.filePath }),
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

  const findings = useMemo(() => {
    const result: PolicyEvaluateResponse | undefined = evalQuery.data;
    return (result?.violations ?? []).map((v) => normalizeViolation(v));
  }, [evalQuery.data]);

  const availableModules = useMemo(
    () => uniqueSortedModuleLabels([...uploadedModules, ...findings.map((finding) => finding.filePath)]),
    [findings, uploadedModules],
  );

  useEffect(() => {
    if (moduleFilter !== "all" && !availableModules.includes(moduleFilter)) {
      setModuleFilter("all");
    }
  }, [availableModules, moduleFilter]);

  const filteredFindings = useMemo(
    () => (moduleFilter === "all" ? findings : findings.filter((finding) => finding.module === moduleFilter)),
    [findings, moduleFilter],
  );
  const visibleModules = useMemo(() => {
    if (moduleFilter === "all") {
      return availableModules;
    }
    return availableModules.includes(moduleFilter) ? [moduleFilter] : [];
  }, [availableModules, moduleFilter]);

  const data = useMemo(() => groupViolationsByRule(filteredFindings), [filteredFindings]);

  const summary = useMemo(
    () => ({
      findingCount: filteredFindings.length,
      ruleCount: data.length,
      moduleCount: visibleModules.length,
      fullSupportCount: filteredFindings.filter((finding) => finding.remediation.support_tier === "full").length,
      guardedSupportCount: filteredFindings.filter((finding) => finding.remediation.support_tier === "guarded").length,
      manualReviewCount: filteredFindings.filter((finding) => finding.remediation.support_tier === "manual").length,
    }),
    [data.length, filteredFindings, visibleModules.length],
  );
  const hasEvaluationResult = Boolean(evalQuery.data || evalQuery.dataUpdatedAt);

  const colWidthClass = (colId: string) => {
    // Needs table-fixed on the table for these widths to be honored.
    // Use percentages so the table always fits the available main-content width.
    if (colId === "expander") return "w-[4%]";
    if (colId === "ruleId") return "w-[24%]";
    if (colId === "severity") return "w-[10%]";
    if (colId === "findingCount") return "w-[12%]";
    if (colId === "fileCount") return "w-[12%]";
    if (colId === "status") return "w-[24%]";
    return "";
  };

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
        cell: ({ row }) => {
          const full = row.original.ruleId;
          return (
            <span className="block min-w-0 truncate font-mono text-xs text-slate-800" title={full}>
              {full}
            </span>
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
          <Badge variant={ruleGroupStatusVariant(row.original)}>
            {ruleGroupStatusLabel(row.original)}
          </Badge>
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
    // We use expansion as a "details row" pattern, not for hierarchical sub-rows.
    getRowCanExpand: () => true,
  });

  return (
    <div className="space-y-4">
      <Card className="p-6">
        <div className="grid gap-4 lg:grid-cols-[minmax(380px,1fr)_auto] lg:items-center">
          <div className="grid gap-4 xl:grid-cols-2">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-600">View mode</label>
              <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <button
                  type="button"
                  role="switch"
                  aria-checked={viewPreset === "framework_demo"}
                  aria-label="Toggle framework demo focus"
                  onClick={() => setViewPreset((current) => (current === "all" ? "framework_demo" : "all"))}
                  className={`relative inline-flex h-7 w-14 items-center rounded-full border transition-colors ${
                    viewPreset === "framework_demo"
                      ? "border-indigo-600 bg-indigo-600"
                      : "border-slate-300 bg-slate-200"
                  }`}
                >
                  <span
                    className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                      viewPreset === "framework_demo" ? "translate-x-8" : "translate-x-1"
                    }`}
                  />
                </button>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-900">Framework demo focus</p>
                  <p className="text-xs text-slate-500">
                    {viewPreset === "framework_demo"
                      ? "On. Show only the benchmark-aligned framework categories."
                      : "Off. Show the full policy surface for the current upload."}
                  </p>
                </div>
              </div>
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-slate-600">Module filter</label>
              <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                <select
                  value={moduleFilter}
                  onChange={(event) => setModuleFilter(event.target.value)}
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900"
                >
                  <option value="all">All modules</option>
                  {availableModules.map((module) => (
                    <option key={module} value={module}>
                      {module}
                    </option>
                  ))}
                </select>
                <p className="mt-2 text-xs text-slate-500">
                  Filter findings to one uploaded module while keeping the active upload workspace unchanged.
                </p>
                {viewPreset === "framework_demo" && policyCatalogQuery.isError && (
                  <p className="mt-2 text-xs text-amber-700">
                    Framework demo metadata could not be loaded from the backend. Falling back to the legacy thesis demo rule set.
                  </p>
                )}
                {viewPreset === "framework_demo" && !policyCatalogQuery.isLoading && frameworkDemoScopeSource === "legacy_fallback" && !policyCatalogQuery.isError && (
                  <p className="mt-2 text-xs text-amber-700">
                    Backend demo metadata is unavailable on this server response. Using the legacy thesis demo rule set for compatibility.
                  </p>
                )}
              </div>
            </div>
          </div>
          <div className="flex lg:justify-end lg:self-center">
            <Button
              onClick={() => evalQuery.refetch()}
              disabled={evalQuery.isFetching || !frameworkDemoReady || policyCatalogQuery.isLoading}
              title={
                viewPreset === "framework_demo"
                  ? "Evaluate only the benchmark-aligned framework demo categories."
                  : "Evaluate the full policy surface for the current upload."
              }
              className="w-full lg:min-w-[18rem] lg:w-auto"
            >
              {evalQuery.isFetching ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {viewPreset === "framework_demo" ? "Running demo scan..." : "Running full scan..."}
                </>
              ) : policyCatalogQuery.isLoading && viewPreset === "framework_demo" ? (
                "Loading demo scope..."
              ) : (
                viewPreset === "framework_demo" ? "Run Framework Demo Scan" : "Run Full Policy Scan"
              )}
            </Button>
          </div>
        </div>
      </Card>

      <div className="grid gap-3 md:grid-cols-6">
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Findings</p>
          <p className="mt-2 text-2xl font-semibold text-slate-900">{summary.findingCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Rules</p>
          <p className="mt-2 text-2xl font-semibold text-slate-900">{summary.ruleCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Modules</p>
          <p className="mt-2 text-2xl font-semibold text-slate-900">{summary.moduleCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Auto-fixable</p>
          <p className="mt-2 text-2xl font-semibold text-emerald-700">{summary.fullSupportCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Guarded fixes</p>
          <p className="mt-2 text-2xl font-semibold text-amber-700">{summary.guardedSupportCount}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Manual review</p>
          <p className="mt-2 text-2xl font-semibold text-slate-900">{summary.manualReviewCount}</p>
        </Card>
      </div>

      <Card className="overflow-hidden">
        {viewPreset === "framework_demo" && (
          <div className="border-b border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            Showing the benchmark-aligned categories used in the thesis framework demo. Switch to All findings to inspect the full policy surface.
          </div>
        )}
        <div className="overflow-auto">
          <table className="w-full table-fixed border-collapse text-sm">
            <thead className="bg-slate-100 text-left text-slate-700">
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      className={`px-3 py-2 font-semibold overflow-hidden ${colWidthClass(header.column.id)}`}
                    >
                      {header.isPlaceholder ? null : (
                        <button
                          className="inline-flex items-center gap-1"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                        </button>
                      )}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <Fragment key={row.id}>
                  <tr key={row.id} className="border-t border-slate-200">
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} className={`px-3 py-2 align-top overflow-hidden ${colWidthClass(cell.column.id)}`}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                  {row.getIsExpanded() && (
                    <tr className="border-t border-slate-100 bg-slate-50">
                      <td className="px-4 py-4" colSpan={columns.length}>
                        <div className="space-y-4">
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <div>
                              <p className="text-sm font-semibold text-slate-900">{row.original.ruleId}</p>
                              <p className="text-sm text-slate-600">
                                {row.original.findingCount} findings across {row.original.fileCount} files
                              </p>
                            </div>
                            <Badge variant={ruleGroupStatusVariant(row.original)}>
                              {ruleGroupStatusLabel(row.original)}
                            </Badge>
                          </div>

                          <div className="space-y-3">
                            {row.original.findings.map((finding) => {
                              const rowPending = pendingAction[finding.id];
                              const remediation = finding.remediation;
                              const isBusy = !!rowPending;
                              const previewDisabled = isBusy || !remediation.preview_available;
                              const verifyDisabled = isBusy || !remediation.verify_available;
                              const isFindingExpanded = expandedFindingByGroup[row.original.id] === finding.id;

                              return (
                                <div key={finding.id} className="rounded-lg border border-slate-200 bg-white">
                                  <button
                                    type="button"
                                    className="flex w-full flex-wrap items-start justify-between gap-3 p-4 text-left"
                                    onClick={() => toggleFindingExpanded(row.original.id, finding.id)}
                                  >
                                    <div className="flex min-w-0 items-start gap-3">
                                      {isFindingExpanded ? (
                                        <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                                      ) : (
                                        <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                                      )}
                                      <div className="min-w-0">
                                        <p className="truncate font-mono text-sm text-slate-900" title={finding.targetMethod}>
                                          {compactTargetMethod(finding.targetMethod)}
                                        </p>
                                        <p className="mt-1 truncate font-mono text-xs text-slate-500" title={finding.filePath}>
                                          {finding.filePath}
                                        </p>
                                        <div className="mt-2">
                                          <Badge variant="secondary">{finding.module}</Badge>
                                        </div>
                                      </div>
                                    </div>
                                    <div className="flex flex-wrap gap-2">
                                      <Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge>
                                      <Badge variant={remediationBadgeVariant(remediation)}>
                                        {remediationBadgeLabel(remediation)}
                                      </Badge>
                                    </div>
                                  </button>

                                  {isFindingExpanded && (
                                    <div className="border-t border-slate-200 p-4">
                                      <div className="space-y-4">
                                        <p className="text-sm text-slate-700">{finding.reason}</p>

                                        <div className="flex flex-wrap gap-2">
                                          <Button
                                            variant="outline"
                                            size="sm"
                                            disabled={isBusy}
                                            title="Generate a concise explanation of why this finding matters and how to address it."
                                            onClick={() => explainMutation.mutate(finding.raw)}
                                          >
                                            {rowPending === "explain" ? (
                                              <>
                                                <Loader2 className="mr-1 h-4 w-4 animate-spin" /> Explaining…
                                              </>
                                            ) : (
                                              <>
                                                <Sparkles className="mr-1 h-4 w-4" /> Explain finding
                                              </>
                                            )}
                                          </Button>
                                          <Button
                                            variant="secondary"
                                            size="sm"
                                            disabled={previewDisabled}
                                            title="Generate a proposed code change and check it virtually without compiling or modifying source files."
                                            onClick={() => previewMutation.mutate(finding)}
                                          >
                                            {rowPending === "preview" ? (
                                              <>
                                                <Loader2 className="mr-1 h-4 w-4 animate-spin" /> Previewing…
                                              </>
                                            ) : (
                                              <>Preview suggested fix</>
                                            )}
                                          </Button>
                                          <Button
                                            variant="default"
                                            size="sm"
                                            disabled={verifyDisabled}
                                            title="Run the full dry-run remediation pipeline: generate a fix, compile in a temp workspace, re-ingest, and re-check policies. No source files are persisted from the UI."
                                            onClick={() => applyMutation.mutate(finding)}
                                          >
                                            {rowPending === "apply" ? (
                                              <>
                                                <Loader2 className="mr-1 h-4 w-4 animate-spin" /> Applying…
                                              </>
                                            ) : (
                                              <>Verify fix (dry run)</>
                                            )}
                                          </Button>
                                        </div>

                                        <p className="text-xs text-slate-500">{remediationSummaryText(remediation)}</p>
                                        <p className="text-xs text-slate-500">{remediation.rationale}</p>

                                        {explainById[finding.id]?.status === "ERROR" && explainById[finding.id]?.error && (
                                          <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                                            {explainById[finding.id].error}
                                          </div>
                                        )}

                                        {explainById[finding.id]?.status === "OK" &&
                                          (explainById[finding.id]?.explanation_structured ||
                                            explainById[finding.id]?.explanation) &&
                                          (explainById[finding.id]?.explanation_structured ? (
                                            renderStructuredExplanation(explainById[finding.id].explanation_structured!)
                                          ) : (
                                            <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50 p-4 text-indigo-900 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                                              <Markdown>{explainById[finding.id].explanation!}</Markdown>
                                            </div>
                                          ))}

                                        <div className="rounded-lg border border-slate-200">
                                          <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
                                            <span className="text-xs font-semibold uppercase text-slate-500">Code snippet</span>
                                            <Button
                                              variant="ghost"
                                              size="sm"
                                              onClick={() => {
                                                navigator.clipboard.writeText(finding.snippet || "");
                                                toast.success("Code copied.");
                                              }}
                                            >
                                              <Copy className="mr-1 h-4 w-4" /> Copy
                                            </Button>
                                          </div>
                                          <CodeHighlight
                                            code={finding.snippet || "// snippet unavailable"}
                                            language="java"
                                            wrapLongLines
                                            maxHeight={320}
                                          />
                                        </div>

                                        {previewById[finding.id]?.error && (
                                          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                                            <strong>Preview error:</strong> {previewById[finding.id].error}
                                          </div>
                                        )}
                                        {previewById[finding.id]?.diff && (
                                          <div className="rounded-lg border border-slate-200">
                                            <div className="border-b border-slate-200 px-3 py-2">
                                              <span className="text-xs font-semibold uppercase text-slate-500">Remediation Diff</span>
                                            </div>
                                            <pre className="overflow-auto whitespace-pre-wrap break-words bg-white p-3 text-xs">
                                              {previewById[finding.id].diff}
                                            </pre>
                                          </div>
                                        )}
                                        {!previewById[finding.id]?.diff && previewById[finding.id]?.explanation && (
                                          <div className="prose prose-sm max-w-none rounded-md border border-emerald-200 bg-emerald-50 p-4 text-emerald-900 break-words">
                                            <strong>Preview:</strong>
                                            <Markdown>{previewById[finding.id].explanation!}</Markdown>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {data.length === 0 && (
                <tr>
                  <td colSpan={columns.length} className="py-12 text-center">
                    <Scale className="mx-auto h-10 w-10 text-slate-300" />
                    <p className="mt-3 text-sm text-slate-500">
                      {hasEvaluationResult
                        ? "No rule groups matched the current policy scan."
                        : "No rule groups loaded yet. Run a policy evaluation to see results."}
                    </p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default PolicyPage;
