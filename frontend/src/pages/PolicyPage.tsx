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
  RemediationApplyResponse,
  RemediationPreviewResponse,
} from "../lib/types";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import CodeHighlight from "../components/ui/CodeHighlight";

type RawViolation = Record<string, unknown>;

interface ViolationRow {
  id: string;
  ruleId: string;
  severity: string;
  targetMethod: string;
  filePath: string;
  reason: string;
  snippet: string;
  raw: RawViolation;
  autoRemediable: boolean;
}

const asRecord = (value: unknown): Record<string, unknown> | undefined =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;

const AUTO_RULES = new Set(["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-CRYPTO", "A.10-WEAK-HASH", "A.10-WEAK-CRYPTO"]);

const asString = (value: unknown, fallback = "—") => (typeof value === "string" && value.trim() ? value : fallback);

const basenameFromPath = (value: string) => {
  if (!value || value === "—") return value;
  const normalized = value.replace(/\\/g, "/");
  const last = normalized.split("/").filter(Boolean).pop();
  return last?.trim() ? last : value;
};

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

const normalizeViolation = (item: RawViolation): ViolationRow => {
  const evidence = asRecord(item.evidence);
  const evidenceSnippet = evidence ? asString(evidence.source_code ?? "", "") : "";
  const ruleId = asString(item.violation_id ?? item.rule_id);
  const targetMethod = asString(item.target_method);
  const filePath = asString(item.file_path);
  const severity = asString(item.severity, "MEDIUM").toUpperCase();
  return {
    id: `${ruleId}:${targetMethod}:${filePath}`,
    ruleId,
    severity,
    targetMethod,
    filePath,
    reason: asString(item.reason ?? item.description),
    // Prefer an empty string over the "—" placeholder so we can render an explicit
    // "snippet unavailable" message in the UI.
    snippet: asString(item.code_snippet ?? evidenceSnippet ?? item.updated_source_code ?? "", ""),
    raw: item,
    autoRemediable: AUTO_RULES.has(ruleId),
  };
};

const severityVariant = (severity: string): "destructive" | "warning" | "secondary" => {
  if (severity === "HIGH") return "destructive";
  if (severity === "MEDIUM") return "warning";
  return "secondary";
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
  const uploadedIndex = normalizedPath.indexOf("/uploaded_code/");
  const srcIndex = normalizedPath.indexOf("/src/");

  if (uploadedIndex >= 0) {
    displayPath = normalizedPath.slice(uploadedIndex + 1);
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

type PendingAction = "explain" | "preview" | "apply";

const PolicyPage = () => {
  const queryClient = useQueryClient();
  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [maxTotal, setMaxTotal] = useState(5);
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

  useEffect(() => {
    try {
      const saved = localStorage.getItem("codegraph:policy:maxTotalViolations");
      if (!saved) return;
      const parsed = Number(saved);
      if (Number.isFinite(parsed) && parsed > 0) setMaxTotal(parsed);
    } catch {
      /* ignore storage errors */
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem("codegraph:policy:maxTotalViolations", String(maxTotal));
    } catch {
      /* ignore storage errors */
    }
  }, [maxTotal]);

  useQuery<PolicyCatalogResponse, Error>({ queryKey: ["policyCatalog"], queryFn: fetchPolicyCatalog });

  const lastEvalToastAtRef = useRef(0);
  const lastEvalErrorToastAtRef = useRef(0);

  // Keep the last evaluation results in the React Query cache so they survive route navigation.
  const evalQuery = useQuery<PolicyEvaluateResponse, Error>({
    queryKey: ["policyEvaluation:last"],
    queryFn: () => evaluatePolicies({ maxTotalViolations: maxTotal }),
    enabled: false,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
    retry: false,
  });

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

  const data = useMemo(() => {
    const result: PolicyEvaluateResponse | undefined = evalQuery.data;
    return (result?.violations ?? []).map((v) => normalizeViolation(v));
  }, [evalQuery.data]);

  const colWidthClass = (colId: string) => {
    // Needs table-fixed on the table for these widths to be honored.
    // Use percentages so the table always fits the available main-content width.
    if (colId === "expander") return "w-[4%]";
    if (colId === "ruleId") return "w-[20%]";
    if (colId === "severity") return "w-[10%]";
    if (colId === "targetMethod") return "w-[32%]";
    if (colId === "filePath") return "w-[16%]";
    if (colId === "status") return "w-[18%]";
    return "";
  };

  const columns = useMemo<ColumnDef<ViolationRow>[]>(
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
        accessorKey: "targetMethod",
        header: "Target Method",
        cell: ({ row }) => {
          const full = row.original.targetMethod;
          const compact = compactTargetMethod(full);
          return (
            <span className="block min-w-0 truncate font-mono text-xs text-slate-800" title={full}>
              {compact}
            </span>
          );
        },
      },
      {
        accessorKey: "filePath",
        header: "File",
        cell: ({ row }) => {
          const full = row.original.filePath;
          const compact = basenameFromPath(full);
          return (
            <span className="block min-w-0 truncate font-mono text-xs text-slate-800" title={full}>
              {compact}
            </span>
          );
        },
      },
      {
        id: "status",
        header: "Remediation",
        cell: ({ row }) => (
          <Badge variant={row.original.autoRemediable ? "success" : "secondary"}>
            {row.original.autoRemediable ? "Auto-remediable" : "Manual fix required"}
          </Badge>
        ),
      },
    ],
    [],
  );

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
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">max_total_violations</label>
            <Input type="number" value={maxTotal} onChange={(e) => setMaxTotal(Number(e.target.value))} className="w-44" />
          </div>
          <Button onClick={() => evalQuery.refetch()} disabled={evalQuery.isFetching}>
            {evalQuery.isFetching ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Evaluating...
              </>
            ) : (
              "Run Policy Evaluation"
            )}
          </Button>
        </div>
      </Card>

      <Card className="overflow-hidden">
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
                          <p className="text-sm text-slate-700">{row.original.reason}</p>
                          {(() => {
                            const rowPending = pendingAction[row.original.id];
                            const isDisabled = !!rowPending;
                            return (
                              <div className="flex flex-wrap gap-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  disabled={isDisabled}
                                  title="Ask the LLM to explain this violation, its impact, and how to fix it"
                                  onClick={() => explainMutation.mutate(row.original.raw)}
                                >
                                  {rowPending === "explain"
                                    ? <><Loader2 className="mr-1 h-4 w-4 animate-spin" /> Explaining…</>
                                    : <><Sparkles className="mr-1 h-4 w-4" /> Explain</>}
                                </Button>
                                <Button
                                  variant="secondary"
                                  size="sm"
                                  disabled={isDisabled}
                                  title="Generate a proposed code fix and verify it against OPA policies — no files are modified"
                                  onClick={() => previewMutation.mutate(row.original)}
                                >
                                  {rowPending === "preview"
                                    ? <><Loader2 className="mr-1 h-4 w-4 animate-spin" /> Previewing…</>
                                    : <>Preview (Dry Run)</>}
                                </Button>
                                <Button
                                  variant="default"
                                  size="sm"
                                  disabled={isDisabled}
                                  title="Generate a fix, apply it to the source file, re-run OPA verification, and report results"
                                  onClick={() => applyMutation.mutate(row.original)}
                                >
                                  {rowPending === "apply"
                                    ? <><Loader2 className="mr-1 h-4 w-4 animate-spin" /> Applying…</>
                                    : <>Apply + Verify</>}
                                </Button>
                              </div>
                            );
                          })()}

                          {explainById[row.original.id]?.status === "ERROR" && explainById[row.original.id]?.error && (
                            <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                              {explainById[row.original.id].error}
                            </div>
                          )}

                          {explainById[row.original.id]?.status === "OK" &&
                            (explainById[row.original.id]?.explanation_structured ||
                              explainById[row.original.id]?.explanation) &&
                            (explainById[row.original.id]?.explanation_structured
                              ? renderStructuredExplanation(explainById[row.original.id].explanation_structured!)
                              : (
                                <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50 p-4 text-indigo-900 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                                  <Markdown>{explainById[row.original.id].explanation!}</Markdown>
                                </div>
                              ))}

                          <div className="rounded-lg border border-slate-200">
                            <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
                              <span className="text-xs font-semibold uppercase text-slate-500">Code snippet</span>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  navigator.clipboard.writeText(row.original.snippet || "");
                                  toast.success("Code copied.");
                                }}
                              >
                                <Copy className="mr-1 h-4 w-4" /> Copy
                              </Button>
                            </div>
                            <CodeHighlight
                              code={row.original.snippet || "// snippet unavailable"}
                              language="java"
                              wrapLongLines
                              maxHeight={320}
                            />
                          </div>

                          {/* Preview results */}
                          {previewById[row.original.id]?.error && (
                            <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                              <strong>Preview error:</strong> {previewById[row.original.id].error}
                            </div>
                          )}
                          {previewById[row.original.id]?.diff && (
                            <div className="rounded-lg border border-slate-200">
                              <div className="border-b border-slate-200 px-3 py-2">
                                <span className="text-xs font-semibold uppercase text-slate-500">Remediation Diff</span>
                              </div>
                              <pre className="overflow-auto whitespace-pre-wrap break-words bg-white p-3 text-xs">{previewById[row.original.id].diff}</pre>
                            </div>
                          )}
                          {!previewById[row.original.id]?.diff && previewById[row.original.id]?.explanation && (
                            <div className="prose prose-sm max-w-none rounded-md border border-emerald-200 bg-emerald-50 p-4 text-emerald-900 break-words">
                              <strong>Preview:</strong>
                              <Markdown>{previewById[row.original.id].explanation!}</Markdown>
                            </div>
                          )}
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
                      No violations loaded yet. Run a policy evaluation to see results.
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
