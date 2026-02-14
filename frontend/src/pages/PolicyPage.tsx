import { Fragment, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
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
import { ChevronDown, ChevronRight, Copy, Sparkles } from "lucide-react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
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
  PolicyExplainOneResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse,
} from "../lib/types";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";

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

const AUTO_RULES = new Set(["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-CRYPTO", "A.10-WEAK-HASH", "A.10-WEAK-CRYPTO"]);

const asString = (value: unknown, fallback = "—") => (typeof value === "string" && value.trim() ? value : fallback);

const normalizeViolation = (item: RawViolation): ViolationRow => {
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
    snippet: asString(item.code_snippet ?? item.updated_source_code ?? ""),
    raw: item,
    autoRemediable: AUTO_RULES.has(ruleId),
  };
};

const severityVariant = (severity: string): "destructive" | "warning" | "secondary" => {
  if (severity === "HIGH") return "destructive";
  if (severity === "MEDIUM") return "warning";
  return "secondary";
};

const PolicyPage = () => {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [maxTotal, setMaxTotal] = useState(100);

  const [previewById, setPreviewById] = useState<Record<string, RemediationPreviewResponse>>({});
  const [applyById, setApplyById] = useState<Record<string, RemediationApplyResponse>>({});
  const [explainById, setExplainById] = useState<Record<string, PolicyExplainOneResponse>>({});

  useQuery<PolicyCatalogResponse, Error>({ queryKey: ["policyCatalog"], queryFn: fetchPolicyCatalog });

  const evalMutation = useMutation({
    mutationFn: () => evaluatePolicies({ maxTotalViolations: maxTotal }),
    onSuccess: (data) => toast.success(`${data.violations?.length ?? 0} violations loaded.`),
    onError: (error: Error) => toast.error(`Evaluation failed: ${error.message}`),
  });

  const explainMutation = useMutation({
    mutationFn: (violation: RawViolation) =>
      explainPolicyViolationOne({ violation, include_graph_context: true }),
    onSuccess: (data, violation) => {
      const row = normalizeViolation(violation);
      setExplainById((prev) => ({ ...prev, [row.id]: data }));
      toast.success("LLM explanation ready.");
    },
    onError: (error: Error) => toast.error(`Explain failed: ${error.message}`),
  });

  const previewMutation = useMutation({
    mutationFn: (row: ViolationRow) => previewRemediation(row.ruleId, row.targetMethod, row.filePath),
    onSuccess: (data, row) => {
      setPreviewById((prev) => ({ ...prev, [row.id]: data }));
      toast.success(`Preview complete for ${row.ruleId}.`);
    },
    onError: (error: Error) => toast.error(`Preview failed: ${error.message}`),
  });

  const applyMutation = useMutation({
    mutationFn: (row: ViolationRow) => applyRemediation({ violation_id: row.ruleId, target_method: row.targetMethod, file_path: row.filePath }),
    onSuccess: (data, row) => {
      setApplyById((prev) => ({ ...prev, [row.id]: data }));
      toast.success(`Dry-run apply completed for ${row.ruleId}.`);
    },
    onError: (error: Error) => toast.error(`Apply failed: ${error.message}`),
  });

  const data = useMemo(() => {
    const result: PolicyEvaluateResponse | undefined = evalMutation.data;
    return (result?.violations ?? []).map((v) => normalizeViolation(v));
  }, [evalMutation.data]);

  const columns = useMemo<ColumnDef<ViolationRow>[]>(
    () => [
      {
        id: "expander",
        header: "",
        cell: ({ row }) => (
          <button className="p-1" onClick={row.getToggleExpandedHandler()}>
            {row.getIsExpanded() ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        ),
      },
      {
        accessorKey: "ruleId",
        header: "Rule ID",
      },
      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }) => <Badge variant={severityVariant(row.original.severity)}>{row.original.severity}</Badge>,
      },
      {
        accessorKey: "targetMethod",
        header: "Target Method",
      },
      {
        accessorKey: "filePath",
        header: "File",
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
  });

  return (
    <div className="space-y-4">
      <Card className="p-6">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-slate-600">max_total_violations</label>
            <Input type="number" value={maxTotal} onChange={(e) => setMaxTotal(Number(e.target.value))} className="w-44" />
          </div>
          <Button onClick={() => evalMutation.mutate()} disabled={evalMutation.isPending}>
            Run Policy Evaluation
          </Button>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="overflow-auto">
          <table className="min-w-full border-collapse text-sm">
            <thead className="bg-slate-100 text-left text-slate-700">
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <th key={header.id} className="px-3 py-2 font-semibold">
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
                      <td key={cell.id} className="px-3 py-2 align-top">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                  {row.getIsExpanded() && (
                    <tr className="border-t border-slate-100 bg-slate-50">
                      <td className="px-4 py-4" colSpan={columns.length}>
                        <div className="space-y-4">
                          <p className="text-sm text-slate-700">{row.original.reason}</p>
                          <div className="flex flex-wrap gap-2">
                            <Button variant="outline" size="sm" onClick={() => explainMutation.mutate(row.original.raw)}>
                              <Sparkles className="mr-1 h-4 w-4" /> Explain
                            </Button>
                            <Button variant="secondary" size="sm" onClick={() => previewMutation.mutate(row.original)}>
                              Preview (Dry Run)
                            </Button>
                            <Button variant="default" size="sm" onClick={() => applyMutation.mutate(row.original)}>
                              Apply + Verify
                            </Button>
                          </div>

                          {explainById[row.original.id]?.explanation && (
                            <div className="rounded-md border border-indigo-200 bg-indigo-50 p-3 text-sm text-indigo-900">
                              {explainById[row.original.id].explanation}
                            </div>
                          )}

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
                            <SyntaxHighlighter language="java" style={oneDark} showLineNumbers customStyle={{ margin: 0, maxHeight: 320 }}>
                              {row.original.snippet || "// snippet unavailable"}
                            </SyntaxHighlighter>
                          </div>

                          {previewById[row.original.id]?.diff && (
                            <pre className="overflow-auto rounded-md border border-slate-200 bg-white p-3 text-xs">{previewById[row.original.id].diff}</pre>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default PolicyPage;
