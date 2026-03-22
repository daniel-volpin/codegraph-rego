import { Fragment } from "react";
import { type Table, flexRender } from "@tanstack/react-table";
import { ChevronDown, ChevronRight, Copy, Loader2, Scale, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import CodeHighlight from "../../ui/CodeHighlight";
import type { PolicyExplanationStructured } from "../../../lib/types";
import {
  type ViolationGroupRow,
  type ViolationRow,
  type RawViolation,
  type PolicyViewPreset,
  type PendingAction,
  type PolicyExplainOneResponse,
  type RemediationPreviewResponse,
  colWidthClass,
  compactTargetMethod,
  formatCitationDisplay,
  remediationBadgeLabel,
  remediationBadgeVariant,
  remediationSummaryText,
  ruleGroupStatusLabel,
  ruleGroupStatusVariant,
  severityVariant,
} from "./policyUtils";

interface ViolationGroupTableProps {
  table: Table<ViolationGroupRow>;
  columnCount: number;
  viewPreset: PolicyViewPreset;
  selectedFindingId: string | null;
  onSelectFinding: (id: string) => void;
  expandedFindingByGroup: Record<string, string | null>;
  onToggleFinding: (groupId: string, findingId: string) => void;
  pendingAction: Record<string, PendingAction>;
  explainById: Record<string, PolicyExplainOneResponse>;
  previewById: Record<string, RemediationPreviewResponse>;
  hasEvaluationResult: boolean;
  onExplain: (raw: RawViolation) => void;
  onPreview: (finding: ViolationRow) => void;
  onApply: (finding: ViolationRow) => void;
}

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

const ViolationGroupTable = ({
  table,
  columnCount,
  viewPreset,
  selectedFindingId,
  onSelectFinding,
  expandedFindingByGroup,
  onToggleFinding,
  pendingAction,
  explainById,
  previewById,
  hasEvaluationResult,
  onExplain,
  onPreview,
  onApply,
}: ViolationGroupTableProps) => (
  <Card className="overflow-hidden">
    {viewPreset === "framework_demo" && (
      <div className="border-b border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
        Showing the benchmark-aligned categories used in the thesis framework demo. Switch to All findings to inspect
        the full policy surface.
      </div>
    )}
    <div className="overflow-auto 2xl:max-h-[calc(100vh-11rem)]">
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
              <tr className="border-t border-slate-200">
                {row.getVisibleCells().map((cell) => (
                  <td
                    key={cell.id}
                    className={`px-3 py-2 align-top overflow-hidden ${colWidthClass(cell.column.id)}`}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
              {row.getIsExpanded() && (
                <tr className="border-t border-slate-100 bg-slate-50">
                  <td className="px-4 py-4" colSpan={columnCount}>
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
                            <div
                              key={finding.id}
                              className={`rounded-lg border bg-white ${
                                selectedFindingId === finding.id
                                  ? "border-indigo-300 ring-2 ring-indigo-100"
                                  : "border-slate-200"
                              }`}
                            >
                              <button
                                type="button"
                                className="flex w-full flex-wrap items-start justify-between gap-3 p-4 text-left"
                                onClick={() => {
                                  onSelectFinding(finding.id);
                                  onToggleFinding(row.original.id, finding.id);
                                }}
                              >
                                <div className="flex min-w-0 items-start gap-3">
                                  {isFindingExpanded ? (
                                    <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                                  ) : (
                                    <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
                                  )}
                                  <div className="min-w-0">
                                    <p
                                      className="truncate font-mono text-sm text-slate-900"
                                      title={finding.targetMethod}
                                    >
                                      {compactTargetMethod(finding.targetMethod)}
                                    </p>
                                    <p
                                      className="mt-1 truncate font-mono text-xs text-slate-500"
                                      title={finding.filePath}
                                    >
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
                                        variant="ghost"
                                        size="sm"
                                        disabled={isBusy}
                                        onClick={() => onSelectFinding(finding.id)}
                                      >
                                        Open dossier
                                      </Button>
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        disabled={isBusy}
                                        title="Generate a concise explanation of why this finding matters and how to address it."
                                        onClick={() => {
                                          onSelectFinding(finding.id);
                                          onExplain(finding.raw);
                                        }}
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
                                        onClick={() => {
                                          onSelectFinding(finding.id);
                                          onPreview(finding);
                                        }}
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
                                        onClick={() => {
                                          onSelectFinding(finding.id);
                                          onApply(finding);
                                        }}
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

                                    {explainById[finding.id]?.status === "ERROR" &&
                                      explainById[finding.id]?.error && (
                                        <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                                          {explainById[finding.id].error}
                                        </div>
                                      )}

                                    {explainById[finding.id]?.status === "OK" &&
                                      (explainById[finding.id]?.explanation_structured ||
                                        explainById[finding.id]?.explanation) &&
                                      (explainById[finding.id]?.explanation_structured ? (
                                        renderStructuredExplanation(
                                          explainById[finding.id].explanation_structured!,
                                        )
                                      ) : (
                                        <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50 p-4 text-indigo-900 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                                          <Markdown>{explainById[finding.id].explanation!}</Markdown>
                                        </div>
                                      ))}

                                    <div className="rounded-lg border border-slate-200">
                                      <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
                                        <span className="text-xs font-semibold uppercase text-slate-500">
                                          Code snippet
                                        </span>
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
                                        maxHeight={460}
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
                                          <span className="text-xs font-semibold uppercase text-slate-500">
                                            Remediation Diff
                                          </span>
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
          {table.getRowModel().rows.length === 0 && (
            <tr>
              <td colSpan={columnCount} className="py-12 text-center">
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
);

export default ViolationGroupTable;
