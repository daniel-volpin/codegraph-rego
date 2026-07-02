import { Fragment } from "react";
import { type Table, flexRender } from "@tanstack/react-table";
import { Scale } from "lucide-react";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import ViolationFinding from "./ViolationFinding";
import {
  type PolicyViewPreset,
  type ViolationGroupRow,
  colWidthClass,
  ruleGroupStatusLabel,
  ruleGroupStatusVariant,
} from "./policyUtils";

interface ViolationGroupTableProps {
  table: Table<ViolationGroupRow>;
  columnCount: number;
  viewPreset: PolicyViewPreset;
  selectedFindingId: string | null;
  onSelectFinding: (id: string) => void;
  expandedFindingByGroup: Record<string, string | null>;
  onToggleFinding: (groupId: string, findingId: string) => void;
  hasEvaluationResult: boolean;
  emptyMessage?: string;
}

const ViolationGroupTable = ({
  table,
  columnCount,
  viewPreset,
  selectedFindingId,
  onSelectFinding,
  expandedFindingByGroup,
  onToggleFinding,
  hasEvaluationResult,
  emptyMessage,
}: ViolationGroupTableProps) => {
  const rows = table.getRowModel().rows;

  return (
    <Card data-testid="policy-results-region" className="min-w-0 overflow-hidden">
      {viewPreset === "framework_demo" && (
        <div className="border-b border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
          Showing the benchmark-aligned categories used in the thesis framework demo. Switch to All findings to inspect
          the full policy surface.
        </div>
      )}
      <div
        data-testid="policy-group-table-scroll"
        className="max-w-full overflow-x-auto 2xl:max-h-[calc(100vh-11rem)]"
      >
        <table className="w-full table-fixed border-collapse text-sm">
          <thead className="bg-slate-100 text-left text-slate-700">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  const sortDir = header.column.getIsSorted();
                  const ariaSort =
                    sortDir === "asc" ? "ascending" : sortDir === "desc" ? "descending" : "none";
                  const canSort = header.column.getCanSort();
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={canSort ? ariaSort : undefined}
                      className={`px-3 py-2 font-semibold overflow-hidden ${colWidthClass(header.column.id)}`}
                    >
                      {header.isPlaceholder ? null : canSort ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {rows.map((row) => (
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
                          {row.original.findings.map((finding) => (
                            <ViolationFinding
                              key={finding.id}
                              finding={finding}
                              groupId={row.original.id}
                              isSelected={selectedFindingId === finding.id}
                              isExpanded={expandedFindingByGroup[row.original.id] === finding.id}
                              onSelect={onSelectFinding}
                              onToggle={onToggleFinding}
                            />
                          ))}
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={columnCount} className="py-12 text-center">
                  <Scale aria-hidden="true" className="mx-auto h-10 w-10 text-slate-300" />
                  <p className="mt-3 text-sm text-slate-500">
                    {emptyMessage ??
                    (hasEvaluationResult
                      ? "No rule groups matched the current policy scan."
                      : "No rule groups loaded yet. Run a policy evaluation to see results.")}
                  </p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Card>
  );
};

export default ViolationGroupTable;
