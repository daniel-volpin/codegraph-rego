import { Fragment } from "react";
import { type Table, flexRender } from "@tanstack/react-table";
import { Scale, ChevronDown, ChevronUp } from "lucide-react";
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
import type { PolicyTableFeatures } from "./tableFeatures";

interface ViolationGroupTableProps {
  table: Table<PolicyTableFeatures, ViolationGroupRow>;
  columnCount: number;
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
  selectedFindingId,
  onSelectFinding,
  expandedFindingByGroup,
  onToggleFinding,
  hasEvaluationResult,
  emptyMessage,
}: ViolationGroupTableProps) => {
  const rows = table.getRowModel().rows;

  return (
    <Card data-testid="policy-results-region" className="min-w-0 overflow-hidden shadow-xs border-zinc-200/80 dark:border-zinc-800">
      <div
        data-testid="policy-group-table-scroll"
        className="max-w-full overflow-x-auto xl:max-h-[calc(100vh-8rem)]"
      >
        <table className="w-full table-fixed border-collapse text-xs">
          <thead className="border-b border-zinc-200 bg-zinc-100/75 text-left text-zinc-600 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-400">
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
                      className={`px-3 py-2.5 font-semibold uppercase tracking-wider text-[11px] ${colWidthClass(header.column.id)}`}
                    >
                      {header.isPlaceholder ? <span className="sr-only">Expand rule group</span> : canSort ? (
                        <button
                          type="button"
                          className="inline-flex items-center gap-1 hover:text-zinc-900 dark:hover:text-zinc-100 font-semibold"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {sortDir === "asc" ? (
                            <ChevronUp className="h-3 w-3" />
                          ) : sortDir === "desc" ? (
                            <ChevronDown className="h-3 w-3" />
                          ) : null}
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
          <tbody className="divide-y divide-zinc-200/70 dark:divide-zinc-800/70">
            {rows.map((row) => (
              <Fragment key={row.id}>
                <tr
                  className="hover:bg-zinc-50/80 dark:hover:bg-zinc-900/60 transition-colors cursor-pointer select-none"
                  onClick={() => row.toggleExpanded()}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className={`px-3 py-2.5 align-middle ${colWidthClass(cell.column.id)}`}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
                {row.getIsExpanded() && (
                  <tr className="bg-zinc-50/80 dark:bg-zinc-950/50">
                    <td className="p-4" colSpan={columnCount}>
                      <div className="space-y-3.5">
                        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200/60 pb-3 dark:border-zinc-800">
                          <div>
                            <p className="font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100">{row.original.ruleId}</p>
                            <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
                              {row.original.findingCount} finding{row.original.findingCount === 1 ? "" : "s"} across {row.original.fileCount} file{row.original.fileCount === 1 ? "" : "s"}
                            </p>
                          </div>
                          <Badge variant={ruleGroupStatusVariant(row.original)}>
                            {ruleGroupStatusLabel(row.original)}
                          </Badge>
                        </div>

                        <div className="space-y-2.5">
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
                  <Scale aria-hidden="true" className="mx-auto h-9 w-9 text-zinc-300 dark:text-zinc-600" />
                  <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400 font-medium">
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
