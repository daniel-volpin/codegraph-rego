import { useMemo, useState } from "react";
import {
  type ExpandedState,
  type SortingState,
  type Table,
  getCoreRowModel,
  getExpandedRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "../../../ui/badge";
import {
  type ViolationGroupRow,
  type ViolationRow,
  groupViolationsByRule,
  ruleGroupStatusLabel,
  ruleGroupStatusVariant,
  severityVariant,
} from "../policyUtils";

export interface UseViolationTableReturn {
  table: Table<ViolationGroupRow>;
  columnCount: number;
  ruleCount: number;
}

export function useViolationTable(filteredFindings: ViolationRow[]): UseViolationTableReturn {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [expanded, setExpanded] = useState<ExpandedState>({});

  const data = useMemo(() => groupViolationsByRule(filteredFindings), [filteredFindings]);

  const columns = useMemo(
    () => [
      {
        id: "expander",
        header: "",
        cell: ({ row }: { row: { getToggleExpandedHandler: () => () => void; getIsExpanded: () => boolean } }) => (
          <button type="button" className="p-1" onClick={row.getToggleExpandedHandler()}>
            {row.getIsExpanded() ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        ),
      },
      {
        accessorKey: "ruleId",
        header: "Rule ID",
        cell: ({ row }: { row: { original: ViolationGroupRow } }) => (
          <span className="block min-w-0 truncate font-mono text-xs text-slate-800" title={row.original.ruleId}>
            {row.original.ruleId}
          </span>
        ),
      },
      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }: { row: { original: ViolationGroupRow } }) => (
          <Badge variant={severityVariant(row.original.severity)}>{row.original.severity}</Badge>
        ),
      },
      {
        accessorKey: "findingCount",
        header: "Findings",
        cell: ({ row }: { row: { original: ViolationGroupRow } }) => (
          <span className="text-sm text-slate-800">{row.original.findingCount}</span>
        ),
      },
      {
        accessorKey: "fileCount",
        header: "Files",
        cell: ({ row }: { row: { original: ViolationGroupRow } }) => (
          <span className="text-sm text-slate-800">{row.original.fileCount}</span>
        ),
      },
      {
        id: "status",
        header: "Remediation",
        cell: ({ row }: { row: { original: ViolationGroupRow } }) => (
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

  return { table, columnCount: columns.length, ruleCount: data.length };
}
