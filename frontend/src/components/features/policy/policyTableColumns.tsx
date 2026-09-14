import type { ColumnDef } from "@tanstack/react-table";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Badge } from "../../ui/badge";
import type { PolicyTableFeatures } from "./tableFeatures";
import {
  type ViolationGroupRow,
  deriveStandardFromRuleId,
  formatHumanRuleTitle,
  ruleGroupStatusLabel,
  ruleGroupStatusVariant,
  severityVariant,
} from "./policyUtils";

export const createPolicyTableColumns = (): ColumnDef<PolicyTableFeatures, ViolationGroupRow>[] => [
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
];
