import { BookOpen, ShieldAlert } from "lucide-react";
import { cn } from "../../../lib/utils";

export interface StandardCounts {
  all: number;
  iso: number;
  pci: number;
  owasp: number;
  nist: number;
  sarif: number;
}

interface PolicyViewControlsProps {
  selectedStandard: string;
  onSelectedStandardChange: (standard: string) => void;
  standardCounts: StandardCounts;
  activeViewMode: "findings" | "rules_catalog";
  onActiveViewModeChange: (mode: "findings" | "rules_catalog") => void;
  filteredFindingsCount: number;
}

/** Standard filter tabs plus the findings/rules-catalog view switcher. */
export const PolicyViewControls = ({
  selectedStandard,
  onSelectedStandardChange,
  standardCounts,
  activeViewMode,
  onActiveViewModeChange,
  filteredFindingsCount,
}: PolicyViewControlsProps) => (
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
            onClick={() => onSelectedStandardChange(tab.id)}
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

    <div className="flex items-center gap-1 bg-slate-100 dark:bg-zinc-800 p-1 rounded-lg text-xs shrink-0">
      <button
        type="button"
        onClick={() => onActiveViewModeChange("findings")}
        className={cn(
          "rounded-md px-3 py-1 text-xs font-medium transition cursor-pointer flex items-center gap-1.5",
          activeViewMode === "findings"
            ? "bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 shadow-2xs font-semibold"
            : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100",
        )}
      >
        <ShieldAlert className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
        <span>Active Violations ({filteredFindingsCount})</span>
      </button>
      <button
        type="button"
        onClick={() => onActiveViewModeChange("rules_catalog")}
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
);

export default PolicyViewControls;
