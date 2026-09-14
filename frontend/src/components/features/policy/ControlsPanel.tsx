import { Download, Loader2, Search, SlidersHorizontal, Upload, ShieldCheck, X } from "lucide-react";
import { Button } from "../../ui/button";
import { Card } from "../../ui/card";

const MODULE_FILTER_SELECT_ID = "policy-module-filter";

export interface SearchAndFilterProps {
  searchQuery?: string;
  onSearchQueryChange?: (query: string) => void;
  moduleFilter: string;
  onModuleFilterChange: (filter: string) => void;
  availableModules: string[];
}

export interface SarifActionsProps {
  onExportSarif?: () => void;
  isExportingSarif?: boolean;
  onImportSarif?: () => void;
  isImportingSarif?: boolean;
  disabled?: boolean;
}

export interface ScanTriggerProps {
  evalIsFetching: boolean;
  onEvalRefetch: () => void;
  policyCatalogIsLoading?: boolean;
}

interface ControlsPanelProps {
  search: SearchAndFilterProps;
  sarif: SarifActionsProps;
  scan: ScanTriggerProps;
}

export const ControlsPanel = ({ search, sarif, scan }: ControlsPanelProps) => (
  <Card className="p-3.5 shadow-xs border-slate-200/80 dark:border-zinc-800">
    <div className="flex flex-wrap items-center justify-between gap-2.5">
      {/* Left controls: Quick Search & Target Module Filter */}
      <div className="flex flex-wrap items-center gap-2">
        {search.onSearchQueryChange && (
          <div className="flex h-9 items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/70 px-2.5 dark:border-zinc-800 dark:bg-zinc-900/40 min-w-[210px]">
            <Search className="h-3.5 w-3.5 text-slate-400 shrink-0" />
            <input
              type="text"
              value={search.searchQuery ?? ""}
              onChange={(e) => search.onSearchQueryChange?.(e.target.value)}
              placeholder="Filter by rule, method, or file…"
              className="w-full bg-transparent text-xs font-medium text-slate-900 dark:text-zinc-100 placeholder:text-slate-400 focus:outline-hidden"
            />
            {search.searchQuery && (
              <button
                type="button"
                onClick={() => search.onSearchQueryChange?.("")}
                className="text-slate-400 hover:text-slate-600 dark:hover:text-zinc-200 text-xs"
                title="Clear search"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        )}

        <div className="flex h-9 items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/70 px-3 dark:border-zinc-800 dark:bg-zinc-900/40">
          <SlidersHorizontal className="h-3.5 w-3.5 text-slate-400 shrink-0" />
          <label
            htmlFor={MODULE_FILTER_SELECT_ID}
            className="text-xs font-medium text-slate-600 dark:text-zinc-400 whitespace-nowrap"
          >
            Module:
          </label>
          <select
            id={MODULE_FILTER_SELECT_ID}
            value={search.moduleFilter}
            onChange={(event) => search.onModuleFilterChange(event.target.value)}
            className="bg-transparent text-xs font-medium text-slate-900 dark:text-zinc-100 focus:outline-hidden cursor-pointer max-w-[170px] truncate pr-1"
          >
            <option value="all">All scanned modules</option>
            {search.availableModules.map((module) => (
              <option key={module} value={module}>
                {module}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Right controls: SARIF Actions & Policy Scan Trigger */}
      <div className="flex flex-wrap items-center gap-2">
        {sarif.onImportSarif && (
          <Button
            variant="outline"
            data-testid="policy-sarif-import"
            onClick={sarif.onImportSarif}
            disabled={sarif.isImportingSarif || sarif.disabled}
            title="Import external SAST report in standard OASIS SARIF v2.1.0 format"
            className="h-9 text-xs font-medium gap-1.5 border-slate-200 dark:border-zinc-800 shadow-2xs hover:bg-slate-100 dark:hover:bg-zinc-800 whitespace-nowrap"
          >
            {sarif.isImportingSarif ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin text-indigo-600" />
                <span>Importing…</span>
              </>
            ) : (
              <>
                <Upload className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
                <span>Import SAST (SARIF)</span>
              </>
            )}
          </Button>
        )}
        {sarif.onExportSarif && (
          <Button
            variant="outline"
            data-testid="policy-sarif-export"
            onClick={sarif.onExportSarif}
            disabled={sarif.isExportingSarif || sarif.disabled}
            title="Export policy findings in standard OASIS SARIF v2.1.0 format"
            className="h-9 text-xs font-medium gap-1.5 border-slate-200 dark:border-zinc-800 shadow-2xs hover:bg-slate-100 dark:hover:bg-zinc-800 whitespace-nowrap"
          >
            {sarif.isExportingSarif ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin text-indigo-600" />
                <span>Exporting…</span>
              </>
            ) : (
              <>
                <Download className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
                <span>Export SARIF v2.1.0</span>
              </>
            )}
          </Button>
        )}
        <Button
          data-testid="policy-eval-run"
          onClick={scan.onEvalRefetch}
          disabled={scan.evalIsFetching || scan.policyCatalogIsLoading}
          title="Evaluate full policy compliance rules across the active codebase."
          className="h-9 px-4 text-xs font-semibold gap-1.5 shadow-xs bg-indigo-600 hover:bg-indigo-700 text-white whitespace-nowrap"
        >
          {scan.evalIsFetching ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>Scanning…</span>
            </>
          ) : (
            <>
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>Run Policy Scan</span>
            </>
          )}
        </Button>
      </div>
    </div>
  </Card>
);

export default ControlsPanel;
