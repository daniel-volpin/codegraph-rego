import { Download, Loader2, Sparkles, SlidersHorizontal, Upload, ShieldCheck } from "lucide-react";
import { Button } from "../../ui/button";
import { Card } from "../../ui/card";
import { Switch } from "../../ui/switch";
import type { PolicyViewPreset } from "./policyUtils";

const VIEW_MODE_DESCRIPTION_ID = "framework-demo-switch-description";
const MODULE_FILTER_SELECT_ID = "policy-module-filter";

interface ControlsPanelProps {
  viewPreset: PolicyViewPreset;
  onViewPresetChange: (preset: PolicyViewPreset) => void;
  moduleFilter: string;
  onModuleFilterChange: (filter: string) => void;
  availableModules: string[];
  evalIsFetching: boolean;
  onEvalRefetch: () => void;
  frameworkDemoReady: boolean;
  policyCatalogIsLoading: boolean;
  policyCatalogIsError: boolean;
  onExportSarif?: () => void;
  isExportingSarif?: boolean;
  onImportSarif?: () => void;
  isImportingSarif?: boolean;
}

export const ControlsPanel = ({
  viewPreset,
  onViewPresetChange,
  moduleFilter,
  onModuleFilterChange,
  availableModules,
  evalIsFetching,
  onEvalRefetch,
  frameworkDemoReady,
  policyCatalogIsLoading,
  policyCatalogIsError,
  onExportSarif,
  isExportingSarif = false,
  onImportSarif,
  isImportingSarif = false,
}: ControlsPanelProps) => (
  <Card className="p-3 sm:p-4 shadow-xs border-slate-200/80 dark:border-zinc-800">
    <div className="flex flex-col xl:flex-row items-stretch xl:items-center justify-between gap-3">
      {/* Left controls: Scan Scope & Target Module */}
      <div className="flex flex-wrap items-center gap-2.5">
        {/* Scan Scope Toggle */}
        <div className="flex h-9 items-center gap-2.5 rounded-lg border border-slate-200 bg-slate-50/70 px-3 dark:border-zinc-800 dark:bg-zinc-900/40">
          <Switch
            checked={viewPreset === "framework_demo"}
            onCheckedChange={(checked) => onViewPresetChange(checked ? "framework_demo" : "all")}
            aria-label="Framework demo focus"
            aria-describedby={VIEW_MODE_DESCRIPTION_ID}
          />
          <div className="flex items-center gap-1.5 min-w-0">
            <Sparkles className="h-3.5 w-3.5 text-indigo-600 dark:text-indigo-400 shrink-0" />
            <span className="text-xs font-semibold text-slate-800 dark:text-zinc-200 whitespace-nowrap">
              Benchmark Demo Scope
            </span>
          </div>
          <span
            id={VIEW_MODE_DESCRIPTION_ID}
            className="text-[10px] font-medium text-slate-500 dark:text-zinc-400 ml-0.5 hidden sm:inline"
          >
            {viewPreset === "framework_demo" ? "(Targeted)" : "(All Rules)"}
          </span>
        </div>

        {/* Target Module Selector */}
        <div className="flex h-9 items-center gap-2 rounded-lg border border-slate-200 bg-slate-50/70 px-3 dark:border-zinc-800 dark:bg-zinc-900/40">
          <SlidersHorizontal className="h-3.5 w-3.5 text-slate-400 shrink-0" />
          <label
            htmlFor={MODULE_FILTER_SELECT_ID}
            className="text-xs font-medium text-slate-500 dark:text-zinc-400 whitespace-nowrap"
          >
            Module:
          </label>
          <select
            id={MODULE_FILTER_SELECT_ID}
            value={moduleFilter}
            onChange={(event) => onModuleFilterChange(event.target.value)}
            className="bg-transparent text-xs font-medium text-slate-800 dark:text-zinc-200 focus:outline-hidden cursor-pointer pr-1"
          >
            <option value="all">All scanned modules</option>
            {availableModules.map((module) => (
              <option key={module} value={module}>
                {module}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Right controls: SARIF Actions & Policy Scan Trigger */}
      <div className="flex flex-wrap items-center gap-2 justify-end">
        {onImportSarif && (
          <Button
            variant="outline"
            data-testid="policy-sarif-import"
            onClick={onImportSarif}
            disabled={isImportingSarif || evalIsFetching}
            title="Import external SAST report in standard OASIS SARIF v2.1.0 format"
            className="h-9 text-xs font-medium gap-1.5 border-slate-200 dark:border-zinc-800 shadow-2xs hover:bg-slate-100 dark:hover:bg-zinc-800"
          >
            {isImportingSarif ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin text-indigo-600" />
                <span>Importing SARIF…</span>
              </>
            ) : (
              <>
                <Upload className="h-3.5 w-3.5 text-slate-500 dark:text-zinc-400" />
                <span>Import SAST (SARIF)</span>
              </>
            )}
          </Button>
        )}
        {onExportSarif && (
          <Button
            variant="outline"
            data-testid="policy-sarif-export"
            onClick={onExportSarif}
            disabled={isExportingSarif || evalIsFetching}
            title="Export policy findings in standard OASIS SARIF v2.1.0 format"
            className="h-9 text-xs font-medium gap-1.5 border-slate-200 dark:border-zinc-800 shadow-2xs hover:bg-slate-100 dark:hover:bg-zinc-800"
          >
            {isExportingSarif ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin text-indigo-600" />
                <span>Exporting SARIF…</span>
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
          onClick={onEvalRefetch}
          disabled={evalIsFetching || !frameworkDemoReady || policyCatalogIsLoading}
          title={
            viewPreset === "framework_demo"
              ? "Evaluate only the benchmark-aligned framework demo categories."
              : "Evaluate the full policy surface for the current upload."
          }
          className="h-9 px-4 text-xs font-semibold gap-1.5 shadow-xs bg-indigo-600 hover:bg-indigo-700 text-white"
        >
          {evalIsFetching ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              <span>{viewPreset === "framework_demo" ? "Running demo scan..." : "Running full scan..."}</span>
            </>
          ) : policyCatalogIsLoading && viewPreset === "framework_demo" ? (
            <span>Loading demo scope...</span>
          ) : viewPreset === "framework_demo" ? (
            <>
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>Run Framework Demo Scan</span>
            </>
          ) : (
            <>
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>Run Full Policy Scan</span>
            </>
          )}
        </Button>
      </div>
    </div>
  </Card>
);

export default ControlsPanel;

