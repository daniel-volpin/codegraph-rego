import { Loader2, Sparkles, SlidersHorizontal } from "lucide-react";
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
  frameworkDemoScopeSource: string;
}

const ControlsPanel = ({
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
  frameworkDemoScopeSource,
}: ControlsPanelProps) => (
  <Card className="p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800">
    <div className="grid gap-4 lg:grid-cols-[minmax(380px,1fr)_auto] lg:items-center">
      <div className="grid gap-4 xl:grid-cols-2">
        <div className="space-y-1.5">
          <label className="block text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
            Scan Scope
          </label>
          <div className="flex items-center gap-3.5 rounded-lg border border-zinc-200 bg-zinc-50/70 px-3.5 py-2.5 dark:border-zinc-800 dark:bg-zinc-900/40">
            <Switch
              checked={viewPreset === "framework_demo"}
              onCheckedChange={(checked) => onViewPresetChange(checked ? "framework_demo" : "all")}
              aria-label="Framework demo focus"
              aria-describedby={VIEW_MODE_DESCRIPTION_ID}
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <Sparkles className="h-3.5 w-3.5 text-zinc-500 dark:text-zinc-400" />
                <p className="text-xs font-semibold text-zinc-900 dark:text-zinc-100">Benchmark Demo Scope</p>
              </div>
              <p id={VIEW_MODE_DESCRIPTION_ID} className="text-[11px] text-zinc-500 dark:text-zinc-400">
                {viewPreset === "framework_demo"
                  ? "On: Evaluates benchmark categories & research rules."
                  : "Off: Evaluates entire policy catalog across all rules."}
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-1.5">
          <label
            htmlFor={MODULE_FILTER_SELECT_ID}
            className="block text-xs font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400"
          >
            Target Module
          </label>
          <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 px-3 py-2 dark:border-zinc-800 dark:bg-zinc-900/40">
            <div className="flex items-center gap-2">
              <SlidersHorizontal className="h-3.5 w-3.5 text-zinc-400 shrink-0" />
              <select
                id={MODULE_FILTER_SELECT_ID}
                value={moduleFilter}
                onChange={(event) => onModuleFilterChange(event.target.value)}
                className="w-full bg-transparent text-xs font-medium text-zinc-900 focus:outline-hidden dark:text-zinc-100"
              >
                <option value="all">All scanned modules</option>
                {availableModules.map((module) => (
                  <option key={module} value={module}>
                    {module}
                  </option>
                ))}
              </select>
            </div>
            {viewPreset === "framework_demo" && policyCatalogIsError && (
              <p className="mt-1.5 text-[11px] text-amber-700 dark:text-amber-400">
                Backend demo metadata unavailable; using thesis fallback demo rules.
              </p>
            )}
            {viewPreset === "framework_demo" &&
              !policyCatalogIsLoading &&
              frameworkDemoScopeSource === "legacy_fallback" &&
              !policyCatalogIsError && (
                <p className="mt-1.5 text-[11px] text-amber-700 dark:text-amber-400">
                  Using benchmark demo rule scope for compatibility.
                </p>
              )}
          </div>
        </div>
      </div>

      <div className="flex lg:justify-end lg:self-center">
        <Button
          data-testid="policy-eval-run"
          onClick={onEvalRefetch}
          disabled={evalIsFetching || !frameworkDemoReady || policyCatalogIsLoading}
          title={
            viewPreset === "framework_demo"
              ? "Evaluate only the benchmark-aligned framework demo categories."
              : "Evaluate the full policy surface for the current upload."
          }
          className="w-full lg:min-w-[17rem] lg:w-auto font-medium"
        >
          {evalIsFetching ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              {viewPreset === "framework_demo" ? "Running demo scan..." : "Running full scan..."}
            </>
          ) : policyCatalogIsLoading && viewPreset === "framework_demo" ? (
            "Loading demo scope..."
          ) : viewPreset === "framework_demo" ? (
            "Run Framework Demo Scan"
          ) : (
            "Run Full Policy Scan"
          )}
        </Button>
      </div>
    </div>
  </Card>
);

export default ControlsPanel;

