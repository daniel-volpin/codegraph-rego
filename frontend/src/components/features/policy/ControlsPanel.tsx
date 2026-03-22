import { Loader2 } from "lucide-react";
import { Button } from "../../ui/button";
import { Card } from "../../ui/card";
import type { PolicyViewPreset } from "./policyUtils";

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
  <Card className="p-6">
    <div className="grid gap-4 lg:grid-cols-[minmax(380px,1fr)_auto] lg:items-center">
      <div className="grid gap-4 xl:grid-cols-2">
        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-slate-600">View mode</label>
          <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
            <button
              type="button"
              role="switch"
              aria-checked={viewPreset === "framework_demo"}
              aria-label="Toggle framework demo focus"
              onClick={() => onViewPresetChange(viewPreset === "all" ? "framework_demo" : "all")}
              className={`relative inline-flex h-7 w-14 items-center rounded-full border transition-colors ${
                viewPreset === "framework_demo"
                  ? "border-indigo-600 bg-indigo-600"
                  : "border-slate-300 bg-slate-200"
              }`}
            >
              <span
                className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                  viewPreset === "framework_demo" ? "translate-x-8" : "translate-x-1"
                }`}
              />
            </button>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-slate-900">Framework demo focus</p>
              <p className="text-xs text-slate-500">
                {viewPreset === "framework_demo"
                  ? "On. Show only the benchmark-aligned framework categories."
                  : "Off. Show the full policy surface for the current upload."}
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-slate-600">Module filter</label>
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
            <select
              value={moduleFilter}
              onChange={(event) => onModuleFilterChange(event.target.value)}
              className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900"
            >
              <option value="all">All modules</option>
              {availableModules.map((module) => (
                <option key={module} value={module}>
                  {module}
                </option>
              ))}
            </select>
            <p className="mt-2 text-xs text-slate-500">
              Filter findings to one uploaded module while keeping the active upload workspace unchanged.
            </p>
            {viewPreset === "framework_demo" && policyCatalogIsError && (
              <p className="mt-2 text-xs text-amber-700">
                Framework demo metadata could not be loaded from the backend. Falling back to the legacy thesis demo
                rule set.
              </p>
            )}
            {viewPreset === "framework_demo" &&
              !policyCatalogIsLoading &&
              frameworkDemoScopeSource === "legacy_fallback" &&
              !policyCatalogIsError && (
                <p className="mt-2 text-xs text-amber-700">
                  Backend demo metadata is unavailable on this server response. Using the legacy thesis demo rule set
                  for compatibility.
                </p>
              )}
          </div>
        </div>
      </div>

      <div className="flex lg:justify-end lg:self-center">
        <Button
          onClick={onEvalRefetch}
          disabled={evalIsFetching || !frameworkDemoReady || policyCatalogIsLoading}
          title={
            viewPreset === "framework_demo"
              ? "Evaluate only the benchmark-aligned framework demo categories."
              : "Evaluate the full policy surface for the current upload."
          }
          className="w-full lg:min-w-[18rem] lg:w-auto"
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
