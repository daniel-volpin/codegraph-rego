import { FormEvent } from "react";
import { UseMutationResult } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import type { PolicyEvaluateResponse } from "../../../lib/types";
import { Card } from "../../ui/card";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";

interface PolicyActionsProps {
  baseEvalMutation: UseMutationResult<
    PolicyEvaluateResponse,
    Error,
    | {
      maxBundles?: number;
      maxTotalViolations?: number;
      maxPerViolationId?: number;
    }
    | undefined
  >;
  llmEvalMutation: UseMutationResult<PolicyEvaluateResponse, Error, void>;
  limit: number;
  setLimit: (val: number) => void;
  model: string;
  setModel: (val: string) => void;
  interactiveMaxBundles: number;
  setInteractiveMaxBundles: (val: number) => void;
  interactiveMaxTotal: number;
  setInteractiveMaxTotal: (val: number) => void;
  interactiveMaxPerRule: number;
  setInteractiveMaxPerRule: (val: number) => void;
  batchUseInteractiveCaps: boolean;
  setBatchUseInteractiveCaps: (val: boolean) => void;
  onLlmSubmit: (event: FormEvent<HTMLFormElement>) => void;
}

export const PolicyActions = ({
  baseEvalMutation,
  llmEvalMutation,
  limit,
  setLimit,
  model,
  setModel,
  interactiveMaxBundles,
  setInteractiveMaxBundles,
  interactiveMaxTotal,
  setInteractiveMaxTotal,
  interactiveMaxPerRule,
  setInteractiveMaxPerRule,
  batchUseInteractiveCaps,
  setBatchUseInteractiveCaps,
  onLlmSubmit,
}: PolicyActionsProps) => {
  const baseEvalPending = baseEvalMutation.status === "pending";
  const isFullEvalRunning =
    baseEvalPending && baseEvalMutation.variables == null;
  const isInteractiveEvalRunning =
    baseEvalPending && baseEvalMutation.variables != null;
  const llmEvalPending = llmEvalMutation.status === "pending";

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {/* ── Full Evaluation ────────────────────────────── */}
      <Card className="space-y-4 p-5">
        <div>
          <h3 className="text-base font-semibold text-slate-900">Full Evaluation</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Scans the entire knowledge graph. Best for final compliance
            verification. May take longer for large codebases.
          </p>
        </div>
        <Button
          onClick={() => baseEvalMutation.mutate(undefined)}
          disabled={baseEvalPending}
          className="w-full"
        >
          {isFullEvalRunning && (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          )}
          {isFullEvalRunning ? "Checking…" : "Run full evaluation"}
        </Button>
      </Card>

      {/* ── Interactive Evaluation ─────────────────────── */}
      <Card className="space-y-4 p-5">
        <div>
          <h3 className="text-base font-semibold text-slate-900">Interactive Evaluation</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Recommended for rapid triage. Limits the scan scope to provide
            quicker feedback during development or review sessions.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <label className="space-y-1">
            <span className="block text-xs font-medium text-slate-600">Max methods scanned</span>
            <Input
              type="number"
              min={1}
              max={5000}
              value={interactiveMaxBundles}
              onChange={(event) =>
                setInteractiveMaxBundles(Number(event.target.value))
              }
            />
          </label>
          <label className="space-y-1">
            <span className="block text-xs font-medium text-slate-600">Max total violations</span>
            <Input
              type="number"
              min={1}
              max={2000}
              value={interactiveMaxTotal}
              onChange={(event) =>
                setInteractiveMaxTotal(Number(event.target.value))
              }
            />
          </label>
          <label className="space-y-1">
            <span className="block text-xs font-medium text-slate-600">Max per rule</span>
            <Input
              type="number"
              min={1}
              max={1000}
              value={interactiveMaxPerRule}
              onChange={(event) =>
                setInteractiveMaxPerRule(Number(event.target.value))
              }
            />
          </label>
        </div>

        <Button
          type="button"
          onClick={() =>
            baseEvalMutation.mutate({
              maxBundles: interactiveMaxBundles,
              maxTotalViolations: interactiveMaxTotal,
              maxPerViolationId: interactiveMaxPerRule,
            })
          }
          disabled={baseEvalPending}
          className="w-full"
        >
          {isInteractiveEvalRunning && (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          )}
          {isInteractiveEvalRunning
            ? "Checking…"
            : "Run interactive evaluation"}
        </Button>
      </Card>

      {/* ── Advanced: Batch Explanation ─────────────────── */}
      <div className="md:col-span-2">
        <details className="group rounded-lg border border-slate-200 bg-white">
          <summary className="cursor-pointer select-none px-5 py-3 text-sm font-medium text-slate-700 transition hover:text-slate-900">
            Advanced: batch explanation (not recommended for thesis runs)
          </summary>
          <div className="space-y-4 border-t border-slate-200 px-5 py-4">
            <p className="text-sm text-muted-foreground">
              Prefer the per-violation "Explain this violation" flow for
              interactive labeling. Batch explanation is primarily for debugging
              or small ablations.
            </p>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="useInteractiveCaps"
                checked={batchUseInteractiveCaps}
                onChange={(event) =>
                  setBatchUseInteractiveCaps(event.target.checked)
                }
                className="h-4 w-4 rounded border-slate-300 text-primary focus:ring-primary"
              />
              <label htmlFor="useInteractiveCaps" className="text-sm text-slate-700">
                Use interactive caps (faster)
              </label>
            </div>
            <form className="space-y-3" onSubmit={onLlmSubmit}>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="space-y-1">
                  <span className="block text-xs font-medium text-slate-600">Top N violations (batch)</span>
                  <Input
                    type="number"
                    min={1}
                    max={100}
                    value={limit}
                    onChange={(event) => setLimit(Number(event.target.value))}
                  />
                </label>
                <label className="space-y-1">
                  <span className="block text-xs font-medium text-slate-600">Model override (advanced)</span>
                  <Input
                    type="text"
                    value={model}
                    onChange={(event) => setModel(event.target.value)}
                    placeholder="Leave blank to use backend LLM_MODEL"
                  />
                </label>
              </div>
              <Button type="submit" disabled={llmEvalPending}>
                {llmEvalPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                {llmEvalPending ? "Requesting…" : "Run batch explanation"}
              </Button>
            </form>
          </div>
        </details>
      </div>
    </div>
  );
};
