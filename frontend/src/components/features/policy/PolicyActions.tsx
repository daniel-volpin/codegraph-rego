import { FormEvent, useState } from "react";
import { UseMutationResult } from "@tanstack/react-query";
import type { PolicyEvaluateResponse } from "../../../lib/types";

interface PolicyActionsProps {
    baseEvalMutation: UseMutationResult<
        PolicyEvaluateResponse,
        Error,
        { maxBundles?: number; maxTotalViolations?: number; maxPerViolationId?: number } | undefined
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
    onLlmSubmit
}: PolicyActionsProps) => {
    const baseEvalPending = baseEvalMutation.status === "pending";
    const isFullEvalRunning = baseEvalPending && baseEvalMutation.variables == null;
    const isInteractiveEvalRunning = baseEvalPending && baseEvalMutation.variables != null;
    const llmEvalPending = llmEvalMutation.status === "pending";

    return (
        <div className="policy-actions">
            <div className="policy-action-card">
                <header>
                    <h3>Full Evaluation</h3>
                    <p className="muted">
                        Scans the entire knowledge graph. Best for final compliance verification.
                        May take longer for large codebases.
                    </p>
                </header>
                <button onClick={() => baseEvalMutation.mutate(undefined)} disabled={baseEvalPending}>
                    {isFullEvalRunning && <span className="btn-spinner" aria-hidden="true" />}
                    <span>{isFullEvalRunning ? "Checking…" : "Run full evaluation"}</span>
                </button>
            </div>

            <div className="policy-action-card">
                <header>
                    <h3>Interactive Evaluation</h3>
                    <p className="muted">
                        Recommended for rapid triage. Limits the scan scope to provide quicker feedback
                        during development or review sessions.
                    </p>
                </header>

                <div className="policy-cap-grid">
                    <label>
                        Max methods scanned
                        <input
                            type="number"
                            min={1}
                            max={5000}
                            value={interactiveMaxBundles}
                            onChange={(event) => setInteractiveMaxBundles(Number(event.target.value))}
                        />
                    </label>
                    <label>
                        Max total violations
                        <input
                            type="number"
                            min={1}
                            max={2000}
                            value={interactiveMaxTotal}
                            onChange={(event) => setInteractiveMaxTotal(Number(event.target.value))}
                        />
                    </label>
                    <label>
                        Max per rule (violation id)
                        <input
                            type="number"
                            min={1}
                            max={1000}
                            value={interactiveMaxPerRule}
                            onChange={(event) => setInteractiveMaxPerRule(Number(event.target.value))}
                        />
                    </label>
                </div>

                <button
                    type="button"
                    onClick={() =>
                        baseEvalMutation.mutate({
                            maxBundles: interactiveMaxBundles,
                            maxTotalViolations: interactiveMaxTotal,
                            maxPerViolationId: interactiveMaxPerRule
                        })
                    }
                    disabled={baseEvalPending}
                >
                    {isInteractiveEvalRunning && <span className="btn-spinner" aria-hidden="true" />}
                    <span>{isInteractiveEvalRunning ? "Checking…" : "Run interactive evaluation"}</span>
                </button>
            </div>

            <details className="policy-advanced">
                <summary>Advanced: batch explanation (not recommended for thesis runs)</summary>
                <div className="policy-advanced-body">
                    <p className="muted">
                        Prefer the per-violation “Explain this violation” flow for interactive labeling. Batch explanation is
                        primarily for debugging or small ablations.
                    </p>
                    <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "1rem" }}>
                        <input
                            type="checkbox"
                            id="useInteractiveCaps"
                            checked={batchUseInteractiveCaps}
                            onChange={(event) => setBatchUseInteractiveCaps(event.target.checked)}
                        />
                        <label htmlFor="useInteractiveCaps">Use interactive caps (faster)</label>
                    </div>
                    <form className="policy-llm-form" onSubmit={onLlmSubmit}>
                        <label>
                            Top N violations (batch)
                            <input
                                type="number"
                                min={1}
                                max={100}
                                value={limit}
                                onChange={(event) => setLimit(Number(event.target.value))}
                            />
                        </label>
                        <label>
                            Model override (advanced)
                            <input
                                type="text"
                                value={model}
                                onChange={(event) => setModel(event.target.value)}
                                placeholder="Leave blank to use backend LLM_MODEL"
                            />
                        </label>
                        <button type="submit" disabled={llmEvalPending}>
                            {llmEvalPending && <span className="btn-spinner" aria-hidden="true" />}
                            <span>{llmEvalPending ? "Requesting…" : "Run batch explanation"}</span>
                        </button>
                    </form>
                </div>
            </details>
        </div>
    );
};
