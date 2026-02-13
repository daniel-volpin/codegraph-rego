import React, { FormEvent } from "react";
import CodeHighlight from "../../ui/CodeHighlight";
import { toast } from "react-hot-toast";

// Types (You might need to export these from a shared types file if not already)
// For now, I'll assume some are passed as 'any' or defined locally if they are simple, 
// but ideally we import them from `../../lib/types`.
import type {
    PolicyViolationSummary,
    AutoRemediationResult,
    PolicyReviewLabel
} from "../../../lib/types";

interface ViolationCardProps {
    item: PolicyViolationSummary;
    violationKey: string;
    index: number;
    defaultOpenViolationIndex: number;

    // State / Data
    remediationOutcome?: AutoRemediationResult;
    applyOutcome?: AutoRemediationResult;
    reviewSaved?: any; // Replace with concrete Review type
    reviewDraft: {
        label?: PolicyReviewLabel;
        notes: string;
        includeGraphContext: boolean;
    };
    explanation?: { explanation: string; model?: string };

    // Loading States
    isStarting: boolean;
    isApplying: boolean;
    isExplaining: boolean;
    isSavingReview: boolean;
    disableRemediationButtons: boolean;

    // Actions
    onRemediate: (e: React.MouseEvent) => void;
    onApply: (e: React.MouseEvent) => void;
    onExplain: (e: React.MouseEvent) => void;
    onSaveReview: (e: React.MouseEvent) => void;
    setReviewDraft: (draft: { label?: PolicyReviewLabel; notes: string; includeGraphContext: boolean }) => void;

    // Utils
    toHtml: (text: string) => string;
    formatAutoRemediationError: (err: any) => string | null;
}

export const ViolationCard: React.FC<ViolationCardProps> = ({
    item,
    violationKey,
    index,
    defaultOpenViolationIndex,
    remediationOutcome,
    applyOutcome,
    reviewSaved,
    reviewDraft,
    explanation,
    isStarting,
    isApplying,
    isExplaining,
    isSavingReview,
    disableRemediationButtons,
    onRemediate,
    onApply,
    onExplain,
    onSaveReview,
    setReviewDraft,
    toHtml,
    formatAutoRemediationError
}) => {

    const applyVerification = applyOutcome?.verification as any;
    const applyCompilation = applyOutcome?.compilation as any;
    const applyBaselineCount = Array.isArray(applyVerification?.baseline)
        ? applyVerification?.baseline?.length
        : undefined;
    const applyAfterCount = Array.isArray(applyVerification?.after)
        ? applyVerification?.after?.length
        : undefined;
    const applyNewCount = Array.isArray(applyVerification?.new_violations)
        ? applyVerification?.new_violations?.length
        : undefined;
    const applyRemainingCount = Array.isArray(applyVerification?.remaining_violations)
        ? applyVerification?.remaining_violations?.length
        : undefined;

    const targetRuleStatus =
        typeof applyVerification?.target_rule_status === "string"
            ? applyVerification.target_rule_status
            : remediationOutcome?.opa_status;

    const overallStatus =
        typeof applyVerification?.overall_status === "string"
            ? applyVerification.overall_status
            : undefined;

    const newViolations =
        Array.isArray(remediationOutcome?.verification?.new_violations)
            ? (remediationOutcome?.verification as any)?.new_violations?.length
            : undefined;

    const remainingViolations =
        Array.isArray(remediationOutcome?.verification?.remaining_violations)
            ? (remediationOutcome?.verification as any)?.remaining_violations?.length
            : undefined;

    return (
        <details
            className="violation-card"
            key={`violation-${index}`}
            open={index === defaultOpenViolationIndex}
        >
            <summary>
                <div className="violation-summary">
                    <div className="violation-summary-text">
                        <span className="violation-control">
                            {item.control || item.violationId || "Unmapped control"}
                        </span>
                        <span className="violation-title">{item.title}</span>
                        <span className="violation-location">
                            {item.targetMethod ? (
                                <>
                                    <code>{item.targetMethod.split("(")[0]}</code>
                                    <span style={{ color: "var(--color-slate-300)" }}>•</span>
                                </>
                            ) : null}
                            {item.filePath ? (
                                <span>{item.filePath.split("/").pop()}</span>
                            ) : (
                                "Unknown location"
                            )}
                        </span>
                    </div>
                    <div className="violation-summary-meta">
                        {item.autoRemediationSupported && (
                            <span className="badge badge-fixable">Fix Available</span>
                        )}
                        <span
                            className={`badge badge-${item.severity
                                .toLowerCase()
                                .replace(/[^a-z0-9]+/g, "-")}`}
                        >
                            {item.severity}
                        </span>
                    </div>
                </div>
            </summary>

            <div className="violation-body">
                <dl className="violation-meta-grid">
                    <div>
                        <dt>Violation ID</dt>
                        <dd>{item.violationId ?? "—"}</dd>
                    </div>
                    <div>
                        <dt>Control</dt>
                        <dd>{item.control ?? "—"}</dd>
                    </div>
                    <div>
                        <dt>Full Path</dt>
                        <dd className="break-all" style={{ fontSize: "0.85rem", fontFamily: "var(--font-mono)" }}>
                            {item.filePath ?? "—"}
                        </dd>
                    </div>
                </dl>

                <div className="violation-actions-grid">
                    <section className="violation-section">
                        <header>
                            <h4>Analysis & Review</h4>
                        </header>

                        <div style={{ display: "grid", gap: "1rem" }}>
                            {/* Review Controls */}
                            <div style={{ background: "white", padding: "1rem", borderRadius: "8px", border: "1px solid var(--color-slate-200)" }}>
                                <fieldset style={{ border: "none", padding: 0, margin: "0 0 1rem 0" }}>
                                    <legend style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--color-slate-500)", marginBottom: "0.5rem" }}>
                                        Mark status
                                    </legend>
                                    <div style={{ display: "flex", gap: "1rem" }}>
                                        {["TP", "FP", "UNCLEAR"].map((label) => (
                                            <label key={label} style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.9rem", fontWeight: 500 }}>
                                                <input
                                                    type="radio"
                                                    name={`review-${violationKey}`}
                                                    checked={reviewDraft.label === label}
                                                    onChange={() =>
                                                        setReviewDraft({ ...reviewDraft, label: label as any })
                                                    }
                                                />
                                                {label}
                                            </label>
                                        ))}
                                    </div>
                                </fieldset>

                                <textarea
                                    rows={3}
                                    placeholder="Add review notes..."
                                    style={{ width: "100%", marginBottom: "1rem" }}
                                    value={reviewDraft.notes}
                                    onChange={(e) =>
                                        setReviewDraft({ ...reviewDraft, notes: e.target.value })
                                    }
                                />

                                <div style={{ display: "flex", gap: "0.5rem" }}>
                                    <button
                                        type="button"
                                        disabled={!reviewDraft.label || isSavingReview}
                                        onClick={onSaveReview}
                                    >
                                        {isSavingReview ? "Saving..." : "Save Review"}
                                    </button>
                                    <button
                                        type="button"
                                        className="btn-secondary"
                                        style={{ background: "transparent", border: "1px solid var(--color-slate-300)", color: "var(--color-slate-600)" }}
                                        disabled={isExplaining}
                                        onClick={onExplain}
                                    >
                                        {isExplaining ? "Analyzing..." : "Ask AI to Explain"}
                                    </button>
                                </div>
                            </div>

                            {explanation?.explanation && (
                                <div className="remediation-panel" style={{ borderLeft: "4px solid var(--color-primary-500)" }}>
                                    <h5 style={{ marginTop: 0, color: "var(--color-primary-700)" }}>AI Explanation</h5>
                                    <div
                                        className="llm-text"
                                        dangerouslySetInnerHTML={{
                                            __html: toHtml(explanation.explanation)
                                        }}
                                    />
                                </div>
                            )}
                        </div>
                    </section>

                    <section className="violation-section">
                        <header>
                            <h4>Remediation</h4>
                        </header>

                        {!item.autoRemediationSupported ? (
                            <div className="callout" style={{ background: "var(--color-slate-100)", border: "none" }}>
                                <p className="muted" style={{ margin: 0 }}>Automated remediation is not available for this violation type.</p>
                            </div>
                        ) : (
                            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                                <div style={{ display: "flex", gap: "0.5rem" }}>
                                    <button
                                        type="button"
                                        disabled={isStarting || disableRemediationButtons}
                                        onClick={onRemediate}
                                    >
                                        {isStarting ? "Generating..." : "Preview Fix"}
                                    </button>
                                    <button
                                        type="button"
                                        onClick={onApply}
                                        disabled={isApplying || disableRemediationButtons}
                                        style={{ background: "white", color: "var(--color-success)", border: "1px solid var(--color-success)", boxShadow: "none" }}
                                    >
                                        {isApplying ? "Applying..." : "Apply Fix"}
                                    </button>
                                </div>

                                {(remediationOutcome || applyOutcome) && (
                                    <div className="remediation-panel">
                                        <p className="remediation-status">
                                            {applyOutcome ? `Apply Status: ${applyOutcome.status}` : `Preview Status: ${remediationOutcome?.status}`}
                                        </p>

                                        {/* Error Display */}
                                        {(remediationOutcome?.error || applyOutcome?.error) && (
                                            <p className="callout callout-error">
                                                {formatAutoRemediationError(applyOutcome?.error || remediationOutcome?.error)}
                                            </p>
                                        )}

                                        {(applyOutcome?.updated_source_code || remediationOutcome?.updated_source_code) && (
                                            <div style={{ maxHeight: "300px", overflow: "auto", marginTop: "1rem" }}>
                                                <CodeHighlight
                                                    code={applyOutcome?.updated_source_code || remediationOutcome?.updated_source_code || ""}
                                                    language="java"
                                                />
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        )}
                    </section>
                </div>
            </div>
        </details>
    );
};
