import { FormEvent, MouseEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  evaluatePolicies,
  evaluatePoliciesWithLLM,
  fetchPolicyCatalog,
  previewRemediation
} from "../lib/api";
import type {
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  RemediationPreviewResponse
} from "../lib/types";
import { useActivityContext } from "../context/ActivityContext";
import { toast } from "react-hot-toast";
import CodeHighlight from "../components/CodeHighlight";

interface ViolationSummary {
  raw: Record<string, unknown>;
  control: string;
  severity: string;
  resource: string;
  description: string;
  violationId?: string;
  method?: string;
  filePath?: string;
}

const PolicyPage = () => {
  const [limit, setLimit] = useState(5);
  const [model, setModel] = useState("");
  const [evaluation, setEvaluation] =
    useState<PolicyEvaluateResponse | null>(null);
  const [llmEvaluation, setLlmEvaluation] =
    useState<PolicyEvaluateResponse | null>(null);
  const [llmStatus, setLlmStatus] = useState<string | null>(null);
  const [remediationPreviews, setRemediationPreviews] = useState<
    Record<string, RemediationPreviewResponse>
  >({});
  const { upsert: upsertActivity, clear: clearActivity } = useActivityContext();

  const catalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: fetchPolicyCatalog
  });

  const baseEvalMutation = useMutation({
    mutationFn: evaluatePolicies,
    onSuccess: (data) => {
      setEvaluation(data);
      const violationCount = data.violations?.length ?? 0;
      toast.success(
        violationCount > 0
          ? `${violationCount} violation${violationCount === 1 ? "" : "s"} detected.`
          : "No policy violations detected."
      );
    },
    onError: (error: Error) => {
      setEvaluation({ error: error.message });
      toast.error(`Evaluation failed: ${error.message}`);
    }
  });

  const llmEvalMutation = useMutation({
    mutationFn: () => evaluatePoliciesWithLLM(limit, model || undefined),
    onSuccess: (data) => {
      setLlmEvaluation(data);
      setLlmStatus("LLM explanations generated.");
      toast.success("LLM explanations ready.");
    },
    onError: (error: Error) => {
      setLlmEvaluation({ error: error.message });
      const message = `LLM request failed: ${error.message}`;
      setLlmStatus(message);
      toast.error(message);
    }
  });

  const remediationPreviewMutation = useMutation({
    mutationFn: (args: { violationId: string; targetMethod?: string; filePath?: string; key: string }) =>
      previewRemediation(args.violationId, args.targetMethod, args.filePath),
    onSuccess: (data, variables) => {
      const key = variables.key;
      setRemediationPreviews((prev) => ({
        ...prev,
        [key]: data
      }));
      toast.success(`Preview ready for ${variables.violationId}.`);
    },
    onError: (error: Error, variables) => {
      toast.error(
        `Failed to preview remediation for ${variables.violationId}: ${error.message}`
      );
    }
  });

  const baseEvalPending = baseEvalMutation.status === "pending";
  const llmEvalPending = llmEvalMutation.status === "pending";
  const remediationPending = remediationPreviewMutation.status === "pending";
  const activeRemediationKey = remediationPending
    ? ((remediationPreviewMutation.variables as { key?: string } | undefined)?.key ??
      undefined)
    : undefined;

  const handleLlmSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLlmStatus("Requesting LLM explanations…");
    setLlmEvaluation(null);
    upsertActivity({
      key: "policy-llm",
      label: "Policy LLM Explanations",
      status: "running",
      message: "Generating explanations…",
      progress: undefined,
      updatedAt: new Date().toISOString()
    });
    llmEvalMutation.mutate();
  };

  const hasViolations = useMemo(() => {
    return Boolean(evaluation?.violations && evaluation.violations.length > 0);
  }, [evaluation]);

  const enrichedViolations = useMemo(() => {
    if (!llmEvaluation || !llmEvaluation.enriched) {
      return [];
    }
    return llmEvaluation.enriched as Array<Record<string, unknown>>;
  }, [llmEvaluation]);

  const handleRemediation = (
    violationId?: string,
    targetMethod?: string,
    filePath?: string,
    key?: string,
    event?: MouseEvent<HTMLButtonElement>
  ) => {
    event?.stopPropagation();
    if (!violationId || !key) {
      toast.error("Selected violation is missing an identifier.");
      return;
    }
    remediationPreviewMutation.mutate({
      violationId,
      targetMethod,
      filePath,
      key
    });
  };
  const toHtml = (value?: string | null) => {
    if (!value) {
      return "";
    }
    return value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/\*(.+?)\*/g, "<em>$1</em>")
      .replace(/`(.+?)`/g, "<code>$1</code>")
      .replace(/\n/g, "<br />");
  };

  const violationSummaries = useMemo(() => {
    if (!evaluation?.violations) {
      return [] as ViolationSummary[];
    }
    return evaluation.violations.map((item) => {
      const record = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
      const pickString = (keys: string[], fallback = "—") => {
        for (const key of keys) {
          const value = record[key];
          if (typeof value === "string" && value.trim().length > 0) {
            return value;
          }
        }
        return fallback;
      };
      const control = pickString(["control", "id", "policy", "rule"], "Unknown");
      const severity = pickString(["severity", "level", "priority"], "Low");
      const resource = pickString(["resource", "node", "target", "entity", "asset"], "—");
      const description = pickString(["description", "message", "detail", "reason"], "—");
      const violationId = pickString(["violation_id", "id", "control", "rule"], "");
      const method = pickString(["target_method", "method", "signature"], undefined);
      const filePath = pickString(["file_path", "file"], undefined);
      return {
        raw: record,
        control,
        severity,
        resource,
        description,
        violationId,
        method,
        filePath
      } satisfies ViolationSummary;
    });
  }, [evaluation]);

  useEffect(() => {
    if (baseEvalPending) {
      upsertActivity({
        key: "policy-base",
        label: "Policy Evaluation",
        status: "running",
        message: "Evaluating policies…",
        progress: undefined,
        updatedAt: new Date().toISOString()
      });
    } else if (baseEvalMutation.isError) {
      const message =
        baseEvalMutation.error instanceof Error
          ? baseEvalMutation.error.message
          : "Policy evaluation failed.";
      upsertActivity({
        key: "policy-base",
        label: "Policy Evaluation",
        status: "error",
        message,
        progress: undefined,
        updatedAt: new Date().toISOString()
      });
    } else if (baseEvalMutation.isSuccess) {
      const message = hasViolations
        ? `${evaluation?.violations?.length ?? 0} violation(s) detected.`
        : "No violations detected.";
      upsertActivity({
        key: "policy-base",
        label: "Policy Evaluation",
        status: "success",
        message,
        progress: undefined,
        updatedAt: new Date().toISOString()
      });
    }
  }, [
    baseEvalPending,
    baseEvalMutation.isError,
    baseEvalMutation.isSuccess,
    baseEvalMutation.error,
    evaluation,
    hasViolations,
    upsertActivity
  ]);

  useEffect(() => {
    if (llmEvalPending) {
      upsertActivity({
        key: "policy-llm",
        label: "Policy LLM Explanations",
        status: "running",
        message: "Generating explanations…",
        progress: undefined,
        updatedAt: new Date().toISOString()
      });
    } else if (llmEvalMutation.isError) {
      const message =
        llmEvalMutation.error instanceof Error
          ? llmEvalMutation.error.message
          : "LLM enrichment failed.";
      upsertActivity({
        key: "policy-llm",
        label: "Policy LLM Explanations",
        status: "error",
        message,
        progress: undefined,
        updatedAt: new Date().toISOString()
      });
    } else if (llmEvalMutation.isSuccess) {
      upsertActivity({
        key: "policy-llm",
        label: "Policy LLM Explanations",
        status: "success",
        message: "Explanations ready.",
        progress: undefined,
        updatedAt: new Date().toISOString()
      });
    }
  }, [
    llmEvalPending,
    llmEvalMutation.isError,
    llmEvalMutation.isSuccess,
    llmEvalMutation.error,
    upsertActivity
  ]);

  useEffect(() => {
    return () => {
      clearActivity("policy-base");
      clearActivity("policy-llm");
    };
  }, [clearActivity]);

  return (
    <section className="card">
      <h1>Policy Evaluation</h1>
      <p>
        Run ISO 27001 policy checks against the ingested knowledge graph and
        optionally request LLM-authored explanations for any violations.
      </p>
      <div className="policy-actions">
        <button
          onClick={() => baseEvalMutation.mutate()}
          disabled={baseEvalPending}
        >
          {baseEvalPending && <span className="btn-spinner" aria-hidden="true" />}
          <span>{baseEvalPending ? "Checking…" : "Evaluate Policies"}</span>
        </button>
        <form className="policy-llm-form" onSubmit={handleLlmSubmit}>
          <label>
            Limit
            <input
              type="number"
              min={1}
              max={50}
              value={limit}
              onChange={(event) => setLimit(Number(event.target.value))}
            />
          </label>
          <label>
            LLM model (optional)
            <input
              type="text"
              value={model}
              onChange={(event) => setModel(event.target.value)}
              placeholder="Override backend default"
            />
          </label>
          <button type="submit" disabled={llmEvalPending}>
            {llmEvalPending && <span className="btn-spinner" aria-hidden="true" />}
            <span>{llmEvalPending ? "Requesting…" : "Evaluate with LLM"}</span>
          </button>
        </form>
      </div>

      {evaluation && (
        <div className="policy-results">
          <h2>Evaluation Result</h2>
          {evaluation.error ? (
            <div className="callout callout-error">
              <p>Error: {evaluation.error}</p>
              <button
                type="button"
                className="callout-action"
                onClick={() => baseEvalMutation.mutate()}
              >
                Retry evaluation
              </button>
            </div>
          ) : (
            <>
              <p className="muted">
                {hasViolations
                  ? `${evaluation.violations?.length ?? 0} potential violation(s) detected.`
                  : "No violations detected by OPA policies."}
              </p>
              {hasViolations && violationSummaries.length > 0 && (
                <div className="violation-deck">
                  {violationSummaries.map((item, index) => {
                    const violationKey = `${item.violationId || "unknown"}::${
                      item.method || ""
                    }::${item.filePath || ""}`;
                    const remediationOutcome = remediationPreviews[violationKey];
                    const verification = remediationOutcome?.verification as
                      | Record<string, unknown>
                      | undefined;
                    const targetRuleStatus =
                      typeof verification?.target_rule_status === "string"
                        ? verification.target_rule_status
                        : remediationOutcome?.opa_status;
                    const overallStatus =
                      typeof verification?.overall_status === "string"
                        ? verification.overall_status
                        : undefined;
                    const newViolations =
                      Array.isArray(verification?.new_violations)
                        ? verification?.new_violations?.length
                        : undefined;
                    const remainingViolations =
                      Array.isArray(verification?.remaining_violations)
                        ? verification?.remaining_violations?.length
                        : undefined;
                    const isStarting =
                      remediationPending && activeRemediationKey === violationKey;
                    return (
                      <details
                        className="violation-card"
                        key={`violation-${index}`}
                        open={index === 0}
                      >
                        <summary>
                          <div className="violation-summary">
                            <div className="violation-summary-text">
                              <span className="violation-control">
                                {item.control || "Unmapped control"}
                              </span>
                              <strong>{item.description}</strong>
                              {item.method && (
                                <span className="violation-method">{item.method}</span>
                              )}
                              {item.filePath && (
                                <span className="violation-path">{item.filePath}</span>
                              )}
                            </div>
                            <div className="violation-summary-meta">
                              <span
                                className={`severity-chip severity-${item.severity
                                  .toLowerCase()
                                  .replace(/[^a-z0-9]+/g, "-")}`}
                              >
                                {item.severity}
                              </span>
                              <button
                                type="button"
                                className="remediation-button"
                                disabled={
                                  !item.violationId || isStarting
                                }
                                onClick={(event) =>
                                  handleRemediation(
                                    item.violationId,
                                    item.method,
                                    item.filePath,
                                    violationKey,
                                    event
                                  )
                                }
                              >
                                {isStarting ? (
                                  <>
                                    <span className="btn-spinner" aria-hidden="true" />
                                    <span>Previewing…</span>
                                  </>
                                ) : (
                                  <span>
                                    {remediationOutcome ? "Re-run Preview" : "Fix &amp; Verify"}
                                  </span>
                                )}
                              </button>
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
                              <dt>Resource</dt>
                              <dd>{item.resource}</dd>
                            </div>
                            <div>
                              <dt>Severity</dt>
                              <dd>{item.severity}</dd>
                            </div>
                          </dl>
                          <div className="violation-detail-grid">
                            <section>
                              <header>
                                <h4>Raw evidence</h4>
                              </header>
                              <CodeHighlight
                                code={JSON.stringify(item.raw, null, 2)}
                                language="json"
                              />
                            </section>
                            <section>
                              <header>
                                <h4>Remediation</h4>
                              </header>
                              {!item.violationId ? (
                                <p className="muted">
                                  This violation is missing an identifier required for remediation.
                                </p>
                              ) : remediationOutcome ? (
                                <div className="remediation-panel">
                                  <p className="remediation-status">
                                    {remediationOutcome.opa_status
                                      ? `OPA: ${remediationOutcome.opa_status}`
                                      : remediationOutcome.status}
                                    {remediationOutcome.rule_id
                                      ? ` (${remediationOutcome.rule_id})`
                                      : ""}
                                  </p>
                                  {remediationOutcome.explanation && (
                                    <p className="remediation-note">
                                      {remediationOutcome.explanation}
                                    </p>
                                  )}
                                  {typeof remediationOutcome.error === "string" && (
                                    <p className="callout callout-error">
                                      {remediationOutcome.error}
                                    </p>
                                  )}
                                  {targetRuleStatus && (
                                    <p className="remediation-note">
                                      Target rule status: {targetRuleStatus}
                                    </p>
                                  )}
                                  {overallStatus && (
                                    <p className="remediation-note">
                                      Overall status: {overallStatus}
                                    </p>
                                  )}
                                  {typeof newViolations === "number" && (
                                    <p className="remediation-note">
                                      New violations: {newViolations}
                                    </p>
                                  )}
                                  {typeof remainingViolations === "number" && (
                                    <p className="remediation-note">
                                      Remaining violations: {remainingViolations}
                                    </p>
                                  )}
                                  {remediationOutcome.updated_source_code ? (
                                    <CodeHighlight
                                      code={remediationOutcome.updated_source_code}
                                      language="java"
                                    />
                                  ) : (
                                    <CodeHighlight
                                      code={JSON.stringify(remediationOutcome, null, 2)}
                                      language="json"
                                    />
                                  )}
                                  {remediationOutcome.diff && (
                                    <CodeHighlight
                                      code={remediationOutcome.diff}
                                      language="text"
                                    />
                                  )}
                                </div>
                              ) : (
                                <p className="muted">
                                  Run “Fix &amp; Verify” to propose and validate a patch.
                                </p>
                              )}
                            </section>
                          </div>
                        </div>
                      </details>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {llmEvaluation && (
        <div className="policy-results">
          <h2>LLM Enriched Result</h2>
          {llmEvaluation.error ? (
            <div className="callout callout-error">
              <p>Error: {llmEvaluation.error}</p>
              <button
                type="button"
                className="callout-action"
                onClick={() => llmEvalMutation.mutate()}
              >
                Retry LLM request
              </button>
            </div>
          ) : (
            <>
              <p className="muted">
                Showing explanations for up to {limit} violation(s).
              </p>
              {enrichedViolations.length === 0 ? (
                <p>No enriched explanations returned.</p>
              ) : (
                <div className="llm-results">
                  {enrichedViolations.map((item, index) => {
                    const title =
                      (typeof item.title === "string" && item.title) ||
                      (typeof item.control === "string" && item.control) ||
                      `Violation ${index + 1}`;
                    const explanation =
                      (typeof item.explanation === "string" && item.explanation) ||
                      (typeof item.summary === "string" && item.summary);
                    const remediation =
                      (typeof item.remediation === "string" && item.remediation) ||
                      (typeof item.action === "string" && item.action);
                    const snippet =
                      (typeof item.snippet === "string" && item.snippet) ||
                      (typeof item.code === "string" && item.code);
                    const severity =
                      (typeof item.severity === "string" && item.severity) || undefined;
                    const violationRecord =
                      item?.violation && typeof item.violation === "object"
                        ? (item.violation as Record<string, unknown>)
                        : null;
                    const methodCandidate =
                      violationRecord && typeof violationRecord.target_method === "string"
                        ? violationRecord.target_method
                        : undefined;
                    const method =
                      methodCandidate ||
                      (typeof item.method === "string" ? item.method : undefined);

                    return (
                      <details className="llm-card" key={`llm-${index}`} open={index === 0}>
                        <summary>
                          <div className="llm-card-summary">
                            <div className="llm-card-summary-text">
                              <strong>{title}</strong>
                              {method && <span className="llm-card-method">{method}</span>}
                            </div>
                            {severity && (
                              <span
                                className={`severity-chip severity-${severity
                                  .toLowerCase()
                                  .replace(/[^a-z0-9]+/g, "-")}`}
                              >
                                {severity}
                              </span>
                            )}
                          </div>
                        </summary>
                        <div className="llm-card-body">
                          {explanation && (
                            <section>
                              <h4>Explanation</h4>
                              <div
                                className="llm-text"
                                dangerouslySetInnerHTML={{ __html: toHtml(explanation) }}
                              />
                            </section>
                          )}
                          {remediation && (
                            <section>
                              <h4>Recommended Action</h4>
                              <div
                                className="llm-text"
                                dangerouslySetInnerHTML={{ __html: toHtml(remediation) }}
                              />
                            </section>
                          )}
                          {snippet && (
                            <section>
                              <h4>Snippet</h4>
                              <CodeHighlight code={snippet} language="java" />
                            </section>
                          )}
                          <section>
                            <details>
                              <summary>Raw response</summary>
                              <CodeHighlight code={JSON.stringify(item, null, 2)} language="json" />
                            </details>
                          </section>
                        </div>
                      </details>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {llmStatus && (
        <div className={`status-banner ${llmEvalMutation.isError ? "status-error" : llmEvalMutation.isSuccess ? "status-success" : "status-info"}`}>
          {llmStatus}
        </div>
      )}

      {llmEvalPending && (
        <div className="policy-overlay" aria-live="polite">
          <div className="spinner" role="status" aria-label="Requesting LLM" />
          <p>Asking the LLM to enrich policy violations…</p>
        </div>
      )}

      <section className="policy-catalog">
        <h2>ISO 27001 Catalog</h2>
        {catalogQuery.isLoading && <p>Loading catalog…</p>}
        {catalogQuery.error && (
          <div className="callout callout-error">
            Error loading catalog: {catalogQuery.error.message}
          </div>
        )}
        {catalogQuery.data && (
          <ul>
            {catalogQuery.data.controls.map((control, index) => (
              <li key={control.control ?? control.id ?? index}>
                <strong>{control.control ?? control.id ?? "Control"}</strong>{" "}
                {control.title && <span>- {control.title}</span>}
                {control.description && (
                  <p className="muted">{control.description}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </section>
  );
};

export default PolicyPage;
