import { FormEvent, MouseEvent, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  applyRemediation,
  explainPolicyViolationOne,
  evaluatePolicies,
  evaluatePoliciesWithLLM,
  fetchPolicyCatalog,
  previewRemediation,
  saveViolationReview
} from "../lib/api";
import type {
  PolicyCatalogResponse,
  PolicyEvaluateResponse,
  PolicyExplainOneResponse,
  PolicyReviewLabel,
  PolicyReviewCreateResponse,
  RemediationApplyResponse,
  RemediationPreviewResponse
} from "../lib/types";
import { useActivityContext } from "../context/ActivityContext";
import { toast } from "react-hot-toast";
import CodeHighlight from "../components/CodeHighlight";

interface ViolationSummary {
  raw: Record<string, unknown>;
  violationId?: string;
  filePath?: string;
  targetMethod?: string;
  title: string;
  reason?: string;
  severity: string;
  control: string;
  autoRemediationSupported: boolean;
}

interface ReviewDraft {
  label?: PolicyReviewLabel;
  notes: string;
  includeGraphContext: boolean;
}

interface ReviewSaved {
  reviewId: string;
  savedAt: string;
  storePath?: string | null;
  scrubWarnings?: string[];
}

const SUPPORTED_AUTO_REMEDIATION_RULES = new Set([
  "ISO-A.10-WEAK-HASH",
  "ISO-A.10-WEAK-CRYPTO"
]);

const ruleIdVariants = (ruleId?: string) => {
  const text = (ruleId ?? "").trim();
  if (!text) {
    return [];
  }
  const variants = [text];
  let base = text;
  if (base.startsWith("ISO-27001-")) {
    base = base.slice("ISO-27001-".length);
  } else if (base.startsWith("ISO-")) {
    base = base.slice("ISO-".length);
  }
  for (const candidate of [base, `ISO-${base}`, `ISO-27001-${base}`]) {
    if (candidate && !variants.includes(candidate)) {
      variants.push(candidate);
    }
  }
  return variants;
};

const isAutoRemediationSupported = (ruleId?: string) => {
  for (const candidate of ruleIdVariants(ruleId)) {
    if (SUPPORTED_AUTO_REMEDIATION_RULES.has(candidate)) {
      return true;
    }
  }
  return false;
};

if (import.meta.env.DEV) {
  console.assert(
    isAutoRemediationSupported("ISO-A.10-WEAK-HASH"),
    "Expected ISO-A.10-WEAK-HASH to be recognized as auto-remediable."
  );
  console.assert(
    isAutoRemediationSupported("A.10-WEAK-HASH"),
    "Expected A.10-WEAK-HASH to be recognized as auto-remediable via normalization."
  );
}

const PolicyPage = () => {
  const [limit, setLimit] = useState(5);
  const [model, setModel] = useState("");
  const [showRemediableOnly, setShowRemediableOnly] = useState(false);
  const [interactiveMaxBundles, setInteractiveMaxBundles] = useState(500);
  const [interactiveMaxTotal, setInteractiveMaxTotal] = useState(100);
  const [interactiveMaxPerRule, setInteractiveMaxPerRule] = useState(25);
  const [batchUseInteractiveCaps, setBatchUseInteractiveCaps] = useState(true);
  const [evaluation, setEvaluation] =
    useState<PolicyEvaluateResponse | null>(null);
  const [llmEvaluation, setLlmEvaluation] =
    useState<PolicyEvaluateResponse | null>(null);
  const [llmStatus, setLlmStatus] = useState<string | null>(null);
  const [explanationsByKey, setExplanationsByKey] = useState<
    Record<string, PolicyExplainOneResponse & { updatedAt: string }>
  >({});
  const [reviewDraftByKey, setReviewDraftByKey] = useState<
    Record<string, ReviewDraft>
  >({});
  const [reviewSavedByKey, setReviewSavedByKey] = useState<
    Record<string, ReviewSaved>
  >({});
  const [remediationPreviews, setRemediationPreviews] = useState<
    Record<string, RemediationPreviewResponse>
  >({});
  const [remediationApplies, setRemediationApplies] = useState<
    Record<string, RemediationApplyResponse>
  >({});
  const { upsert: upsertActivity, clear: clearActivity } = useActivityContext();

  const catalogQuery = useQuery<PolicyCatalogResponse, Error>({
    queryKey: ["policyCatalog"],
    queryFn: fetchPolicyCatalog
  });

  const baseEvalMutation = useMutation({
    mutationFn: (args?: { maxBundles?: number; maxTotalViolations?: number; maxPerViolationId?: number }) =>
      evaluatePolicies(args),
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
    mutationFn: () =>
      evaluatePoliciesWithLLM({
        limit,
        model: model || undefined,
        maxBundles: batchUseInteractiveCaps ? interactiveMaxBundles : undefined,
        maxTotalViolations: batchUseInteractiveCaps ? interactiveMaxTotal : undefined,
        maxPerViolationId: batchUseInteractiveCaps ? interactiveMaxPerRule : undefined
      }),
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
      const status = (data.status || "").toUpperCase();
      if (status === "OK") {
        toast.success(`Preview ready for ${variables.violationId}.`);
      } else {
        toast.error(`Preview finished with status ${data.status} for ${variables.violationId}.`);
      }
    },
    onError: (error: Error, variables) => {
      toast.error(
        `Failed to preview remediation for ${variables.violationId}: ${error.message}`
      );
    }
  });

  const remediationApplyMutation = useMutation({
    mutationFn: (args: { violationId: string; targetMethod?: string; filePath?: string; key: string }) =>
      applyRemediation({
        violation_id: args.violationId,
        target_method: args.targetMethod,
        file_path: args.filePath
      }),
    onSuccess: (data, variables) => {
      const key = variables.key;
      setRemediationApplies((prev) => ({
        ...prev,
        [key]: data
      }));
      const status = (data.status || "").toUpperCase();
      if (status === "OK") {
        toast.success(`Dry-run apply verified for ${variables.violationId}.`);
      } else {
        toast.error(
          `Dry-run apply finished with status ${data.status} for ${variables.violationId}.`
        );
      }
    },
    onError: (error: Error, variables) => {
      toast.error(
        `Apply+verify failed for ${variables.violationId}: ${error.message}`
      );
    }
  });

  const explainOneMutation = useMutation({
    mutationFn: (args: {
      key: string;
      violation: Record<string, unknown>;
      includeGraphContext: boolean;
      model?: string;
    }) =>
      explainPolicyViolationOne({
        violation: args.violation,
        include_graph_context: args.includeGraphContext,
        model: args.model ?? null
      }),
    onSuccess: (data, variables) => {
      setExplanationsByKey((prev) => ({
        ...prev,
        [variables.key]: {
          ...data,
          updatedAt: new Date().toISOString()
        }
      }));
      if ((data.status || "").toUpperCase() === "OK") {
        toast.success("Explanation ready.");
      } else {
        toast.error(data.error || "Explanation failed.");
      }
    },
    onError: (error: Error) => {
      toast.error(`Explain failed: ${error.message}`);
    }
  });

  const saveReviewMutation = useMutation({
    mutationFn: (args: {
      key: string;
      label: PolicyReviewLabel;
      notes: string;
      violation: Record<string, unknown>;
      includeGraphContext: boolean;
      explanation?: PolicyExplainOneResponse | null;
      remediationPreview?: RemediationPreviewResponse;
      remediationApply?: RemediationApplyResponse;
    }) =>
      saveViolationReview({
        label: args.label,
        notes: args.notes || null,
        violation: args.violation,
        explanation: args.explanation?.explanation ?? null,
        llm_model: args.explanation?.model ?? model ?? null,
        include_graph_context: args.includeGraphContext,
        remediation_preview: (args.remediationPreview as unknown as Record<string, unknown>) ?? null,
        remediation_apply: (args.remediationApply as unknown as Record<string, unknown>) ?? null
      }),
    onSuccess: (data: PolicyReviewCreateResponse, variables) => {
      const status = (data.status || "").toUpperCase();
      if (status !== "OK") {
        toast.error(data.error || "Failed to save review.");
        return;
      }
      setReviewSavedByKey((prev) => ({
        ...prev,
        [variables.key]: {
          reviewId: data.review_id || "unknown",
          savedAt: new Date().toISOString(),
          storePath: data.store_path,
          scrubWarnings: data.scrub_warnings || []
        }
      }));
      toast.success("Review saved.");
    },
    onError: (error: Error) => {
      toast.error(`Save review failed: ${error.message}`);
    }
  });

  const baseEvalPending = baseEvalMutation.status === "pending";
  const isFullEvalRunning =
    baseEvalPending && (baseEvalMutation.variables == null);
  const isInteractiveEvalRunning =
    baseEvalPending && (baseEvalMutation.variables != null);
  const llmEvalPending = llmEvalMutation.status === "pending";
  const remediationPending = remediationPreviewMutation.status === "pending";
  const applyPending = remediationApplyMutation.status === "pending";
  const explainPending = explainOneMutation.status === "pending";
  const saveReviewPending = saveReviewMutation.status === "pending";
  const activeRemediationKey = remediationPending
    ? ((remediationPreviewMutation.variables as { key?: string } | undefined)?.key ??
      undefined)
    : undefined;
  const activeApplyKey = applyPending
    ? ((remediationApplyMutation.variables as { key?: string } | undefined)?.key ??
      undefined)
    : undefined;
  const activeExplainKey = explainPending
    ? ((explainOneMutation.variables as { key?: string } | undefined)?.key ?? undefined)
    : undefined;
  const activeSaveReviewKey = saveReviewPending
    ? ((saveReviewMutation.variables as { key?: string } | undefined)?.key ?? undefined)
    : undefined;

  const handleLlmSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLlmStatus("Requesting batch LLM explanations…");
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

  const evaluationMeta = useMemo(() => {
    if (!evaluation || typeof evaluation !== "object") {
      return null;
    }
    const record = evaluation as unknown as Record<string, unknown>;
    const limits =
      record.limits && typeof record.limits === "object"
        ? (record.limits as Record<string, unknown>)
        : null;
    const truncated = Boolean(record.truncated);
    const bundleCount =
      typeof record.bundle_count === "number" ? record.bundle_count : null;
    const opaRuns = typeof record.opa_runs === "number" ? record.opa_runs : null;
    return {
      truncated,
      limits,
      bundleCount,
      opaRuns
    };
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

  const handleApply = (
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
    if (!targetMethod || !filePath) {
      toast.error("Apply+verify requires both target_method and file_path.");
      return;
    }
    remediationApplyMutation.mutate({
      violationId,
      targetMethod,
      filePath,
      key
    });
  };

  const handleExplainOne = (
    violation: Record<string, unknown>,
    key: string,
    includeGraphContext: boolean,
    event?: MouseEvent<HTMLButtonElement>
  ) => {
    event?.stopPropagation();
    explainOneMutation.mutate({
      key,
      violation,
      includeGraphContext,
      model: model || undefined
    });
  };

  const handleSaveReview = (
    violation: Record<string, unknown>,
    key: string,
    label: PolicyReviewLabel,
    notes: string,
    includeGraphContext: boolean,
    remediationPreview?: RemediationPreviewResponse,
    remediationApply?: RemediationApplyResponse,
    event?: MouseEvent<HTMLButtonElement>
  ) => {
    event?.stopPropagation();
    const explanation = explanationsByKey[key] ?? null;
    saveReviewMutation.mutate({
      key,
      label,
      notes,
      violation,
      includeGraphContext,
      explanation,
      remediationPreview,
      remediationApply
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

  const formatAutoRemediationError = (value?: string | null) => {
    if (!value) {
      return null;
    }
    const normalized = value.toLowerCase();
    if (normalized.includes("unsupported_rule_for_auto_fix")) {
      return "No automatic remediation for this rule yet.";
    }
    if (normalized.startsWith("no_fix:") || normalized.startsWith("no_fix")) {
      return value.replace(/^no_fix:\s*/i, "NO_FIX: ");
    }
    return value;
  };

  const violationSummaries = useMemo(() => {
    if (!evaluation?.violations) {
      return [] as ViolationSummary[];
    }
    return evaluation.violations.map((item) => {
      const record = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
      const getString = (key: string): string | undefined => {
        const value = record[key];
        if (typeof value === "string") {
          const trimmed = value.trim();
          return trimmed.length > 0 ? trimmed : undefined;
        }
        return undefined;
      };

      const violationId = getString("violation_id") ?? getString("id");
      const reason =
        getString("reason") ??
        getString("description") ??
        getString("message") ??
        getString("detail");
      const severity = getString("severity") ?? "high";
      const filePath = getString("file_path") ?? getString("file");
      const targetMethod =
        getString("target_method") ?? getString("method") ?? getString("signature");

      const controlMetadata =
        record.control_metadata && typeof record.control_metadata === "object"
          ? (record.control_metadata as Record<string, unknown>)
          : undefined;
      const control =
        (controlMetadata?.title && typeof controlMetadata.title === "string"
          ? controlMetadata.title
          : undefined) ??
        (controlMetadata?.control && typeof controlMetadata.control === "string"
          ? controlMetadata.control
          : undefined) ??
        (controlMetadata?.control_id && typeof controlMetadata.control_id === "string"
          ? controlMetadata.control_id
          : undefined) ??
        (controlMetadata?.id && typeof controlMetadata.id === "string"
          ? controlMetadata.id
          : undefined) ??
        violationId ??
        "Unknown";

      const title = violationId ?? reason ?? "Violation";
      const autoRemediationSupported = isAutoRemediationSupported(violationId);
      return {
        raw: record,
        control,
        violationId,
        filePath,
        targetMethod,
        title,
        reason,
        severity,
        autoRemediationSupported
      } satisfies ViolationSummary;
    });
  }, [evaluation]);

  const displayedViolationSummaries = useMemo(() => {
    if (!showRemediableOnly) {
      return violationSummaries;
    }
    return violationSummaries.filter((item) => item.autoRemediationSupported);
  }, [showRemediableOnly, violationSummaries]);

  const defaultOpenViolationIndex = useMemo(() => {
    if (displayedViolationSummaries.length === 0) {
      return 0;
    }
    const firstFixable = displayedViolationSummaries.findIndex(
      (item) => item.autoRemediationSupported
    );
    return firstFixable >= 0 ? firstFixable : 0;
  }, [displayedViolationSummaries]);

  const autoRemediableCount = useMemo(() => {
    return violationSummaries.reduce((count, item) => {
      return count + (item.autoRemediationSupported ? 1 : 0);
    }, 0);
  }, [violationSummaries]);

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
        <div className="policy-action-card">
          <header>
            <h3>Full evaluation (uncapped)</h3>
            <p className="muted">
              Scans the entire knowledge graph. This can be slow on large codebases, but is the closest match to
              experiment-grade behavior.
            </p>
          </header>
          <button onClick={() => baseEvalMutation.mutate(undefined)} disabled={baseEvalPending}>
            {isFullEvalRunning && <span className="btn-spinner" aria-hidden="true" />}
            <span>{isFullEvalRunning ? "Checking…" : "Run full evaluation"}</span>
          </button>
        </div>

        <div className="policy-action-card">
          <header>
            <h3>Interactive (capped) evaluation</h3>
            <p className="muted">
              Recommended for UI triage. Caps results so one rule does not dominate, and can early-stop by limiting the
              number of methods scanned.
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
            <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
              <input
                type="checkbox"
                checked={batchUseInteractiveCaps}
                onChange={(event) => setBatchUseInteractiveCaps(event.target.checked)}
              />
              Use interactive caps (faster)
            </label>
            <form className="policy-llm-form" onSubmit={handleLlmSubmit}>
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

      {evaluation && (
        <div className="policy-results">
          <h2>Evaluation Result</h2>
          {evaluation.error ? (
            <div className="callout callout-error">
              <p>Error: {evaluation.error}</p>
              <button
                type="button"
                className="callout-action"
                onClick={() => baseEvalMutation.mutate(undefined)}
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
              {evaluationMeta?.truncated && (
                <div className="callout">
                  <p style={{ margin: 0 }}>
                    Interactive evaluation truncated results.
                    {typeof evaluationMeta.bundleCount === "number"
                      ? ` Scanned ${evaluationMeta.bundleCount} method(s).`
                      : ""}
                  </p>
                  {evaluationMeta.limits && (
                    <p className="muted" style={{ marginTop: "0.5rem" }}>
                      Limits:{" "}
                      <code>
                        max_bundles={String(evaluationMeta.limits.max_bundles ?? "—")}
                      </code>
                      {"  "}
                      <code>
                        max_total_violations=
                        {String(evaluationMeta.limits.max_total_violations ?? "—")}
                      </code>
                      {"  "}
                      <code>
                        max_per_violation_id=
                        {String(evaluationMeta.limits.max_per_violation_id ?? "—")}
                      </code>
                    </p>
                  )}
                </div>
              )}
              {hasViolations && (
                <div className="callout">
                  <p>
                    Fix available for{" "}
                    <strong>
                      {autoRemediableCount} / {evaluation.violations?.length ?? violationSummaries.length}
                    </strong>{" "}
                    violation(s).
                  </p>
                  <p>
                    Fix (Preview/Apply) is currently implemented for:{" "}
                    <code>ISO-A.10-WEAK-HASH</code>, <code>ISO-A.10-WEAK-CRYPTO</code>.
                  </p>
                  <label style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginTop: "0.75rem" }}>
                    <input
                      type="checkbox"
                      checked={showRemediableOnly}
                      onChange={(event) => setShowRemediableOnly(event.target.checked)}
                    />
                    Show only fixable violations
                  </label>
                </div>
              )}
              {hasViolations && violationSummaries.length > 0 && (
                <div className="violation-deck">
                  {displayedViolationSummaries.length === 0 ? (
                    <p className="muted">No fixable violations found.</p>
                  ) : (
                    displayedViolationSummaries.map((item, index) => {
                    const violationKey = `${item.violationId || "unknown"}::${
                      item.targetMethod || ""
                    }::${item.filePath || ""}`;
                    const remediationOutcome = remediationPreviews[violationKey];
                    const applyOutcome = remediationApplies[violationKey];
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
                    const isApplying = applyPending && activeApplyKey === violationKey;
                    const disableRemediationButtons = remediationPending || applyPending;
                    const reviewSaved = reviewSavedByKey[violationKey];
                    const reviewDraft = reviewDraftByKey[violationKey] ?? {
                      label: undefined,
                      notes: "",
                      includeGraphContext: true
                    };
                    const explanation = explanationsByKey[violationKey];
                    const isExplaining = explainPending && activeExplainKey === violationKey;
                    const isSavingReview = saveReviewPending && activeSaveReviewKey === violationKey;

                    const applyVerification = applyOutcome?.verification;
                    const applyCompilation = applyOutcome?.compilation;
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
                              <strong>{item.title}</strong>
                              {item.reason && item.reason !== item.title && (
                                <span className="violation-method">{item.reason}</span>
                              )}
                              {item.targetMethod && (
                                <span className="violation-method">{item.targetMethod}</span>
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
                              {reviewSaved && (
                                <span className="muted" style={{ fontWeight: 600 }}>
                                  Reviewed
                                </span>
                              )}
                              {item.autoRemediationSupported ? (
                                <>
                                  <button
                                    type="button"
                                    className="remediation-button"
                                    disabled={
                                      !item.violationId || disableRemediationButtons || isStarting
                                    }
                                    onClick={(event) =>
                                      handleRemediation(
                                        item.violationId,
                                        item.targetMethod,
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
                                        {remediationOutcome ? "Re-run Preview" : "Preview Fix (Virtual)"}
                                      </span>
                                    )}
                                  </button>
                                  <button
                                    type="button"
                                    className="remediation-button"
                                    disabled={
                                      !item.violationId || disableRemediationButtons || isApplying
                                    }
                                    onClick={(event) =>
                                      handleApply(
                                        item.violationId,
                                        item.targetMethod,
                                        item.filePath,
                                        violationKey,
                                        event
                                      )
                                    }
                                  >
                                    {isApplying ? (
                                      <>
                                        <span className="btn-spinner" aria-hidden="true" />
                                        <span>Applying…</span>
                                      </>
                                    ) : (
                                      <span>Run Apply+Verify (Dry-run)</span>
                                    )}
                                  </button>
                                </>
                              ) : (
                                <span className="muted">No fix available</span>
                              )}
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
                              <dd>{item.control ?? item.violationId ?? "—"}</dd>
                            </div>
                            <div>
                              <dt>Resource</dt>
                              <dd>
                                {item.filePath ? <code>{item.filePath}</code> : "—"}
                                {item.targetMethod && (
                                  <>
                                    <br />
                                    <code>{item.targetMethod}</code>
                                  </>
                                )}
                              </dd>
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
                                <h4>Review</h4>
                              </header>
                              <div style={{ display: "grid", gap: "0.75rem" }}>
                                <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                                  <input
                                    type="checkbox"
                                    checked={reviewDraft.includeGraphContext}
                                    onChange={(event) =>
                                      setReviewDraftByKey((prev) => ({
                                        ...prev,
                                        [violationKey]: {
                                          ...reviewDraft,
                                          includeGraphContext: event.target.checked
                                        }
                                      }))
                                    }
                                  />
                                  Include evidence context
                                </label>

                                <button
                                  type="button"
                                  disabled={isExplaining || explainPending}
                                  onClick={(event) =>
                                    handleExplainOne(
                                      item.raw,
                                      violationKey,
                                      reviewDraft.includeGraphContext,
                                      event
                                    )
                                  }
                                >
                                  {isExplaining ? (
                                    <>
                                      <span className="btn-spinner" aria-hidden="true" />
                                      <span>Explaining…</span>
                                    </>
                                  ) : (
                                    <span>Explain this violation</span>
                                  )}
                                </button>

                                {explanation?.explanation && (
                                  <div className="llm-text">
                                    <h5 style={{ margin: 0 }}>Explanation</h5>
                                    <div
                                      className="llm-text"
                                      dangerouslySetInnerHTML={{
                                        __html: toHtml(explanation.explanation)
                                      }}
                                    />
                                    {explanation.model && (
                                      <p className="muted" style={{ marginTop: "0.5rem" }}>
                                        Model: <code>{explanation.model}</code>
                                      </p>
                                    )}
                                  </div>
                                )}

                                <fieldset style={{ border: "1px solid rgba(0,0,0,0.1)", padding: "0.75rem" }}>
                                  <legend style={{ padding: "0 0.25rem" }}>Label</legend>
                                  <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                                    <input
                                      type="radio"
                                      name={`review-${violationKey}`}
                                      checked={reviewDraft.label === "TP"}
                                      onChange={() =>
                                        setReviewDraftByKey((prev) => ({
                                          ...prev,
                                          [violationKey]: { ...reviewDraft, label: "TP" }
                                        }))
                                      }
                                    />
                                    TP
                                  </label>
                                  <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                                    <input
                                      type="radio"
                                      name={`review-${violationKey}`}
                                      checked={reviewDraft.label === "FP"}
                                      onChange={() =>
                                        setReviewDraftByKey((prev) => ({
                                          ...prev,
                                          [violationKey]: { ...reviewDraft, label: "FP" }
                                        }))
                                      }
                                    />
                                    FP
                                  </label>
                                  <label style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                                    <input
                                      type="radio"
                                      name={`review-${violationKey}`}
                                      checked={reviewDraft.label === "UNCLEAR"}
                                      onChange={() =>
                                        setReviewDraftByKey((prev) => ({
                                          ...prev,
                                          [violationKey]: { ...reviewDraft, label: "UNCLEAR" }
                                        }))
                                      }
                                    />
                                    Unclear
                                  </label>
                                </fieldset>

                                <label style={{ display: "grid", gap: "0.25rem" }}>
                                  Notes (optional)
                                  <textarea
                                    rows={4}
                                    value={reviewDraft.notes}
                                    onChange={(event) =>
                                      setReviewDraftByKey((prev) => ({
                                        ...prev,
                                        [violationKey]: { ...reviewDraft, notes: event.target.value }
                                      }))
                                    }
                                  />
                                </label>

                                <button
                                  type="button"
                                  disabled={!reviewDraft.label || isSavingReview || saveReviewPending}
                                  onClick={(event) =>
                                    handleSaveReview(
                                      item.raw,
                                      violationKey,
                                      reviewDraft.label as PolicyReviewLabel,
                                      reviewDraft.notes,
                                      reviewDraft.includeGraphContext,
                                      remediationOutcome,
                                      applyOutcome,
                                      event
                                    )
                                  }
                                >
                                  {isSavingReview ? (
                                    <>
                                      <span className="btn-spinner" aria-hidden="true" />
                                      <span>Saving…</span>
                                    </>
                                  ) : (
                                    <span>Save review</span>
                                  )}
                                </button>

                                {reviewSaved && (
                                  <div className="callout">
                                    <p className="muted" style={{ margin: 0 }}>
                                      Saved as <code>{reviewSaved.reviewId}</code>
                                      {reviewSaved.storePath ? (
                                        <>
                                          {" "}
                                          to <code>{reviewSaved.storePath}</code>
                                        </>
                                      ) : null}
                                    </p>
                                    {reviewSaved.scrubWarnings &&
                                      reviewSaved.scrubWarnings.length > 0 && (
                                        <details style={{ marginTop: "0.5rem" }}>
                                          <summary>Scrub warnings</summary>
                                          <CodeHighlight
                                            code={JSON.stringify(reviewSaved.scrubWarnings, null, 2)}
                                            language="json"
                                          />
                                        </details>
                                      )}
                                  </div>
                                )}
                              </div>
                            </section>
                            <section>
                              <header>
                                <h4>Remediation</h4>
                              </header>
                              {!item.autoRemediationSupported ? (
                                <p className="callout callout-error">
                                  No automatic remediation for this rule yet.
                                </p>
                              ) : !item.violationId ? (
                                <p className="muted">
                                  This violation is missing an identifier required for remediation.
                                </p>
                              ) : (
                                <>
                                  <p className="remediation-note">Preview does not modify files.</p>

                                  <h5>Preview Fix (Virtual)</h5>
                                  {!remediationOutcome ? (
                                    <p className="muted">
                                      Run “Preview Fix (Virtual)” to propose and validate a patch in memory.
                                    </p>
                                  ) : (
                                    <div className="remediation-panel">
                                      <p className="remediation-status">
                                        {remediationOutcome.opa_status
                                          ? `OPA: ${remediationOutcome.opa_status}`
                                          : remediationOutcome.status}
                                        {remediationOutcome.rule_id ? ` (${remediationOutcome.rule_id})` : ""}
                                      </p>
                                      {remediationOutcome.explanation && (
                                        <p className="remediation-note">{remediationOutcome.explanation}</p>
                                      )}
                                      {typeof remediationOutcome.error === "string" &&
                                        formatAutoRemediationError(remediationOutcome.error) && (
                                          <p className="callout callout-error">
                                            {formatAutoRemediationError(remediationOutcome.error)}
                                          </p>
                                        )}
                                      {targetRuleStatus && (
                                        <p className="remediation-note">Target rule status: {targetRuleStatus}</p>
                                      )}
                                      {overallStatus && (
                                        <p className="remediation-note">Overall status: {overallStatus}</p>
                                      )}
                                      {typeof newViolations === "number" && (
                                        <p className="remediation-note">New violations: {newViolations}</p>
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
                                        <CodeHighlight code={remediationOutcome.diff} language="text" />
                                      )}
                                    </div>
                                  )}

                                  <h5>Apply + Verify (Dry-run)</h5>
                                  {!applyOutcome ? (
                                    <p className="muted">
                                      Run “Apply+Verify (Dry-run)” to exercise the backend apply loop (no changes are
                                      persisted).
                                    </p>
                                  ) : (
                                    <div className="remediation-panel">
                                      <p className="remediation-status">Status: {applyOutcome.status}</p>
                                      {typeof applyOutcome.error === "string" &&
                                        formatAutoRemediationError(applyOutcome.error) && (
                                          <p className="callout callout-error">
                                            {formatAutoRemediationError(applyOutcome.error)}
                                          </p>
                                        )}
                                      {applyVerification?.error && (
                                        <p className="callout callout-error">
                                          Verification error: {applyVerification.error}
                                        </p>
                                      )}
                                      {applyVerification?.target_rule_status && (
                                        <p className="remediation-note">
                                          Target rule status: {applyVerification.target_rule_status}
                                        </p>
                                      )}
                                      {applyVerification?.overall_status && (
                                        <p className="remediation-note">
                                          Overall status: {applyVerification.overall_status}
                                        </p>
                                      )}
                                      {(typeof applyBaselineCount === "number" ||
                                        typeof applyAfterCount === "number") && (
                                        <p className="remediation-note">
                                          Violations: {applyBaselineCount ?? "—"} → {applyAfterCount ?? "—"}
                                        </p>
                                      )}
                                      {typeof applyNewCount === "number" && (
                                        <p className="remediation-note">New violations: {applyNewCount}</p>
                                      )}
                                      {typeof applyRemainingCount === "number" && (
                                        <p className="remediation-note">
                                          Remaining violations: {applyRemainingCount}
                                        </p>
                                      )}
                                      {applyCompilation && (
                                        <>
                                          <p className="remediation-note">
                                            Compilation:{" "}
                                            {applyCompilation.attempted
                                              ? applyCompilation.success
                                                ? "success"
                                                : "failed"
                                              : "skipped"}
                                          </p>
                                          {applyCompilation.output_snippet ? (
                                            <CodeHighlight
                                              code={applyCompilation.output_snippet}
                                              language="text"
                                            />
                                          ) : applyCompilation.skipped_reason ? (
                                            <p className="muted">{applyCompilation.skipped_reason}</p>
                                          ) : null}
                                        </>
                                      )}
                                      {applyOutcome.updated_source_code && (
                                        <CodeHighlight code={applyOutcome.updated_source_code} language="java" />
                                      )}
                                      {applyOutcome.diff && (
                                        <CodeHighlight code={applyOutcome.diff} language="text" />
                                      )}
                                    </div>
                                  )}
                                </>
                              )}
                            </section>
                          </div>
                        </div>
                      </details>
                    );
                  })
                  )}
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
              <li
                key={
                  (typeof control.id === "string" && control.id.trim())
                    ? control.id
                    : `${String(control.control ?? "control")}:${String(control.title ?? "")}:${index}`
                }
              >
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
