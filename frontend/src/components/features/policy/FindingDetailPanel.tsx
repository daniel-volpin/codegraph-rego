import { useState } from "react";
import { AlertTriangle, CheckCircle2, ChevronDown, Copy, Loader2, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import CodeHighlight from "../../ui/CodeHighlight";
import ConfidenceBand from "./ConfidenceBand";
import { copyTextToClipboard } from "../../../lib/utils";
import type { PolicyExplanationStructured } from "../../../lib/types";
import {
  deriveConfidenceSurface,
  type ViolationRow,
  artifactStatusLabel,
  artifactStatusVariant,
  formatCitationDisplay,
  remediationBadgeLabel,
  remediationBadgeVariant,
  severityVariant,
} from "./policyUtils";
import {
  useApplyMutation,
  useApplyResult,
  useExplainMutation,
  useExplainResult,
  usePendingAction,
  usePreviewMutation,
  usePreviewResult,
} from "../../../hooks/usePolicyArtifacts";

interface FindingDetailPanelProps {
  selectedFinding: ViolationRow | null;
}

interface ImmediateEvidence {
  citation: string;
  callers: string[];
  neighbors: string[];
}

const renderStructuredExplanation = (payload: PolicyExplanationStructured) => {
  const citation = formatCitationDisplay(payload.citation);
  return (
    <div className="space-y-3 rounded-md border border-indigo-200 bg-indigo-50 p-4 text-sm text-indigo-950">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Citation</p>
        <p className="mt-1 break-words font-mono text-xs text-indigo-900" title={citation.full}>
          {citation.display}
        </p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Why</p>
        <p className="mt-1 break-words">{payload.why}</p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-600">Fix</p>
        <p className="mt-1 break-words">{payload.fix}</p>
      </div>
    </div>
  );
};

const buildImmediateEvidence = (finding: ViolationRow): ImmediateEvidence => {
  const raw = finding.raw as Record<string, unknown>;

  const evidence =
    raw.evidence && typeof raw.evidence === "object" && raw.evidence !== null
      ? (raw.evidence as Record<string, unknown>)
      : null;
  const graphContext =
    evidence?.graph_context &&
    typeof evidence.graph_context === "object" &&
    evidence.graph_context !== null
      ? (evidence.graph_context as Record<string, unknown>)
      : null;

  const callers = Array.isArray(graphContext?.callers)
    ? graphContext.callers.filter((item): item is string => typeof item === "string")
    : [];
  const neighbors = Array.isArray(evidence?.vector_context)
    ? evidence.vector_context.filter((item): item is string => typeof item === "string")
    : [];

  return { citation: finding.citation, callers, neighbors };
};

const ArtifactSkeleton = ({ lines = 3 }: { lines?: number }) => (
  <div className="space-y-2" aria-hidden="true">
    {Array.from({ length: lines }).map((_, index) => (
      <div
        key={index}
        className={`h-3 animate-pulse rounded bg-slate-100 ${
          index === lines - 1 ? "w-2/3" : "w-full"
        }`}
      />
    ))}
  </div>
);

const remediationArtifactStatus = (status: string | null | undefined): "idle" | "ready" | "error" => {
  if (!status) return "idle";
  return status === "OK" ? "ready" : "error";
};

const FindingDetailPanel = ({ selectedFinding }: FindingDetailPanelProps) => {
  const findingId = selectedFinding?.id ?? null;
  const explainResult = useExplainResult(findingId);
  const previewResult = usePreviewResult(findingId);
  const applyResult = useApplyResult(findingId);
  const pendingAction = usePendingAction(findingId);

  const explainMutation = useExplainMutation();
  const previewMutation = usePreviewMutation();
  const applyMutation = useApplyMutation();
  const [showVerificationDetails, setShowVerificationDetails] = useState(false);

  const explainStatus: "idle" | "running" | "ready" | "error" =
    pendingAction === "explain" ? "running"
    : remediationArtifactStatus(explainResult?.status);

  const previewStatus: "idle" | "running" | "ready" | "error" =
    pendingAction === "preview" ? "running"
    : remediationArtifactStatus(previewResult?.status);

  const verifyStatus: "idle" | "running" | "ready" | "error" =
    pendingAction === "apply" ? "running"
    : remediationArtifactStatus(applyResult?.status);

  const confidenceSurface = deriveConfidenceSurface(
    applyResult?.confidence ?? previewResult?.confidence ?? null,
  );
  const immediateEvidence = selectedFinding ? buildImmediateEvidence(selectedFinding) : null;
  const verificationOutcome = applyResult?.verification?.overall_status ?? null;
  const verificationPrefix =
    verificationOutcome === "PASS"
      ? "Verification passed."
      : verificationOutcome
        ? `Verification completed with status ${verificationOutcome}.`
        : "Verification completed.";
  const previewFailed = previewResult?.status && previewResult.status !== "OK";
  const applyFailed = applyResult?.status && applyResult.status !== "OK";
  const explainFailed = explainResult?.status && explainResult.status !== "OK";
  const remediationUnavailable =
    selectedFinding?.remediation.support_tier === "manual" ||
    selectedFinding?.remediation.preview_available === false ||
    selectedFinding?.remediation.verify_available === false;
  const statusMessage =
    applyResult?.status === "OK"
      ? `${verificationPrefix} ${applyResult.verification?.new_violations?.length ?? 0} new violations.`
      : applyFailed && applyResult?.error
        ? `Verification issue. ${applyResult.error}`
        : previewResult?.status === "OK"
          ? "Preview ready."
          : previewFailed && previewResult?.error
            ? `Preview issue. ${previewResult.error}`
            : explainResult?.status === "OK"
              ? "Explanation ready."
              : explainFailed && explainResult?.error
                ? `Explanation issue. ${explainResult.error}`
                : "";
  const applySucceeded = applyResult?.status === "OK";

  return (
    <Card
      className="min-w-0 p-5 2xl:sticky 2xl:top-24 2xl:max-h-[calc(100vh-11rem)] 2xl:overflow-auto"
      data-testid="finding-dossier"
    >
      <div role="status" aria-live="polite" className="sr-only">
        {statusMessage}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <p className="text-sm font-semibold text-slate-900">Case dossier</p>
          <p className="text-xs text-slate-500">
            One selected finding with end-to-end evidence: explanation, suggested fix, and dry-run verification.
          </p>
        </div>
        {selectedFinding && (
          <div className="flex items-center gap-2">
            <Badge variant={severityVariant(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
            <Badge variant={remediationBadgeVariant(selectedFinding.remediation)}>
              {remediationBadgeLabel(selectedFinding.remediation)}
            </Badge>
          </div>
        )}
      </div>

      {!selectedFinding ? (
        <div className="py-6 text-sm text-slate-600">
          Run a policy scan and select a finding to open a case dossier.
        </div>
      ) : (
        <div className="space-y-4 pt-4">
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">Control {selectedFinding.controlLabel}</Badge>
              <Badge variant="secondary">{selectedFinding.cweLabel}</Badge>
              <Badge variant={severityVariant(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
            </div>
            <p className="mt-3 truncate font-mono text-sm text-slate-900" title={selectedFinding.targetMethod}>
              {selectedFinding.targetMethod}
            </p>
            <p className="mt-1 truncate font-mono text-xs text-slate-500" title={selectedFinding.filePath}>
              {selectedFinding.filePath}
            </p>
            <p className="mt-1 break-words font-mono text-xs text-slate-500" title={selectedFinding.citation}>
              {formatCitationDisplay(selectedFinding.citation).display}
            </p>
            <p className="mt-2 text-sm text-slate-700">{selectedFinding.reason}</p>
          </div>

          <div className="grid gap-3 md:grid-cols-3 2xl:grid-cols-1">
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">1. Explain</p>
                <Badge variant={artifactStatusVariant(explainStatus)}>{artifactStatusLabel(explainStatus)}</Badge>
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">2. Preview</p>
                <Badge variant={artifactStatusVariant(previewStatus)}>{artifactStatusLabel(previewStatus)}</Badge>
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 p-3">
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">3. Verify</p>
                <Badge variant={artifactStatusVariant(verifyStatus)}>{artifactStatusLabel(verifyStatus)}</Badge>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={pendingAction !== undefined}
              onClick={() => explainMutation.mutate(selectedFinding)}
            >
              {pendingAction === "explain" ? (
                <>
                  <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Explaining…
                </>
              ) : (
                <>
                  <Sparkles aria-hidden="true" className="mr-1 h-4 w-4" /> Explain finding
                </>
              )}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              disabled={pendingAction !== undefined || !selectedFinding.remediation.preview_available}
              onClick={() => previewMutation.mutate(selectedFinding)}
            >
              {pendingAction === "preview" ? (
                <>
                  <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Previewing…
                </>
              ) : (
                <>Preview suggested fix</>
              )}
            </Button>
            <Button
              variant="default"
              size="sm"
              disabled={pendingAction !== undefined || !selectedFinding.remediation.verify_available}
              onClick={() => applyMutation.mutate(selectedFinding)}
            >
              {pendingAction === "apply" ? (
                <>
                  <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Verifying…
                </>
              ) : (
                <>Verify fix (dry run)</>
              )}
            </Button>
          </div>

          {remediationUnavailable && (
            <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
              <p className="font-medium">Automatic remediation is unavailable for this finding.</p>
              <p className="mt-1 break-words">
                {selectedFinding.remediation.reason_code}: {selectedFinding.remediation.rationale}
              </p>
            </div>
          )}

          <ConfidenceBand confidence={confidenceSurface} />

          <div className="space-y-4">
            <div
              className="min-h-[18rem] space-y-3 rounded-lg border border-slate-200 p-4"
              data-testid="explanation-artifact"
            >
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Explanation artifact</p>
              {(pendingAction === "explain" || !explainResult) && immediateEvidence && (
                <details
                  aria-label="Evidence and source context"
                  className="rounded-md border border-slate-200 bg-slate-50 p-4"
                >
                  <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-slate-600">
                    Immediate evidence
                    <span className="ml-2 normal-case tracking-normal text-slate-500">
                      Evidence and source context
                    </span>
                  </summary>
                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Citation</p>
                      <p className="mt-1 break-words font-mono text-xs text-slate-800">
                        {formatCitationDisplay(immediateEvidence.citation).display}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Target method</p>
                      <p className="mt-1 break-words font-mono text-xs text-slate-800">
                        {selectedFinding.targetMethod}
                      </p>
                    </div>
                  </div>
                  {(immediateEvidence.callers.length > 0 || immediateEvidence.neighbors.length > 0) && (
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Callers</p>
                        <p className="mt-1 text-sm text-slate-700">
                          {immediateEvidence.callers.length > 0
                            ? immediateEvidence.callers.slice(0, 3).join(", ")
                            : "No caller summary available."}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Neighbors</p>
                        <p className="mt-1 text-sm text-slate-700">
                          {immediateEvidence.neighbors.length > 0
                            ? immediateEvidence.neighbors.slice(0, 3).join(", ")
                            : "No semantic neighbors available."}
                        </p>
                      </div>
                    </div>
                  )}
                </details>
              )}
              {explainFailed && explainResult?.error && (
                <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                  {explainResult.error}
                </div>
              )}
              {explainResult?.status === "OK" && explainResult.explanation_structured &&
                renderStructuredExplanation(explainResult.explanation_structured)}
              {explainResult?.status === "OK" &&
                !explainResult.explanation_structured &&
                explainResult.explanation && (
                  <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50 p-4 text-indigo-900 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                    <Markdown>{explainResult.explanation}</Markdown>
                  </div>
                )}
              {pendingAction === "explain" && <ArtifactSkeleton lines={4} />}
              {!explainResult && pendingAction !== "explain" && (
                <p className="text-sm text-slate-500">No explanation generated yet.</p>
              )}
            </div>

            <div
              className="min-h-[20rem] space-y-3 rounded-lg border border-slate-200 p-4"
              data-testid={`verify-summary-${findingId ?? "none"}`}
            >
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Remediation artifacts</p>
              {previewResult?.error && (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                  <strong>Preview error:</strong> {previewResult.error}
                </div>
              )}
              {previewResult?.diff && (
                <div className="rounded-lg border border-slate-200">
                  <div className="border-b border-slate-200 px-3 py-2">
                    <span className="text-xs font-semibold uppercase text-slate-500">Proposed diff</span>
                  </div>
                  <pre className="overflow-auto whitespace-pre-wrap break-words bg-white p-3 text-xs">
                    {previewResult.diff}
                  </pre>
                </div>
              )}
              {!previewResult?.diff && previewResult?.explanation && (
                <div className="prose prose-sm max-w-none rounded-md border border-emerald-200 bg-emerald-50 p-4 text-emerald-900 break-words">
                  <strong>Preview:</strong>
                  <Markdown>{previewResult.explanation}</Markdown>
                </div>
              )}
              {pendingAction === "preview" && <ArtifactSkeleton lines={5} />}
              {!previewResult && pendingAction !== "preview" && (
                <p className="text-sm text-slate-500">No preview generated yet.</p>
              )}

              {applyResult && (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                  <div className={`flex items-center gap-2 ${applySucceeded ? "text-slate-900" : "text-rose-900"}`}>
                    {applySucceeded ? (
                      <CheckCircle2 aria-hidden="true" className="h-4 w-4" />
                    ) : (
                      <AlertTriangle aria-hidden="true" className="h-4 w-4" />
                    )}
                    <p className="font-medium">{applySucceeded ? "Verification summary" : "Verification issue"}</p>
                  </div>
                  {!applySucceeded && applyResult.error && (
                    <p className="mt-2 break-words text-rose-700">{applyResult.error}</p>
                  )}
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Badge variant="secondary">
                      Overall {applyResult.verification?.overall_status ?? "—"}
                    </Badge>
                    <Badge variant="secondary">
                      Rule {applyResult.verification?.target_rule_status ?? "—"}
                    </Badge>
                    <Badge
                      variant={
                        applyResult.compilation?.success
                          ? "success"
                          : applyResult.compilation?.attempted
                            ? "destructive"
                            : "secondary"
                      }
                    >
                      Compilation {applyResult.compilation?.success
                        ? "success"
                        : applyResult.compilation?.attempted
                          ? "failed"
                          : "not attempted"}
                    </Badge>
                  </div>

                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="mt-3 px-0"
                    onClick={() => setShowVerificationDetails((current) => !current)}
                  >
                    <ChevronDown
                      aria-hidden="true"
                      className={`mr-1 h-4 w-4 transition-transform ${
                        showVerificationDetails ? "rotate-180" : ""
                      }`}
                    />
                    {showVerificationDetails ? "Hide details" : "View details"}
                  </Button>

                  {showVerificationDetails && (
                    <div className="mt-2 grid gap-2 md:grid-cols-2 2xl:grid-cols-1">
                      <p>
                        Remaining violations:{" "}
                        <span className="font-medium">
                          {applyResult.verification?.remaining_violations?.length ?? 0}
                        </span>
                      </p>
                      <p>
                        New violations:{" "}
                        <span className="font-medium">
                          {applyResult.verification?.new_violations?.length ?? 0}
                        </span>
                      </p>
                      <p>
                        Decision:{" "}
                        <span className="font-medium">{applyResult.generation?.decision ?? "—"}</span>
                      </p>
                      {applyResult.generation?.reason && (
                        <p>Reason: <span className="font-medium">{applyResult.generation.reason}</span></p>
                      )}
                      {applyResult.error && (
                        <p className="text-rose-700">Error: {applyResult.error}</p>
                      )}
                    </div>
                  )}
                </div>
              )}

              {pendingAction === "apply" && <ArtifactSkeleton lines={5} />}
            </div>
          </div>

          <div className="rounded-lg border border-slate-200">
            <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
              <span className="text-xs font-semibold uppercase text-slate-500">Evidence snippet</span>
              <Button
                variant="ghost"
                size="sm"
                aria-label={`Copy snippet for ${selectedFinding.targetMethod}`}
                onClick={async () => {
                  const ok = await copyTextToClipboard(selectedFinding.snippet || "");
                  if (ok) toast.success("Code copied.");
                  else toast.error("Clipboard unavailable. Select and copy manually.");
                }}
              >
                <Copy aria-hidden="true" className="mr-1 h-4 w-4" /> Copy
              </Button>
            </div>
            <CodeHighlight
              code={selectedFinding.snippet || "// snippet unavailable"}
              language="java"
              maxHeight={460}
            />
          </div>
        </div>
      )}
    </Card>
  );
};

export default FindingDetailPanel;
