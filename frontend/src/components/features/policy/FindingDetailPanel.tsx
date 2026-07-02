import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Copy,
  FileCode,
  Info,
  Loader2,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import CodeHighlight from "../../ui/CodeHighlight";
import ConfidenceBand from "./ConfidenceBand";
import { RemediationConfirmDialog } from "./RemediationConfirmDialog";
import { copyTextToClipboard } from "../../../lib/utils";
import type { PolicyExplanationStructured } from "../../../lib/types";
import {
  artifactStatusLabel,
  artifactStatusVariant,
  categorizeApplyOutcome,
  deriveConfidenceSurface,
  formatCitationDisplay,
  remediationBadgeLabel,
  remediationBadgeVariant,
  severityVariant,
  type ViolationRow,
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
    <div className="space-y-3 rounded-lg border border-indigo-200 bg-indigo-50/70 p-4 text-sm text-indigo-950">
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-700">Citation Grounding</p>
        <p className="mt-1 break-all font-mono text-xs font-semibold text-indigo-900" title={citation.full}>
          {citation.display}
        </p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-700">Why Finding Matters</p>
        <p className="mt-1 break-words leading-relaxed">{payload.why}</p>
      </div>
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide text-indigo-700">Recommended Remediation</p>
        <p className="mt-1 break-words leading-relaxed">{payload.fix}</p>
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
  <div className="space-y-2 py-1" aria-hidden="true">
    {Array.from({ length: lines }).map((_, index) => (
      <div
        key={index}
        className={`h-3 animate-pulse rounded bg-slate-200/80 ${
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

  const [showConfirmDialog, setShowConfirmDialog] = useState(false);
  const [showVerificationDetails, setShowVerificationDetails] = useState(false);
  const [showCompilationLogs, setShowCompilationLogs] = useState(false);

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

  const previewFailed = previewResult?.status && previewResult.status !== "OK";
  const applyFailed = applyResult?.status && applyResult.status !== "OK";
  const explainFailed = explainResult?.status && explainResult.status !== "OK";

  const remediationUnavailable =
    selectedFinding?.remediation.support_tier === "manual" ||
    selectedFinding?.remediation.preview_available === false ||
    selectedFinding?.remediation.verify_available === false;

  const categorizedOutcome = applyResult ? categorizeApplyOutcome(applyResult) : null;

  const statusMessage =
    applyResult?.status === "OK"
      ? `Verification complete: ${categorizedOutcome?.title}`
      : applyFailed && applyResult?.error
        ? `Verification issue: ${applyResult.error}`
        : previewResult?.status === "OK"
          ? "Preview ready."
          : previewFailed && previewResult?.error
            ? `Preview issue: ${previewResult.error}`
            : explainResult?.status === "OK"
              ? "Explanation ready."
              : explainFailed && explainResult?.error
                ? `Explanation issue: ${explainResult.error}`
                : "";

  return (
    <>
      <Card
        className="min-w-0 p-5 2xl:sticky 2xl:top-24 2xl:max-h-[calc(100vh-11rem)] 2xl:overflow-auto"
        data-testid="finding-dossier"
      >
        <div role="status" aria-live="polite" className="sr-only">
          {statusMessage}
        </div>

        {/* Level 1 Header: Dossier & Authoritative Policy Violation */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck aria-hidden="true" className="h-4 w-4 text-indigo-600" />
              <p className="text-sm font-semibold text-slate-900">Case Dossier</p>
            </div>
            <p className="mt-0.5 text-xs text-slate-500">
              Selected finding analysis with evidence hierarchy, explanation, preview, and dry-run re-verification.
            </p>
          </div>
          {selectedFinding && (
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={severityVariant(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
              <Badge variant={remediationBadgeVariant(selectedFinding.remediation)}>
                {remediationBadgeLabel(selectedFinding.remediation)}
              </Badge>
            </div>
          )}
        </div>

        {!selectedFinding ? (
          <div className="py-8 text-center text-sm text-slate-500">
            Run a policy scan and select a finding to open a case dossier.
          </div>
        ) : (
          <div className="space-y-5 pt-4">
            {/* 1. Authoritative Policy Violation Box */}
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                  1. Policy Finding (Authoritative OPA Rule)
                </span>
                <span className="font-mono text-xs font-semibold text-slate-800">{selectedFinding.ruleId}</span>
              </div>

              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary">Control {selectedFinding.controlLabel}</Badge>
                <Badge variant="secondary">{selectedFinding.cweLabel}</Badge>
                <Badge variant={severityVariant(selectedFinding.severity)}>{selectedFinding.severity}</Badge>
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Target Method & Path</p>
                <p className="mt-0.5 break-all font-mono text-sm font-semibold text-slate-900" title={selectedFinding.targetMethod}>
                  {selectedFinding.targetMethod}
                </p>
                <p className="mt-0.5 break-all font-mono text-xs text-slate-600" title={selectedFinding.filePath}>
                  {selectedFinding.filePath}
                </p>
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Violation Reason</p>
                <p className="mt-1 text-sm text-slate-800 leading-relaxed">{selectedFinding.reason}</p>
              </div>
            </div>

            {/* Pipeline Step Summary Cards */}
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

            {/* Action Toolbar */}
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
                onClick={() => setShowConfirmDialog(true)}
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
                <p className="font-semibold flex items-center gap-1.5">
                  <Info aria-hidden="true" className="h-4 w-4 shrink-0 text-amber-700" />
                  Automatic remediation unavailable for this category
                </p>
                <p className="mt-1 break-words text-xs text-amber-800">
                  {selectedFinding.remediation.reason_code}: {selectedFinding.remediation.rationale}
                </p>
              </div>
            )}

            {/* Confidence Surface */}
            <ConfidenceBand confidence={confidenceSurface} />

            {/* 2. Source Evidence & Citation Section */}
            <div className="space-y-4">
              <div className="rounded-lg border border-slate-200 p-4 space-y-3 bg-white">
                <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                    2. Source Evidence & Graph Grounding
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs"
                    aria-label={`Copy citation for ${selectedFinding.targetMethod}`}
                    onClick={async () => {
                      const ok = await copyTextToClipboard(selectedFinding.citation);
                      if (ok) toast.success("Citation copied.");
                      else toast.error("Clipboard unavailable.");
                    }}
                  >
                    <Copy aria-hidden="true" className="mr-1 h-3.5 w-3.5" /> Copy citation
                  </Button>
                </div>

                {immediateEvidence && (
                  <details
                    aria-label="Evidence and source context"
                    open
                    className="rounded-md border border-slate-200 bg-slate-50 p-3"
                  >
                    <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-slate-700">
                      Evidence & Source Context
                    </summary>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Citation</p>
                        <p className="mt-1 break-all font-mono text-xs text-slate-900 font-medium">
                          {formatCitationDisplay(immediateEvidence.citation).display}
                        </p>
                      </div>
                      <div>
                        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Target Method</p>
                        <p className="mt-1 break-all font-mono text-xs text-slate-900 font-medium">
                          {selectedFinding.targetMethod}
                        </p>
                      </div>
                    </div>
                    {(immediateEvidence.callers.length > 0 || immediateEvidence.neighbors.length > 0) && (
                      <div className="mt-3 grid gap-3 md:grid-cols-2">
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Callers</p>
                          <p className="mt-1 text-xs text-slate-700 break-all font-mono">
                            {immediateEvidence.callers.length > 0
                              ? immediateEvidence.callers.slice(0, 3).join(", ")
                              : "No caller summary available."}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Neighbors</p>
                          <p className="mt-1 text-xs text-slate-700 break-all font-mono">
                            {immediateEvidence.neighbors.length > 0
                              ? immediateEvidence.neighbors.slice(0, 3).join(", ")
                              : "No semantic neighbors available."}
                          </p>
                        </div>
                      </div>
                    )}
                  </details>
                )}

                {/* Evidence Code Snippet */}
                <div className="rounded-lg border border-slate-200">
                  <div className="flex items-center justify-between border-b border-slate-200 px-3 py-1.5 bg-slate-50">
                    <span className="text-xs font-semibold uppercase text-slate-500">Evidence snippet</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-[11px]"
                      aria-label={`Copy snippet for ${selectedFinding.targetMethod}`}
                      onClick={async () => {
                        const ok = await copyTextToClipboard(selectedFinding.snippet || "");
                        if (ok) toast.success("Code copied.");
                        else toast.error("Clipboard unavailable.");
                      }}
                    >
                      <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy
                    </Button>
                  </div>
                  <CodeHighlight
                    code={selectedFinding.snippet || "// snippet unavailable"}
                    language="java"
                    maxHeight={460}
                  />
                </div>
              </div>

              {/* 3. Generated LLM Explanation Artifact Section */}
              <div
                className="min-h-[14rem] space-y-3 rounded-lg border border-slate-200 p-4 bg-white"
                data-testid="explanation-artifact"
              >
                <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                      3. Generated LLM Explanation
                    </span>
                    <Badge variant="secondary" className="text-[10px]">AI Analysis (Non-Authoritative)</Badge>
                  </div>
                  {explainResult?.model && (
                    <span className="font-mono text-xs text-slate-500">
                      Model: {explainResult.model}
                    </span>
                  )}
                </div>

                {explainFailed && explainResult?.error && (
                  <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                    <p className="font-semibold flex items-center gap-1.5 text-rose-800">
                      <AlertTriangle aria-hidden="true" className="h-4 w-4 shrink-0" />
                      Explanation Generation Issue
                    </p>
                    <p className="mt-1 break-words text-xs">{explainResult.error}</p>
                  </div>
                )}

                {explainResult?.status === "OK" && explainResult.explanation_structured && (
                  <div className="space-y-2">
                    <div className="flex justify-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-xs"
                        onClick={async () => {
                          const text = `Citation: ${explainResult.explanation_structured?.citation}\nWhy: ${explainResult.explanation_structured?.why}\nFix: ${explainResult.explanation_structured?.fix}`;
                          const ok = await copyTextToClipboard(text);
                          if (ok) toast.success("Explanation text copied.");
                        }}
                      >
                        <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy explanation
                      </Button>
                    </div>
                    {renderStructuredExplanation(explainResult.explanation_structured)}
                  </div>
                )}

                {explainResult?.status === "OK" &&
                  !explainResult.explanation_structured &&
                  explainResult.explanation && (
                    <div className="space-y-2">
                      <div className="flex justify-end">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-xs"
                          onClick={async () => {
                            const ok = await copyTextToClipboard(explainResult.explanation || "");
                            if (ok) toast.success("Explanation markdown copied.");
                          }}
                        >
                          <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy
                        </Button>
                      </div>
                      <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50/70 p-4 text-indigo-950 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                        <Markdown>{explainResult.explanation}</Markdown>
                      </div>
                    </div>
                  )}

                {pendingAction === "explain" && <ArtifactSkeleton lines={4} />}
                {!explainResult && pendingAction !== "explain" && (
                  <p className="text-sm text-slate-500">
                    No explanation generated yet. Click &quot;Explain finding&quot; to request grounded analysis.
                  </p>
                )}
              </div>

              {/* 4. Bounded Remediation Artifacts Section */}
              <div
                className="min-h-[16rem] space-y-3 rounded-lg border border-slate-200 p-4 bg-white"
                data-testid={`verify-summary-${findingId ?? "none"}`}
              >
                <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                  <span className="text-xs font-semibold uppercase tracking-wide text-slate-600">
                    4. Remediation & Virtual Verification
                  </span>
                  <Badge variant="secondary" className="text-[10px]">Dry-Run Execution</Badge>
                </div>

                {/* Read-Only Fix Preview */}
                {previewResult?.error && (
                  <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                    <p className="font-semibold flex items-center gap-1.5 text-amber-800">
                      <AlertTriangle aria-hidden="true" className="h-4 w-4 shrink-0" />
                      Preview Issue
                    </p>
                    <p className="mt-1 break-words text-xs">{previewResult.error}</p>
                  </div>
                )}

                {previewResult?.diff && (
                  <div className="rounded-lg border border-slate-200 space-y-1">
                    <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2 bg-slate-50">
                      <div className="flex items-center gap-2">
                        <FileCode aria-hidden="true" className="h-4 w-4 text-indigo-600" />
                        <span className="text-xs font-semibold uppercase text-slate-700">
                          Read-Only Virtual Fix Preview
                        </span>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-xs"
                        onClick={async () => {
                          const ok = await copyTextToClipboard(previewResult.diff || "");
                          if (ok) toast.success("Proposed diff copied.");
                        }}
                      >
                        <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy diff
                      </Button>
                    </div>
                    <div tabIndex={0} aria-label="Proposed diff content" className="overflow-auto max-h-72 p-3 bg-white font-mono text-xs">
                      <pre className="whitespace-pre-wrap break-words">{previewResult.diff}</pre>
                    </div>
                  </div>
                )}

                {!previewResult?.diff && previewResult?.explanation && (
                  <div className="prose prose-sm max-w-none rounded-md border border-emerald-200 bg-emerald-50/70 p-4 text-emerald-950 break-words">
                    <p className="font-semibold text-emerald-900">Preview Guidance:</p>
                    <Markdown>{previewResult.explanation}</Markdown>
                  </div>
                )}

                {pendingAction === "preview" && <ArtifactSkeleton lines={5} />}
                {!previewResult && pendingAction !== "preview" && (
                  <p className="text-sm text-slate-500">No preview generated yet. Click &quot;Preview suggested fix&quot; to inspect proposed changes.</p>
                )}

                {/* Dry-Run Re-Verification Outcome & Pipeline Breakdown */}
                {applyResult && categorizedOutcome && (
                  <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-800">
                    {/* Outcome Header Banner */}
                    <div className="flex items-start justify-between gap-3 border-b border-slate-200 pb-3">
                      <div className="flex items-center gap-2">
                        {categorizedOutcome.badgeVariant === "success" ? (
                          <CheckCircle2 aria-hidden="true" className="h-5 w-5 text-emerald-600 shrink-0" />
                        ) : (
                          <AlertTriangle aria-hidden="true" className="h-5 w-5 text-amber-600 shrink-0" />
                        )}
                        <div>
                          <p className="font-semibold text-slate-900">{categorizedOutcome.title}</p>
                          <p className="mt-0.5 text-xs text-slate-600">{categorizedOutcome.detailMessage}</p>
                        </div>
                      </div>
                      <Badge variant={categorizedOutcome.badgeVariant}>
                        {categorizedOutcome.badgeLabel}
                      </Badge>
                    </div>

                    {/* Post-Apply Stage Pipeline Visualization */}
                    <div className="space-y-2">
                      <p className="text-xs font-semibold uppercase tracking-wide text-slate-600">Re-Verification Stage Pipeline</p>
                      <div className="grid gap-2 sm:grid-cols-2 text-xs">
                        <div className="rounded-md border border-slate-200 bg-white p-2.5">
                          <span className="font-medium text-slate-500">1. Generation Decision:</span>{" "}
                          <span className="font-semibold text-slate-900">{applyResult.generation?.decision ?? "—"}</span>
                          {applyResult.generation?.reason && (
                            <p className="mt-1 text-slate-600 break-words">{applyResult.generation.reason}</p>
                          )}
                        </div>
                        <div className="rounded-md border border-slate-200 bg-white p-2.5">
                          <span className="font-medium text-slate-500">2. Virtual Edit:</span>{" "}
                          <span className="font-semibold text-slate-900">Applied (Dry Run)</span>
                        </div>
                        <div className="rounded-md border border-slate-200 bg-white p-2.5">
                          <span className="font-medium text-slate-500">3. Build Compilation:</span>{" "}
                          <span className={applyResult.compilation?.success ? "font-semibold text-emerald-700" : "font-semibold text-rose-700"}>
                            {applyResult.compilation?.success ? "PASS" : applyResult.compilation?.attempted ? "FAIL" : "Not attempted"}
                          </span>
                        </div>
                        <div className="rounded-md border border-slate-200 bg-white p-2.5">
                          <span className="font-medium text-slate-500">4. OPA Re-Verification:</span>{" "}
                          <span className={applyResult.verification?.overall_status === "PASS" ? "font-semibold text-emerald-700" : "font-semibold text-amber-700"}>
                            {applyResult.verification?.overall_status ?? "—"}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Expandable Technical Details & Compilation Log */}
                    <div className="pt-1">
                      <div className="flex flex-wrap items-center gap-3">
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="px-0 text-xs font-medium text-indigo-700 hover:text-indigo-900 hover:bg-transparent"
                          onClick={() => setShowVerificationDetails((current) => !current)}
                        >
                          <ChevronDown
                            aria-hidden="true"
                            className={`mr-1 h-3.5 w-3.5 transition-transform ${
                              showVerificationDetails ? "rotate-180" : ""
                            }`}
                          />
                          {showVerificationDetails ? "Hide metrics detail" : "View metrics detail"}
                        </Button>

                        {applyResult.compilation?.output_snippet && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="px-0 text-xs font-medium text-indigo-700 hover:text-indigo-900 hover:bg-transparent"
                            onClick={() => setShowCompilationLogs((current) => !current)}
                          >
                            <Terminal aria-hidden="true" className="mr-1 h-3.5 w-3.5" />
                            {showCompilationLogs ? "Hide compilation log" : "View compilation log"}
                          </Button>
                        )}
                      </div>

                      {showVerificationDetails && (
                        <div className="mt-3 grid gap-2 rounded-md border border-slate-200 bg-white p-3 text-xs md:grid-cols-2">
                          <p>Target Rule Status: <span className="font-medium">{applyResult.verification?.target_rule_status ?? "—"}</span></p>
                          <p>Remaining Violations: <span className="font-medium">{applyResult.verification?.remaining_violations?.length ?? 0}</span></p>
                          <p>New Violations Introduced: <span className="font-medium">{applyResult.verification?.new_violations?.length ?? 0}</span></p>
                          <p>Confidence Score: <span className="font-medium">{applyResult.confidence?.score != null ? `${Math.round(applyResult.confidence.score * 100)}%` : "—"}</span></p>
                        </div>
                      )}

                      {showCompilationLogs && applyResult.compilation?.output_snippet && (
                        <div className="mt-3 rounded-md border border-slate-200 bg-slate-900 text-slate-100 p-3 text-xs space-y-2">
                          <div className="flex items-center justify-between border-b border-slate-800 pb-1.5">
                            <span className="font-mono text-[11px] uppercase text-slate-400">Compiler Output Log</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-5 px-1.5 text-[10px] text-slate-300 hover:bg-slate-800 hover:text-white"
                              onClick={async () => {
                                const ok = await copyTextToClipboard(applyResult.compilation?.output_snippet || "");
                                if (ok) toast.success("Compilation output log copied.");
                              }}
                            >
                              <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy log
                            </Button>
                          </div>
                          <pre tabIndex={0} aria-label="Compiler output log" className="overflow-auto max-h-48 font-mono whitespace-pre-wrap break-all">{applyResult.compilation.output_snippet}</pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {pendingAction === "apply" && <ArtifactSkeleton lines={5} />}
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Accessible Confirmation Modal before Dry-Run Verification */}
      <RemediationConfirmDialog
        open={showConfirmDialog}
        onOpenChange={setShowConfirmDialog}
        onConfirm={() => {
          if (selectedFinding) {
            applyMutation.mutate(selectedFinding);
          }
        }}
        finding={selectedFinding}
        confidence={confidenceSurface}
        isSubmitting={pendingAction === "apply"}
      />
    </>
  );
};

export default FindingDetailPanel;
