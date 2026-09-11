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
    <div className="space-y-3 rounded-lg border border-sky-200 bg-sky-50/70 p-4 text-xs text-sky-950 dark:border-sky-900/60 dark:bg-sky-950/30 dark:text-sky-100">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400">Citation Grounding</p>
        <p className="mt-0.5 break-all font-mono text-xs font-semibold text-sky-900 dark:text-sky-200" title={citation.full}>
          {citation.display}
        </p>
      </div>
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400">Why Finding Matters</p>
        <p className="mt-0.5 break-words leading-relaxed text-xs">{payload.why}</p>
      </div>
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400">Recommended Remediation</p>
        <p className="mt-0.5 break-words leading-relaxed text-xs">{payload.fix}</p>
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
        className="min-w-0 p-5 2xl:sticky 2xl:top-24 2xl:max-h-[calc(100vh-11rem)] 2xl:overflow-auto shadow-xs border-zinc-200/80 dark:border-zinc-800"
        data-testid="finding-dossier"
      >
        <div role="status" aria-live="polite" className="sr-only">
          {statusMessage}
        </div>

        {/* Level 1 Header: Dossier & Authoritative Policy Violation */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200 pb-4 dark:border-zinc-800">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck aria-hidden="true" className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
              <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Case Dossier</p>
            </div>
            <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
              Selected finding analysis with evidence hierarchy, explanation, preview, and dry-run re-verification.
            </p>
          </div>
          {selectedFinding && (
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge variant={severityVariant(selectedFinding.severity)} className="text-[10px]">{selectedFinding.severity}</Badge>
              <Badge variant={remediationBadgeVariant(selectedFinding.remediation)} className="text-[10px]">
                {remediationBadgeLabel(selectedFinding.remediation)}
              </Badge>
            </div>
          )}
        </div>

        {!selectedFinding ? (
          <div className="py-8 text-center text-xs text-zinc-500 dark:text-zinc-400">
            Run a policy scan and select a finding to open a case dossier.
          </div>
        ) : (
          <div className="space-y-4 pt-4">
            {/* 1. Authoritative Policy Violation Box */}
            <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-4 space-y-3 dark:border-zinc-800 dark:bg-zinc-900/40">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  1. Policy Finding (Authoritative OPA Rule)
                </span>
                <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100">{selectedFinding.ruleId}</span>
              </div>

              <div className="flex flex-wrap gap-1.5">
                <Badge variant="secondary" className="text-[10px]">Control {selectedFinding.controlLabel}</Badge>
                <Badge variant="secondary" className="text-[10px]">{selectedFinding.cweLabel}</Badge>
                <Badge variant={severityVariant(selectedFinding.severity)} className="text-[10px]">{selectedFinding.severity}</Badge>
              </div>

              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target Method & Path</p>
                <p className="mt-0.5 break-all font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100" title={selectedFinding.targetMethod}>
                  {selectedFinding.targetMethod}
                </p>
                <p className="mt-0.5 break-all font-mono text-[11px] text-zinc-500 dark:text-zinc-400" title={selectedFinding.filePath}>
                  {selectedFinding.filePath}
                </p>
              </div>

              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Violation Reason</p>
                <p className="mt-1 text-xs text-zinc-700 leading-relaxed dark:text-zinc-300">{selectedFinding.reason}</p>
              </div>
            </div>

            {/* Pipeline Step Summary Cards */}
            <div className="grid gap-2.5 md:grid-cols-3 2xl:grid-cols-1">
              <div className="rounded-lg border border-zinc-200 p-2.5 bg-white dark:border-zinc-800 dark:bg-zinc-900">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">1. Explain</p>
                  <Badge variant={artifactStatusVariant(explainStatus)} className="text-[10px]">{artifactStatusLabel(explainStatus)}</Badge>
                </div>
              </div>
              <div className="rounded-lg border border-zinc-200 p-2.5 bg-white dark:border-zinc-800 dark:bg-zinc-900">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">2. Preview</p>
                  <Badge variant={artifactStatusVariant(previewStatus)} className="text-[10px]">{artifactStatusLabel(previewStatus)}</Badge>
                </div>
              </div>
              <div className="rounded-lg border border-zinc-200 p-2.5 bg-white dark:border-zinc-800 dark:bg-zinc-900">
                <div className="flex items-center justify-between gap-2">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">3. Verify</p>
                  <Badge variant={artifactStatusVariant(verifyStatus)} className="text-[10px]">{artifactStatusLabel(verifyStatus)}</Badge>
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
              <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200">
                <p className="font-semibold flex items-center gap-1.5">
                  <Info aria-hidden="true" className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                  Automatic remediation unavailable for this category
                </p>
                <p className="mt-1 break-words text-[11px] text-amber-800 dark:text-amber-300">
                  {selectedFinding.remediation.reason_code}: {selectedFinding.remediation.rationale}
                </p>
              </div>
            )}

            {/* Confidence Surface */}
            <ConfidenceBand confidence={confidenceSurface} />

            {/* 2. Source Evidence & Citation Section */}
            <div className="space-y-4">
              <div className="rounded-lg border border-zinc-200 p-4 space-y-3 bg-white dark:border-zinc-800 dark:bg-zinc-900">
                <div className="flex items-center justify-between border-b border-zinc-200 pb-2.5 dark:border-zinc-800">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    2. Source Evidence & Graph Grounding
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 text-xs"
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
                    className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3.5 dark:border-zinc-800 dark:bg-zinc-950/40"
                  >
                    <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                      Evidence & Source Context
                    </summary>
                    <div className="mt-3 grid gap-3 md:grid-cols-2">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Citation</p>
                        <p className="mt-0.5 break-all font-mono text-xs text-zinc-900 font-medium dark:text-zinc-100">
                          {formatCitationDisplay(immediateEvidence.citation).display}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target Method</p>
                        <p className="mt-0.5 break-all font-mono text-xs text-zinc-900 font-medium dark:text-zinc-100">
                          {selectedFinding.targetMethod}
                        </p>
                      </div>
                    </div>
                    {(immediateEvidence.callers.length > 0 || immediateEvidence.neighbors.length > 0) && (
                      <div className="mt-3 grid gap-3 md:grid-cols-2 border-t border-zinc-200/60 pt-2.5 dark:border-zinc-800">
                        <div>
                          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Callers</p>
                          <p className="mt-0.5 text-xs text-zinc-700 break-all font-mono dark:text-zinc-300">
                            {immediateEvidence.callers.length > 0
                              ? immediateEvidence.callers.slice(0, 3).join(", ")
                              : "No caller summary available."}
                          </p>
                        </div>
                        <div>
                          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Neighbors</p>
                          <p className="mt-0.5 text-xs text-zinc-700 break-all font-mono dark:text-zinc-300">
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
                <div className="rounded-lg border border-zinc-200 overflow-hidden dark:border-zinc-800">
                  <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-1.5 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-800/50">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Evidence snippet</span>
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
                className="min-h-[14rem] space-y-3 rounded-lg border border-zinc-200 p-4 bg-white dark:border-zinc-800 dark:bg-zinc-900"
                data-testid="explanation-artifact"
              >
                <div className="flex items-center justify-between border-b border-zinc-200 pb-2.5 dark:border-zinc-800">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                      3. Generated LLM Explanation
                    </span>
                    <Badge variant="secondary" className="text-[10px]">AI Analysis (Non-Authoritative)</Badge>
                  </div>
                  {explainResult?.model && (
                    <span className="font-mono text-[11px] text-zinc-400">
                      Model: {explainResult.model}
                    </span>
                  )}
                </div>

                {explainFailed && explainResult?.error && (
                  <div className="rounded-lg border border-rose-200 bg-rose-50/70 p-3 text-xs text-rose-900 dark:border-rose-900/60 dark:bg-rose-950/30 dark:text-rose-200">
                    <p className="font-semibold flex items-center gap-1.5 text-rose-800 dark:text-rose-300">
                      <AlertTriangle aria-hidden="true" className="h-4 w-4 shrink-0" />
                      Explanation Generation Issue
                    </p>
                    <p className="mt-1 break-words text-[11px]">{explainResult.error}</p>
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
                      <div className="prose prose-xs max-w-none rounded-lg border border-sky-200 bg-sky-50/70 p-3.5 text-sky-950 break-words dark:border-sky-900/60 dark:bg-sky-950/30 dark:text-sky-100 [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                        <Markdown>{explainResult.explanation}</Markdown>
                      </div>
                    </div>
                  )}

                {pendingAction === "explain" && <ArtifactSkeleton lines={4} />}
                {!explainResult && pendingAction !== "explain" && (
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    No explanation generated yet. Click &quot;Explain finding&quot; to request grounded analysis.
                  </p>
                )}
              </div>

              {/* 4. Bounded Remediation Artifacts Section */}
              <div
                className="min-h-[16rem] space-y-3 rounded-lg border border-zinc-200 p-4 bg-white dark:border-zinc-800 dark:bg-zinc-900"
                data-testid={`verify-summary-${findingId ?? "none"}`}
              >
                <div className="flex items-center justify-between border-b border-zinc-200 pb-2.5 dark:border-zinc-800">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    4. Remediation & Virtual Verification
                  </span>
                  <Badge variant="secondary" className="text-[10px]">Dry-Run Execution</Badge>
                </div>

                {/* Read-Only Fix Preview */}
                {previewResult?.error && (
                  <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200">
                    <p className="font-semibold flex items-center gap-1.5 text-amber-800 dark:text-amber-300">
                      <AlertTriangle aria-hidden="true" className="h-4 w-4 shrink-0" />
                      Preview Issue
                    </p>
                    <p className="mt-1 break-words text-[11px]">{previewResult.error}</p>
                  </div>
                )}

                {previewResult?.diff && (
                  <div className="rounded-lg border border-zinc-200 overflow-hidden dark:border-zinc-800">
                    <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-1.5 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-800/50">
                      <div className="flex items-center gap-2">
                        <FileCode aria-hidden="true" className="h-3.5 w-3.5 text-zinc-500" />
                        <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
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
                    <div tabIndex={0} aria-label="Proposed diff content" className="overflow-auto max-h-72 p-3 bg-white font-mono text-xs dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100">
                      <pre className="whitespace-pre-wrap break-words">{previewResult.diff}</pre>
                    </div>
                  </div>
                )}

                {!previewResult?.diff && previewResult?.explanation && (
                  <div className="prose prose-xs max-w-none rounded-lg border border-emerald-200 bg-emerald-50/70 p-3.5 text-emerald-950 break-words dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-100">
                    <p className="font-semibold text-emerald-900 dark:text-emerald-300">Preview Guidance:</p>
                    <Markdown>{previewResult.explanation}</Markdown>
                  </div>
                )}

                {pendingAction === "preview" && <ArtifactSkeleton lines={5} />}
                {!previewResult && pendingAction !== "preview" && (
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">No preview generated yet. Click &quot;Preview suggested fix&quot; to inspect proposed changes.</p>
                )}

                {/* Dry-Run Re-Verification Outcome & Pipeline Breakdown */}
                {applyResult && categorizedOutcome && (
                  <div className="space-y-3 rounded-lg border border-zinc-200 bg-zinc-50/70 p-4 text-xs text-zinc-800 dark:border-zinc-800 dark:bg-zinc-950/40 dark:text-zinc-200">
                    {/* Outcome Header Banner */}
                    <div className="flex items-start justify-between gap-3 border-b border-zinc-200/70 pb-3 dark:border-zinc-800">
                      <div className="flex items-center gap-2">
                        {categorizedOutcome.badgeVariant === "success" ? (
                          <CheckCircle2 aria-hidden="true" className="h-4 w-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                        ) : (
                          <AlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
                        )}
                        <div>
                          <p className="font-semibold text-zinc-900 dark:text-zinc-100">{categorizedOutcome.title}</p>
                          <p className="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">{categorizedOutcome.detailMessage}</p>
                        </div>
                      </div>
                      <Badge variant={categorizedOutcome.badgeVariant} className="text-[10px]">
                        {categorizedOutcome.badgeLabel}
                      </Badge>
                    </div>

                    {/* Post-Apply Stage Pipeline Visualization */}
                    <div className="space-y-2">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Re-Verification Stage Pipeline</p>
                      <div className="grid gap-2 sm:grid-cols-2 text-xs">
                        <div className="rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
                          <span className="font-medium text-zinc-500 dark:text-zinc-400">1. Generation Decision:</span>{" "}
                          <span className="font-semibold text-zinc-900 dark:text-zinc-100">{applyResult.generation?.decision ?? "—"}</span>
                          {applyResult.generation?.reason && (
                            <p className="mt-1 text-zinc-600 dark:text-zinc-300 break-words text-[11px]">{applyResult.generation.reason}</p>
                          )}
                        </div>
                        <div className="rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
                          <span className="font-medium text-zinc-500 dark:text-zinc-400">2. Virtual Edit:</span>{" "}
                          <span className="font-semibold text-zinc-900 dark:text-zinc-100">Applied (Dry Run)</span>
                        </div>
                        <div className="rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
                          <span className="font-medium text-zinc-500 dark:text-zinc-400">3. Build Compilation:</span>{" "}
                          <span className={applyResult.compilation?.success ? "font-semibold text-emerald-600 dark:text-emerald-400" : "font-semibold text-rose-600 dark:text-rose-400"}>
                            {applyResult.compilation?.success ? "PASS" : applyResult.compilation?.attempted ? "FAIL" : "Not attempted"}
                          </span>
                        </div>
                        <div className="rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
                          <span className="font-medium text-zinc-500 dark:text-zinc-400">4. OPA Re-Verification:</span>{" "}
                          <span className={applyResult.verification?.overall_status === "PASS" ? "font-semibold text-emerald-600 dark:text-emerald-400" : "font-semibold text-amber-600 dark:text-amber-400"}>
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
                          className="px-0 text-xs font-medium text-zinc-700 hover:text-zinc-900 hover:bg-transparent dark:text-zinc-300 dark:hover:text-white"
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
                            className="px-0 text-xs font-medium text-zinc-700 hover:text-zinc-900 hover:bg-transparent dark:text-zinc-300 dark:hover:text-white"
                            onClick={() => setShowCompilationLogs((current) => !current)}
                          >
                            <Terminal aria-hidden="true" className="mr-1 h-3.5 w-3.5" />
                            {showCompilationLogs ? "Hide compilation log" : "View compilation log"}
                          </Button>
                        )}
                      </div>

                      {showVerificationDetails && (
                        <div className="mt-3 grid gap-2 rounded-lg border border-zinc-200 bg-white p-3 text-xs md:grid-cols-2 dark:border-zinc-800 dark:bg-zinc-900">
                          <p>Target Rule Status: <span className="font-medium">{applyResult.verification?.target_rule_status ?? "—"}</span></p>
                          <p>Remaining Violations: <span className="font-medium">{applyResult.verification?.remaining_violations?.length ?? 0}</span></p>
                          <p>New Violations Introduced: <span className="font-medium">{applyResult.verification?.new_violations?.length ?? 0}</span></p>
                          <p>Confidence Score: <span className="font-medium">{applyResult.confidence?.score != null ? `${Math.round(applyResult.confidence.score * 100)}%` : "—"}</span></p>
                        </div>
                      )}

                      {showCompilationLogs && applyResult.compilation?.output_snippet && (
                        <div className="mt-3 rounded-lg border border-zinc-800 bg-zinc-950 text-zinc-100 p-3 text-xs space-y-2">
                          <div className="flex items-center justify-between border-b border-zinc-800 pb-1.5">
                            <span className="font-mono text-[11px] uppercase text-zinc-400">Compiler Output Log</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-5 px-1.5 text-[10px] text-zinc-300 hover:bg-zinc-800 hover:text-white"
                              onClick={async () => {
                                const ok = await copyTextToClipboard(applyResult.compilation?.output_snippet || "");
                                if (ok) toast.success("Compilation output log copied.");
                              }}
                            >
                              <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy log
                            </Button>
                          </div>
                          <pre tabIndex={0} aria-label="Compiler output log" className="overflow-auto max-h-48 font-mono whitespace-pre-wrap break-all text-xs">{applyResult.compilation.output_snippet}</pre>
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
