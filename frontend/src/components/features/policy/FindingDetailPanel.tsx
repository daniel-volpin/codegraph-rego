import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import ConfidenceBand from "./ConfidenceBand";
import { RemediationConfirmDialog } from "./RemediationConfirmDialog";
import {
  ActionToolbar,
  AgenticRemediationSection,
  BoundedRemediationSection,
  EvidenceSection,
  ExplanationSection,
  FindingHeader,
  PipelineStageCards,
  RemediationUnavailableNotice,
} from "./detail";
import {
  categorizeApplyOutcome,
  deriveConfidenceSurface,
  remediationBadgeLabel,
  remediationBadgeVariant,
  severityVariant,
  type ViolationRow,
} from "./policyUtils";
import {
  useAgenticMutation,
  useAgenticResult,
  useApplyMutation,
  useApplyResult,
  useExplainMutation,
  useExplainResult,
  usePendingAction,
  usePreviewMutation,
  usePreviewResult,
} from "../../../hooks/usePolicyArtifacts";

export interface FindingDetailPanelProps {
  selectedFinding: ViolationRow | null;
}

const remediationArtifactStatus = (status: string | null | undefined): "idle" | "ready" | "error" => {
  if (!status) return "idle";
  return status === "OK" ? "ready" : "error";
};

export const FindingDetailPanel = ({ selectedFinding }: FindingDetailPanelProps) => {
  const findingId = selectedFinding?.id ?? null;
  const explainResult = useExplainResult(findingId);
  const previewResult = usePreviewResult(findingId);
  const applyResult = useApplyResult(findingId);
  const agenticResult = useAgenticResult(findingId);
  const pendingAction = usePendingAction(findingId);

  const explainMutation = useExplainMutation();
  const previewMutation = usePreviewMutation();
  const applyMutation = useApplyMutation();
  const agenticMutation = useAgenticMutation();

  const [activeTab, setActiveTab] = useState<"all" | "fix" | "evidence" | "explanation">("all");
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

  const previewFailed = Boolean(previewResult?.status && previewResult.status !== "OK");
  const applyFailed = Boolean(applyResult?.status && applyResult.status !== "OK");
  const explainFailed = Boolean(explainResult?.status && explainResult.status !== "OK");

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
        className="min-w-0 p-4 xl:sticky xl:top-24 xl:max-h-[calc(100vh-7rem)] xl:overflow-y-auto shadow-xs border-zinc-200/80 dark:border-zinc-800"
        data-testid="finding-dossier"
      >
        <div role="status" aria-live="polite" className="sr-only">
          {statusMessage}
        </div>

        {/* Compact Header with Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-2.5 border-b border-zinc-200 pb-3 dark:border-zinc-800">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <ShieldCheck aria-hidden="true" className="h-4 w-4 text-indigo-600 dark:text-indigo-400 shrink-0" />
              <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Case Dossier</span>
              {selectedFinding && (
                <span className="font-mono text-xs font-semibold text-slate-700 dark:text-zinc-300 truncate">
                  {selectedFinding.ruleId}
                </span>
              )}
            </div>
            {selectedFinding && (
              <div className="mt-1 flex flex-wrap items-center gap-1.5">
                <Badge variant={severityVariant(selectedFinding.severity)} className="text-[10px]">
                  {selectedFinding.severity}
                </Badge>
                <Badge variant={remediationBadgeVariant(selectedFinding.remediation)} className="text-[10px]">
                  {remediationBadgeLabel(selectedFinding.remediation)}
                </Badge>
                <Badge variant="secondary" className="text-[10px]">
                  {selectedFinding.cweLabel}
                </Badge>
              </div>
            )}
          </div>

          {selectedFinding && (
            <div className="flex items-center gap-1 bg-slate-100 dark:bg-zinc-800 p-1 rounded-lg text-xs shrink-0">
              {[
                { id: "all", label: "All Details" },
                { id: "fix", label: "⚡ 3-Gate Fix" },
                { id: "evidence", label: "🔍 Evidence" },
                { id: "explanation", label: "📋 AI Analysis" },
              ].map((tab) => {
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition cursor-pointer whitespace-nowrap ${
                      active
                        ? "bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 shadow-2xs font-semibold"
                        : "text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
                    }`}
                  >
                    {tab.label}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {!selectedFinding ? (
          <div className="py-8 text-center text-xs text-zinc-500 dark:text-zinc-400">
            Select any finding on the left to inspect evidence, run AI analysis, or execute autonomous 3-gate repair.
          </div>
        ) : (
          <div className="space-y-3.5 pt-3">
            {/* 1. Authoritative Policy Finding Box */}
            <FindingHeader finding={selectedFinding} />

            {/* Action Toolbar */}
            <ActionToolbar
              pendingAction={pendingAction}
              previewAvailable={Boolean(selectedFinding.remediation.preview_available)}
              verifyAvailable={Boolean(selectedFinding.remediation.verify_available)}
              onExplain={() => explainMutation.mutate(selectedFinding)}
              onPreview={() => previewMutation.mutate(selectedFinding)}
              onVerify={() => setShowConfirmDialog(true)}
              onAgentic={() => agenticMutation.mutate(selectedFinding)}
            />

            {/* Pipeline Stage Cards */}
            <PipelineStageCards
              explainStatus={explainStatus}
              previewStatus={previewStatus}
              verifyStatus={verifyStatus}
            />

            {remediationUnavailable && (
              <RemediationUnavailableNotice
                reasonCode={selectedFinding.remediation.reason_code}
                rationale={selectedFinding.remediation.rationale}
              />
            )}

            {/* Confidence Surface */}
            <ConfidenceBand confidence={confidenceSurface} />

            {/* Dossier Content Sections */}
            <div className="space-y-3.5">
              {/* 2. Source Evidence & Citation Section */}
              {(activeTab === "all" || activeTab === "evidence") && (
                <EvidenceSection finding={selectedFinding} />
              )}

              {/* 3. Generated LLM Explanation Artifact Section */}
              {(activeTab === "all" || activeTab === "explanation") && (
                <ExplanationSection
                  explainResult={explainResult}
                  explainFailed={explainFailed}
                  pendingAction={pendingAction}
                />
              )}

              {/* 4. Bounded Remediation Artifacts Section */}
              {(activeTab === "all" || activeTab === "fix") && (
                <BoundedRemediationSection
                  findingId={findingId}
                  previewResult={previewResult}
                  applyResult={applyResult}
                  previewFailed={previewFailed}
                  categorizedOutcome={categorizedOutcome}
                  pendingAction={pendingAction}
                  showVerificationDetails={showVerificationDetails}
                  onToggleVerificationDetails={() => setShowVerificationDetails((c) => !c)}
                  showCompilationLogs={showCompilationLogs}
                  onToggleCompilationLogs={() => setShowCompilationLogs((c) => !c)}
                />
              )}

              {/* 5. Autonomous Multi-Turn Agentic Remediation Section */}
              {(activeTab === "all" || activeTab === "fix") && (
                <AgenticRemediationSection
                  findingId={findingId}
                  agenticResult={agenticResult}
                  pendingAction={pendingAction}
                />
              )}
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
