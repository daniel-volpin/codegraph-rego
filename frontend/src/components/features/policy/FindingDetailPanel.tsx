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
        className="min-w-0 p-5 xl:sticky xl:top-24 xl:max-h-[calc(100vh-8rem)] xl:overflow-y-auto shadow-xs border-zinc-200/80 dark:border-zinc-800"
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
            {/* 1. Authoritative Policy Finding Box */}
            <FindingHeader finding={selectedFinding} />

            {/* Pipeline Step Summary Cards */}
            <PipelineStageCards
              explainStatus={explainStatus}
              previewStatus={previewStatus}
              verifyStatus={verifyStatus}
            />

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

            {remediationUnavailable && (
              <RemediationUnavailableNotice
                reasonCode={selectedFinding.remediation.reason_code}
                rationale={selectedFinding.remediation.rationale}
              />
            )}

            {/* Confidence Surface */}
            <ConfidenceBand confidence={confidenceSurface} />

            {/* 2. Source Evidence & Citation Section */}
            <div className="space-y-4">
              <EvidenceSection finding={selectedFinding} />

              {/* 3. Generated LLM Explanation Artifact Section */}
              <ExplanationSection
                explainResult={explainResult}
                explainFailed={explainFailed}
                pendingAction={pendingAction}
              />

              {/* 4. Bounded Remediation Artifacts Section */}
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

              {/* 5. Autonomous Multi-Turn Agentic Remediation Section */}
              <AgenticRemediationSection
                findingId={findingId}
                agenticResult={agenticResult}
                pendingAction={pendingAction}
              />
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
