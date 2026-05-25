import { CheckCircle2, Copy, Loader2, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import CodeHighlight from "../../ui/CodeHighlight";
import { copyTextToClipboard } from "../../../lib/utils";
import type { PolicyExplanationStructured } from "../../../lib/types";
import {
  type ViolationRow,
  type RawViolation,
  type PendingAction,
  type PolicyExplainOneResponse,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
  artifactStatusLabel,
  artifactStatusVariant,
  formatCitationDisplay,
  remediationBadgeLabel,
  remediationBadgeVariant,
  severityVariant,
} from "./policyUtils";

interface FindingDetailPanelProps {
  selectedFinding: ViolationRow | null;
  explainById: Record<string, PolicyExplainOneResponse>;
  previewById: Record<string, RemediationPreviewResponse>;
  applyById: Record<string, RemediationApplyResponse>;
  pendingAction: Record<string, PendingAction>;
  explainStatus: "idle" | "running" | "ready" | "error";
  previewStatus: "idle" | "running" | "ready" | "error";
  verifyStatus: "idle" | "running" | "ready" | "error";
  onExplain: (raw: RawViolation) => void;
  onPreview: (finding: ViolationRow) => void;
  onApply: (finding: ViolationRow) => void;
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

const FindingDetailPanel = ({
  selectedFinding,
  explainById,
  previewById,
  applyById,
  pendingAction,
  explainStatus,
  previewStatus,
  verifyStatus,
  onExplain,
  onPreview,
  onApply,
}: FindingDetailPanelProps) => {
  const selectedPendingAction = selectedFinding ? pendingAction[selectedFinding.id] : undefined;
  const selectedExplain = selectedFinding ? explainById[selectedFinding.id] : undefined;
  const selectedPreview = selectedFinding ? previewById[selectedFinding.id] : undefined;
  const selectedApply = selectedFinding ? applyById[selectedFinding.id] : undefined;

  return (
    <Card className="p-5 2xl:sticky 2xl:top-24 2xl:max-h-[calc(100vh-11rem)] 2xl:overflow-auto">
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
            <p className="truncate font-mono text-sm text-slate-900" title={selectedFinding.targetMethod}>
              {selectedFinding.targetMethod}
            </p>
            <p className="mt-1 truncate font-mono text-xs text-slate-500" title={selectedFinding.filePath}>
              {selectedFinding.filePath}
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
              disabled={selectedPendingAction !== undefined}
              onClick={() => onExplain(selectedFinding.raw)}
            >
              {selectedPendingAction === "explain" ? (
                <>
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" /> Explaining…
                </>
              ) : (
                <>
                  <Sparkles className="mr-1 h-4 w-4" /> Explain finding
                </>
              )}
            </Button>
            <Button
              variant="secondary"
              size="sm"
              disabled={selectedPendingAction !== undefined || !selectedFinding.remediation.preview_available}
              onClick={() => onPreview(selectedFinding)}
            >
              {selectedPendingAction === "preview" ? (
                <>
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" /> Previewing…
                </>
              ) : (
                <>Preview suggested fix</>
              )}
            </Button>
            <Button
              variant="default"
              size="sm"
              disabled={selectedPendingAction !== undefined || !selectedFinding.remediation.verify_available}
              onClick={() => onApply(selectedFinding)}
            >
              {selectedPendingAction === "apply" ? (
                <>
                  <Loader2 className="mr-1 h-4 w-4 animate-spin" /> Verifying…
                </>
              ) : (
                <>Verify fix (dry run)</>
              )}
            </Button>
          </div>

          <div className="space-y-4">
            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Explanation artifact</p>
              {selectedExplain?.status === "ERROR" && selectedExplain.error && (
                <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                  {selectedExplain.error}
                </div>
              )}
              {selectedExplain?.status === "OK" && selectedExplain.explanation_structured &&
                renderStructuredExplanation(selectedExplain.explanation_structured)}
              {selectedExplain?.status === "OK" &&
                !selectedExplain.explanation_structured &&
                selectedExplain.explanation && (
                  <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50 p-4 text-indigo-900 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                    <Markdown>{selectedExplain.explanation}</Markdown>
                  </div>
                )}
              {!selectedExplain && <p className="text-sm text-slate-500">No explanation generated yet.</p>}
            </div>

            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Remediation artifacts</p>
              {selectedPreview?.error && (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                  <strong>Preview error:</strong> {selectedPreview.error}
                </div>
              )}
              {selectedPreview?.diff && (
                <div className="rounded-lg border border-slate-200">
                  <div className="border-b border-slate-200 px-3 py-2">
                    <span className="text-xs font-semibold uppercase text-slate-500">Proposed diff</span>
                  </div>
                  <pre className="overflow-auto whitespace-pre-wrap break-words bg-white p-3 text-xs">
                    {selectedPreview.diff}
                  </pre>
                </div>
              )}
              {!selectedPreview?.diff && selectedPreview?.explanation && (
                <div className="prose prose-sm max-w-none rounded-md border border-emerald-200 bg-emerald-50 p-4 text-emerald-900 break-words">
                  <strong>Preview:</strong>
                  <Markdown>{selectedPreview.explanation}</Markdown>
                </div>
              )}
              {!selectedPreview && <p className="text-sm text-slate-500">No preview generated yet.</p>}

              {selectedApply && (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                  <div className="flex items-center gap-2 text-slate-900">
                    <CheckCircle2 className="h-4 w-4" />
                    <p className="font-medium">Verification summary</p>
                  </div>
                  <div className="mt-2 grid gap-2 md:grid-cols-2 2xl:grid-cols-1">
                    <p>
                      Overall:{" "}
                      <span className="font-medium">{selectedApply.verification?.overall_status ?? "—"}</span>
                    </p>
                    <p>
                      Rule status:{" "}
                      <span className="font-medium">{selectedApply.verification?.target_rule_status ?? "—"}</span>
                    </p>
                    <p>
                      Remaining violations:{" "}
                      <span className="font-medium">
                        {selectedApply.verification?.remaining_violations?.length ?? 0}
                      </span>
                    </p>
                    <p>
                      New violations:{" "}
                      <span className="font-medium">
                        {selectedApply.verification?.new_violations?.length ?? 0}
                      </span>
                    </p>
                    <p>
                      Compilation:{" "}
                      <span className="font-medium">
                        {selectedApply.compilation?.success
                          ? "success"
                          : selectedApply.compilation?.attempted
                            ? "failed"
                            : "not attempted"}
                      </span>
                    </p>
                    <p>
                      Decision:{" "}
                      <span className="font-medium">{selectedApply.generation?.decision ?? "—"}</span>
                    </p>
                  </div>
                  {selectedApply.generation?.reason && (
                    <p className="mt-2 text-xs text-slate-600">Reason: {selectedApply.generation.reason}</p>
                  )}
                  {selectedApply.error && (
                    <p className="mt-2 text-xs text-rose-700">Error: {selectedApply.error}</p>
                  )}
                </div>
              )}
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
