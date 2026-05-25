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

const FindingDetailPanel = ({ selectedFinding }: FindingDetailPanelProps) => {
  const findingId = selectedFinding?.id ?? null;
  const explainResult = useExplainResult(findingId);
  const previewResult = usePreviewResult(findingId);
  const applyResult = useApplyResult(findingId);
  const pendingAction = usePendingAction(findingId);

  const explainMutation = useExplainMutation();
  const previewMutation = usePreviewMutation();
  const applyMutation = useApplyMutation();

  const explainStatus: "idle" | "running" | "ready" | "error" =
    pendingAction === "explain" ? "running"
    : explainResult?.status === "OK" ? "ready"
    : explainResult?.status === "ERROR" ? "error"
    : "idle";

  const previewStatus: "idle" | "running" | "ready" | "error" =
    pendingAction === "preview" ? "running"
    : previewResult?.status === "OK" ? "ready"
    : previewResult?.status === "ERROR" ? "error"
    : "idle";

  const verifyStatus: "idle" | "running" | "ready" | "error" =
    pendingAction === "apply" ? "running"
    : applyResult?.status === "OK" ? "ready"
    : applyResult?.status === "ERROR" ? "error"
    : "idle";

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

          <div className="space-y-4">
            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Explanation artifact</p>
              {explainResult?.status === "ERROR" && explainResult.error && (
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
              {!explainResult && <p className="text-sm text-slate-500">No explanation generated yet.</p>}
            </div>

            <div className="space-y-3 rounded-lg border border-slate-200 p-4">
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
              {!previewResult && <p className="text-sm text-slate-500">No preview generated yet.</p>}

              {applyResult && (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                  <div className="flex items-center gap-2 text-slate-900">
                    <CheckCircle2 aria-hidden="true" className="h-4 w-4" />
                    <p className="font-medium">Verification summary</p>
                  </div>
                  <div className="mt-2 grid gap-2 md:grid-cols-2 2xl:grid-cols-1">
                    <p>
                      Overall:{" "}
                      <span className="font-medium">{applyResult.verification?.overall_status ?? "—"}</span>
                    </p>
                    <p>
                      Rule status:{" "}
                      <span className="font-medium">{applyResult.verification?.target_rule_status ?? "—"}</span>
                    </p>
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
                      Compilation:{" "}
                      <span className="font-medium">
                        {applyResult.compilation?.success
                          ? "success"
                          : applyResult.compilation?.attempted
                            ? "failed"
                            : "not attempted"}
                      </span>
                    </p>
                    <p>
                      Decision:{" "}
                      <span className="font-medium">{applyResult.generation?.decision ?? "—"}</span>
                    </p>
                  </div>
                  {applyResult.generation?.reason && (
                    <p className="mt-2 text-xs text-slate-600">Reason: {applyResult.generation.reason}</p>
                  )}
                  {applyResult.error && (
                    <p className="mt-2 text-xs text-rose-700">Error: {applyResult.error}</p>
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
