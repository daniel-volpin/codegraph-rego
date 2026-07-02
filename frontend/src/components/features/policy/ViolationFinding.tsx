import { memo } from "react";
import { ChevronDown, ChevronRight, Copy, Loader2, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import CodeHighlight from "../../ui/CodeHighlight";
import ConfidenceBand from "./ConfidenceBand";
import { copyTextToClipboard } from "../../../lib/utils";
import type { PolicyExplanationStructured } from "../../../lib/types";
import {
  type ViolationRow,
  compactTargetMethod,
  deriveConfidenceSurface,
  formatCitationDisplay,
  remediationBadgeLabel,
  remediationBadgeVariant,
  remediationSummaryText,
  severityVariant,
} from "./policyUtils";
import {
  useApplyResult,
  useApplyMutation,
  useExplainMutation,
  useExplainResult,
  usePendingAction,
  usePreviewMutation,
  usePreviewResult,
} from "../../../hooks/usePolicyArtifacts";

interface ViolationFindingProps {
  finding: ViolationRow;
  groupId: string;
  isSelected: boolean;
  isExpanded: boolean;
  onSelect: (id: string) => void;
  onToggle: (groupId: string, findingId: string) => void;
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

const ViolationFinding = memo(function ViolationFinding({
  finding,
  groupId,
  isSelected,
  isExpanded,
  onSelect,
  onToggle,
}: ViolationFindingProps) {
  // Each row owns its own subscriptions. Re-renders are scoped to this id —
  // sibling rows' explain/preview/apply landings no longer fan out.
  const explainResult = useExplainResult(finding.id);
  const previewResult = usePreviewResult(finding.id);
  const applyResult = useApplyResult(finding.id);
  const pendingAction = usePendingAction(finding.id);

  const explainMutation = useExplainMutation();
  const previewMutation = usePreviewMutation();
  const applyMutation = useApplyMutation();

  const isBusy = pendingAction !== undefined;
  const remediation = finding.remediation;
  const previewDisabled = isBusy || !remediation.preview_available;
  const verifyDisabled = isBusy || !remediation.verify_available;
  const confidenceSurface = deriveConfidenceSurface(
    applyResult?.confidence ?? previewResult?.confidence ?? null,
  );

  return (
    <div
      data-testid={`finding-row-${finding.id}`}
      className={`rounded-lg border bg-white ${
        isSelected ? "border-indigo-300 ring-2 ring-indigo-100" : "border-slate-200"
      }`}
    >
      <button
        type="button"
        aria-expanded={isExpanded}
        aria-controls={`finding-${finding.id}-detail`}
        className="flex w-full flex-wrap items-start justify-between gap-3 p-4 text-left"
        onClick={() => {
          onSelect(finding.id);
          onToggle(groupId, finding.id);
        }}
      >
        <div className="flex min-w-0 items-start gap-3">
          {isExpanded ? (
            <ChevronDown aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
          ) : (
            <ChevronRight aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" />
          )}
          <div className="min-w-0">
            <p className="truncate font-mono text-sm text-slate-900" title={finding.targetMethod}>
              {compactTargetMethod(finding.targetMethod)}
            </p>
            <p className="mt-1 truncate font-mono text-xs text-slate-500" title={finding.filePath}>
              {finding.filePath}
            </p>
            <div className="mt-2">
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary">{finding.module}</Badge>
                <Badge variant="secondary">Control {finding.controlLabel}</Badge>
                <Badge variant="secondary">{finding.cweLabel}</Badge>
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Badge variant={severityVariant(finding.severity)}>{finding.severity}</Badge>
          <Badge variant={remediationBadgeVariant(remediation)}>
            {remediationBadgeLabel(remediation)}
          </Badge>
        </div>
      </button>

      {isExpanded && (
        <div id={`finding-${finding.id}-detail`} className="border-t border-slate-200 p-4">
          <div className="space-y-4">
            <p className="text-sm text-slate-700">{finding.reason}</p>

            <div className="flex flex-wrap gap-2">
              <Button
                variant="ghost"
                size="sm"
                disabled={isBusy}
                onClick={() => onSelect(finding.id)}
              >
                Open dossier
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={isBusy}
                title="Generate a concise explanation of why this finding matters and how to address it."
                onClick={() => {
                  onSelect(finding.id);
                  explainMutation.mutate(finding);
                }}
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
                disabled={previewDisabled}
                title="Generate a proposed code change and check it virtually without compiling or modifying source files."
                onClick={() => {
                  onSelect(finding.id);
                  previewMutation.mutate(finding);
                }}
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
                disabled={verifyDisabled}
                title="Run the full dry-run remediation pipeline: generate a fix, compile in a temp workspace, re-ingest, and re-check policies. No source files are persisted from the UI."
                onClick={() => {
                  onSelect(finding.id);
                  applyMutation.mutate(finding);
                }}
              >
                {pendingAction === "apply" ? (
                  <>
                    <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Applying…
                  </>
                ) : (
                  <>Verify fix (dry run)</>
                )}
              </Button>
            </div>

            <ConfidenceBand confidence={confidenceSurface} title="Remediation confidence" />

            <p className="text-xs text-slate-500">{remediationSummaryText(remediation)}</p>
            <p className="text-xs text-slate-500">{remediation.rationale}</p>

            {explainResult?.status === "ERROR" && explainResult.error && (
              <div className="rounded-md border border-rose-200 bg-rose-50 p-3 text-sm text-rose-900">
                {explainResult.error}
              </div>
            )}

            {explainResult?.status === "OK" &&
              (explainResult.explanation_structured || explainResult.explanation) &&
              (explainResult.explanation_structured ? (
                renderStructuredExplanation(explainResult.explanation_structured)
              ) : (
                <div className="prose prose-sm prose-indigo max-w-none rounded-md border border-indigo-200 bg-indigo-50 p-4 text-indigo-900 break-words [&_pre]:whitespace-pre-wrap [&_code]:break-all">
                  <Markdown>{explainResult.explanation!}</Markdown>
                </div>
              ))}

            <div className="rounded-lg border border-slate-200">
              <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2">
                <span className="text-xs font-semibold uppercase text-slate-500">Code snippet</span>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Copy snippet for ${finding.targetMethod}`}
                  onClick={async () => {
                    const ok = await copyTextToClipboard(finding.snippet || "");
                    if (ok) toast.success("Code copied.");
                    else toast.error("Clipboard unavailable. Select and copy manually.");
                  }}
                >
                  <Copy aria-hidden="true" className="mr-1 h-4 w-4" /> Copy
                </Button>
              </div>
              <CodeHighlight
                code={finding.snippet || "// snippet unavailable"}
                language="java"
                maxHeight={460}
              />
            </div>

            {previewResult?.error && (
              <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                <strong>Preview error:</strong> {previewResult.error}
              </div>
            )}
            {previewResult?.diff && (
              <div className="rounded-lg border border-slate-200">
                <div className="border-b border-slate-200 px-3 py-2">
                  <span className="text-xs font-semibold uppercase text-slate-500">
                    Remediation Diff
                  </span>
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
          </div>
        </div>
      )}
    </div>
  );
});

export default ViolationFinding;
