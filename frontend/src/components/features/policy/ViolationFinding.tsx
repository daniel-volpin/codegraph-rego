import { memo } from "react";
import { ChevronDown, ChevronRight, Copy, Loader2, Sparkles } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import CodeHighlight from "../../ui/CodeHighlight";
import ConfidenceBand from "./ConfidenceBand";
import { PreviewExplanationBox } from "./PreviewExplanationBox";
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
    <div className="space-y-2.5 rounded-lg border border-sky-200 bg-sky-50/70 p-3.5 text-xs text-sky-950 dark:border-sky-900/60 dark:bg-sky-950/30 dark:text-sky-100">
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400">Citation Grounding</p>
        <p className="mt-0.5 break-all font-mono text-[11px] font-medium text-sky-900 dark:text-sky-200" title={citation.full}>
          {citation.display}
        </p>
      </div>
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400">Why Finding Matters</p>
        <p className="mt-0.5 break-words leading-relaxed">{payload.why}</p>
      </div>
      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-700 dark:text-sky-400">Recommended Fix</p>
        <p className="mt-0.5 break-words leading-relaxed">{payload.fix}</p>
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
      className={`rounded-lg border bg-white shadow-2xs transition-all dark:bg-zinc-900 ${
        isSelected
          ? "border-zinc-900 ring-2 ring-zinc-900/10 dark:border-zinc-100 dark:ring-zinc-100/10"
          : "border-zinc-200 dark:border-zinc-800"
      }`}
    >
      <button
        type="button"
        aria-expanded={isExpanded}
        aria-controls={`finding-${finding.id}-detail`}
        className="flex w-full flex-wrap items-start justify-between gap-3 p-3.5 text-left transition hover:bg-zinc-50/50 dark:hover:bg-zinc-800/40"
        onClick={() => {
          onSelect(finding.id);
          onToggle(groupId, finding.id);
        }}
      >
        <div className="flex min-w-0 items-start gap-2.5">
          {isExpanded ? (
            <ChevronDown aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-zinc-400" />
          ) : (
            <ChevronRight aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-zinc-400" />
          )}
          <div className="min-w-0">
            <p className="truncate font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100" title={finding.targetMethod}>
              {compactTargetMethod(finding.targetMethod)}
            </p>
            <p className="mt-0.5 truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400" title={finding.filePath}>
              {formatCitationDisplay(finding.filePath).display}
            </p>
            <div className="mt-2">
              <div className="flex flex-wrap gap-1.5">
                <Badge variant="secondary" className="text-[10px]">{formatCitationDisplay(finding.module).display}</Badge>
                <Badge variant="secondary" className="text-[10px]">Control {finding.controlLabel}</Badge>
                <Badge variant="secondary" className="text-[10px]">{finding.cweLabel}</Badge>
              </div>
            </div>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Badge variant={severityVariant(finding.severity)} className="text-[10px]">{finding.severity}</Badge>
          <Badge variant={remediationBadgeVariant(remediation)} className="text-[10px]">
            {remediationBadgeLabel(remediation)}
          </Badge>
        </div>
      </button>

      {isExpanded && (
        <div id={`finding-${finding.id}-detail`} className="border-t border-zinc-200 p-4 space-y-3.5 dark:border-zinc-800">
          <div className="space-y-3.5">
            <p className="text-xs text-zinc-700 leading-relaxed dark:text-zinc-300">{finding.reason}</p>

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
                    <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Verifying…
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

            <div className="rounded-lg border border-zinc-200 overflow-hidden dark:border-zinc-800">
              <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-1.5 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-800/50">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Code snippet</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 px-2 text-xs"
                  aria-label={`Copy snippet for ${finding.targetMethod}`}
                  onClick={async () => {
                    const ok = await copyTextToClipboard(finding.snippet || "");
                    if (ok) toast.success("Code copied.");
                    else toast.error("Clipboard unavailable. Select and copy manually.");
                  }}
                >
                  <Copy aria-hidden="true" className="mr-1 h-3.5 w-3.5" /> Copy
                </Button>
              </div>
              <CodeHighlight
                code={finding.snippet || "// snippet unavailable"}
                language="java"
                maxHeight={460}
              />
            </div>

            {previewResult?.error && (
              <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200">
                <strong>Preview error:</strong> {previewResult.error}
              </div>
            )}
            {previewResult?.diff && (
              <div className="rounded-lg border border-zinc-200 overflow-hidden dark:border-zinc-800">
                <div className="border-b border-zinc-200 px-3 py-1.5 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-800/50">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Remediation Diff
                  </span>
                </div>
                <pre className="overflow-auto whitespace-pre-wrap break-words bg-white p-3 font-mono text-xs dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100">
                  {previewResult.diff}
                </pre>
              </div>
            )}
            {!previewResult?.diff && previewResult?.explanation && (
              <PreviewExplanationBox heading="Preview:" explanation={previewResult.explanation} />
            )}
          </div>
        </div>
      )}
    </div>
  );
});

export default ViolationFinding;
