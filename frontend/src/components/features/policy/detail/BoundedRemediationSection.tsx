import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Copy,
  FileCode,
  Terminal,
} from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Badge } from "../../../ui/badge";
import { Button } from "../../../ui/button";
import { copyTextToClipboard } from "../../../../lib/utils";
import type {
  RemediationApplyResponse,
  RemediationPreviewResponse,
} from "../../../../lib/types";
import { categorizeApplyOutcome } from "../policyUtils";
import { ArtifactSkeleton } from "./ArtifactSkeleton";

export interface BoundedRemediationSectionProps {
  findingId: string | null;
  previewResult: RemediationPreviewResponse | undefined;
  applyResult: RemediationApplyResponse | undefined;
  previewFailed: boolean;
  categorizedOutcome: ReturnType<typeof categorizeApplyOutcome> | null;
  pendingAction: "explain" | "preview" | "apply" | "agentic" | undefined;
  showVerificationDetails: boolean;
  onToggleVerificationDetails: () => void;
  showCompilationLogs: boolean;
  onToggleCompilationLogs: () => void;
}

export const BoundedRemediationSection = ({
  findingId,
  previewResult,
  applyResult,
  categorizedOutcome,
  pendingAction,
  showVerificationDetails,
  onToggleVerificationDetails,
  showCompilationLogs,
  onToggleCompilationLogs,
}: BoundedRemediationSectionProps) => (
  <div
    className="min-h-[16rem] space-y-3 rounded-lg border border-zinc-200 p-4 bg-white dark:border-zinc-800 dark:bg-zinc-900"
    data-testid={`verify-summary-${findingId ?? "none"}`}
  >
    <div className="flex items-center justify-between border-b border-zinc-200 pb-2.5 dark:border-zinc-800">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
        4. Remediation &amp; Virtual Verification
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
              onClick={onToggleVerificationDetails}
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
                onClick={onToggleCompilationLogs}
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
);

export default BoundedRemediationSection;
