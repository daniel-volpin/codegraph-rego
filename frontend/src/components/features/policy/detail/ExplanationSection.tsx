import { AlertTriangle, Copy } from "lucide-react";
import Markdown from "react-markdown";
import { toast } from "sonner";
import { Badge } from "../../../ui/badge";
import { Button } from "../../../ui/button";
import { copyTextToClipboard } from "../../../../lib/utils";
import type { PolicyExplainOneResponse, PolicyExplanationStructured } from "../../../../lib/types";
import { formatCitationDisplay } from "../policyUtils";
import { ArtifactSkeleton } from "./ArtifactSkeleton";

export interface ExplanationSectionProps {
  explainResult: PolicyExplainOneResponse | undefined;
  explainFailed: boolean;
  pendingAction: "explain" | "preview" | "apply" | "agentic" | undefined;
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

export const ExplanationSection = ({
  explainResult,
  explainFailed,
  pendingAction,
}: ExplanationSectionProps) => (
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
);

export default ExplanationSection;
