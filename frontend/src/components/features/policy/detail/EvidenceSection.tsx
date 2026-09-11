import { Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "../../../ui/button";
import CodeHighlight from "../../../ui/CodeHighlight";
import { copyTextToClipboard } from "../../../../lib/utils";
import {
  formatCitationDisplay,
  type ViolationRow,
} from "../policyUtils";

export interface EvidenceSectionProps {
  finding: ViolationRow;
}

interface ImmediateEvidence {
  citation: string;
  callers: string[];
  neighbors: string[];
}

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

export const EvidenceSection = ({ finding }: EvidenceSectionProps) => {
  const immediateEvidence = buildImmediateEvidence(finding);

  return (
    <div className="rounded-lg border border-zinc-200 p-4 space-y-3 bg-white dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex items-center justify-between border-b border-zinc-200 pb-2.5 dark:border-zinc-800">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
          2. Source Evidence &amp; Graph Grounding
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          aria-label={`Copy citation for ${finding.targetMethod}`}
          onClick={async () => {
            const ok = await copyTextToClipboard(finding.citation);
            if (ok) toast.success("Citation copied.");
            else toast.error("Clipboard unavailable.");
          }}
        >
          <Copy aria-hidden="true" className="mr-1 h-3.5 w-3.5" /> Copy citation
        </Button>
      </div>

      <details
        aria-label="Evidence and source context"
        open
        className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3.5 dark:border-zinc-800 dark:bg-zinc-950/40"
      >
        <summary className="cursor-pointer text-[11px] font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
          Evidence &amp; Source Context
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
              {finding.targetMethod}
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

      {/* Evidence Code Snippet */}
      <div className="rounded-lg border border-zinc-200 overflow-hidden dark:border-zinc-800">
        <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-1.5 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-800/50">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Evidence snippet</span>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-[11px]"
            aria-label={`Copy snippet for ${finding.targetMethod}`}
            onClick={async () => {
              const ok = await copyTextToClipboard(finding.snippet || "");
              if (ok) toast.success("Code copied.");
              else toast.error("Clipboard unavailable.");
            }}
          >
            <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy
          </Button>
        </div>
        <CodeHighlight
          code={finding.snippet || "// snippet unavailable"}
          language="java"
          maxHeight={460}
        />
      </div>
    </div>
  );
};

export default EvidenceSection;
