import { Copy, FileCode, Loader2, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "../../../ui/badge";
import { Button } from "../../../ui/button";
import { copyTextToClipboard } from "../../../../lib/utils";
import type { AgenticRemediationResponse } from "../../../../lib/types";
import { ArtifactSkeleton } from "./ArtifactSkeleton";

export interface AgenticRemediationSectionProps {
  findingId: string | null;
  agenticResult: AgenticRemediationResponse | undefined;
  pendingAction: "explain" | "preview" | "apply" | "agentic" | undefined;
}

export const AgenticRemediationSection = ({
  findingId,
  agenticResult,
  pendingAction,
}: AgenticRemediationSectionProps) => (
  <div
    className="min-h-[14rem] space-y-3 rounded-lg border border-indigo-200 p-4 bg-indigo-50/20 dark:border-indigo-900/50 dark:bg-indigo-950/20"
    data-testid={`agentic-summary-${findingId ?? "none"}`}
  >
    <div className="flex items-center justify-between border-b border-indigo-100 pb-2.5 dark:border-indigo-900/60">
      <div className="flex items-center gap-2">
        <Sparkles aria-hidden="true" className="h-4 w-4 text-indigo-600 dark:text-indigo-400" />
        <span className="text-[11px] font-semibold uppercase tracking-wider text-indigo-950 dark:text-indigo-300">
          5. Autonomous Agentic Remediation
        </span>
      </div>
      <Badge variant="default" className="bg-indigo-600 text-[10px]">
        3-Gate Sandboxed Agent
      </Badge>
    </div>

    {pendingAction === "agentic" && (
      <div className="space-y-2 py-2">
        <div className="flex items-center gap-2 text-xs text-indigo-900 dark:text-indigo-200">
          <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin text-indigo-600" />
          <span>Autonomous agent running multi-turn refactoring &amp; verification…</span>
        </div>
        <ArtifactSkeleton lines={4} />
      </div>
    )}

    {agenticResult && pendingAction !== "agentic" && (
      <div className="space-y-3">
        <div className="flex items-start justify-between gap-3 rounded-lg border border-indigo-200 bg-white p-3 dark:border-indigo-900/60 dark:bg-zinc-900">
          <div>
            <div className="flex items-center gap-2">
              <Badge variant={agenticResult.status === "SUCCESS" ? "success" : agenticResult.status === "REFUSED" ? "secondary" : "destructive"}>
                {agenticResult.status}
              </Badge>
              <span className="font-mono text-[11px] text-zinc-500">
                {agenticResult.iterations} iteration{agenticResult.iterations === 1 ? "" : "s"}
              </span>
            </div>
            <p className="mt-1 text-xs text-zinc-800 leading-relaxed dark:text-zinc-200">
              {agenticResult.reason || "Autonomous agent concluded."}
            </p>
          </div>
        </div>

        {agenticResult.verification && typeof agenticResult.verification === "object" && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
            <div className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
              <span className="text-zinc-600 dark:text-zinc-400 font-medium">1. Compilation Gate:</span>
              <Badge variant={agenticResult.verification.compile_passed ? "success" : "destructive"}>
                {agenticResult.verification.compile_passed ? "0 Errors" : "Failed"}
              </Badge>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
              <span className="text-zinc-600 dark:text-zinc-400 font-medium">2. Regression Gate:</span>
              <Badge variant={agenticResult.verification.tests_passed ? "success" : "destructive"}>
                {agenticResult.verification.tests_passed ? "100% Pass" : "Regressed"}
              </Badge>
            </div>
            <div className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white p-2.5 dark:border-zinc-800 dark:bg-zinc-900">
              <span className="text-zinc-600 dark:text-zinc-400 font-medium">3. Policy Clearance:</span>
              <Badge variant={agenticResult.verification.policy_passed ? "success" : "destructive"}>
                {agenticResult.verification.policy_passed ? "0 Violations" : "Violated"}
              </Badge>
            </div>
          </div>
        )}

        {agenticResult.modified_files && agenticResult.modified_files.length > 0 && (
          <div className="rounded-lg border border-zinc-200 bg-white p-3 text-xs dark:border-zinc-800 dark:bg-zinc-900">
            <span className="font-semibold text-zinc-700 dark:text-zinc-300">Modified Files:</span>
            <div className="mt-1 flex flex-wrap gap-1.5 font-mono text-[11px]">
              {agenticResult.modified_files.map((file) => (
                <Badge key={file} variant="outline">{file}</Badge>
              ))}
            </div>
          </div>
        )}

        {agenticResult.diff && (
          <div className="rounded-lg border border-zinc-200 overflow-hidden dark:border-zinc-800">
            <div className="flex items-center justify-between border-b border-zinc-200 px-3 py-1.5 bg-zinc-50 dark:border-zinc-800 dark:bg-zinc-800/50">
              <div className="flex items-center gap-2">
                <FileCode aria-hidden="true" className="h-3.5 w-3.5 text-indigo-500" />
                <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                  Multi-File Verified Patch Diff
                </span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-xs"
                onClick={async () => {
                  const ok = await copyTextToClipboard(agenticResult.diff || "");
                  if (ok) toast.success("Agentic diff copied.");
                }}
              >
                <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy diff
              </Button>
            </div>
            <div tabIndex={0} aria-label="Agent patch diff" className="overflow-auto max-h-72 p-3 bg-white font-mono text-xs dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100">
              <pre className="whitespace-pre-wrap break-words">{agenticResult.diff}</pre>
            </div>
          </div>
        )}
      </div>
    )}

    {!agenticResult && pendingAction !== "agentic" && (
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        Click &quot;Autonomous Agent Fix&quot; to run an autonomous multi-turn agent that refactors code, inserts imports, and verifies JDT compilation + project tests + OPA policy clearance.
      </p>
    )}
  </div>
);

export default AgenticRemediationSection;
