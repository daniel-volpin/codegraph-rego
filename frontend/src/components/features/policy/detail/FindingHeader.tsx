import { Copy } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "../../../ui/badge";
import { Button } from "../../../ui/button";
import { copyTextToClipboard } from "../../../../lib/utils";
import {
  formatCitationDisplay,
  parseMethodKey,
  severityVariant,
  type ViolationRow,
} from "../policyUtils";

export interface FindingHeaderProps {
  finding: ViolationRow;
}

export const FindingHeader = ({ finding }: FindingHeaderProps) => {
  const parsedMethod = parseMethodKey(finding.targetMethod || finding.methodKey);
  const cleanPath = formatCitationDisplay(finding.filePath).display;
  const cleanControl = finding.controlLabel.toLowerCase().startsWith("control")
    ? finding.controlLabel
    : `Control ${finding.controlLabel}`;

  return (
    <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-4 space-y-3 dark:border-zinc-800 dark:bg-zinc-900/40">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
          1. Policy Finding (Authoritative OPA Rule)
        </span>
        <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100">{finding.ruleId}</span>
      </div>

      <div className="flex flex-wrap gap-1.5">
        <Badge variant="secondary" className="text-[10px]">{cleanControl}</Badge>
        <Badge variant="secondary" className="text-[10px]">{finding.cweLabel}</Badge>
        <Badge variant={severityVariant(finding.severity)} className="text-[10px]">{finding.severity}</Badge>
      </div>

      <div>
        <div className="flex items-center justify-between">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target Method &amp; Path</p>
          <Button
            variant="ghost"
            size="sm"
            className="h-5 px-1.5 text-[10px] text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100"
            onClick={async () => {
              const ok = await copyTextToClipboard(parsedMethod.shortSignature);
              if (ok) toast.success("Method signature copied.");
              else toast.error("Clipboard unavailable.");
            }}
          >
            <Copy aria-hidden="true" className="mr-1 h-3 w-3" /> Copy Signature
          </Button>
        </div>
        <p className="mt-0.5 break-all font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100" title={finding.targetMethod}>
          {parsedMethod.shortSignature}
        </p>
        <div className="mt-0.5 flex items-center gap-2">
          <p className="break-all font-mono text-[11px] text-zinc-500 dark:text-zinc-400" title={finding.filePath}>
            {cleanPath}
          </p>
          {parsedMethod.packageName && (
            <span className="text-[10px] text-zinc-400 dark:text-zinc-500 font-mono">
              ({parsedMethod.packageName})
            </span>
          )}
        </div>
      </div>

      <div>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Violation Reason</p>
        <p className="mt-1 text-xs text-zinc-700 leading-relaxed dark:text-zinc-300">{finding.reason}</p>
      </div>
    </div>
  );
};

export default FindingHeader;
