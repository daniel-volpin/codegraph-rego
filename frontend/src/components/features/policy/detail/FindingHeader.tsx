import { Badge } from "../../../ui/badge";
import {
  severityVariant,
  type ViolationRow,
} from "../policyUtils";

export interface FindingHeaderProps {
  finding: ViolationRow;
}

export const FindingHeader = ({ finding }: FindingHeaderProps) => (
  <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-4 space-y-3 dark:border-zinc-800 dark:bg-zinc-900/40">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
        1. Policy Finding (Authoritative OPA Rule)
      </span>
      <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100">{finding.ruleId}</span>
    </div>

    <div className="flex flex-wrap gap-1.5">
      <Badge variant="secondary" className="text-[10px]">Control {finding.controlLabel}</Badge>
      <Badge variant="secondary" className="text-[10px]">{finding.cweLabel}</Badge>
      <Badge variant={severityVariant(finding.severity)} className="text-[10px]">{finding.severity}</Badge>
    </div>

    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Target Method &amp; Path</p>
      <p className="mt-0.5 break-all font-mono text-xs font-semibold text-zinc-900 dark:text-zinc-100" title={finding.targetMethod}>
        {finding.targetMethod}
      </p>
      <p className="mt-0.5 break-all font-mono text-[11px] text-zinc-500 dark:text-zinc-400" title={finding.filePath}>
        {finding.filePath}
      </p>
    </div>

    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Violation Reason</p>
      <p className="mt-1 text-xs text-zinc-700 leading-relaxed dark:text-zinc-300">{finding.reason}</p>
    </div>
  </div>
);

export default FindingHeader;
