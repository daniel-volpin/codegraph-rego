import { Info } from "lucide-react";

export interface RemediationUnavailableNoticeProps {
  reasonCode: string;
  rationale: string;
}

export const RemediationUnavailableNotice = ({
  reasonCode,
  rationale,
}: RemediationUnavailableNoticeProps) => (
  <div className="rounded-lg border border-amber-200 bg-amber-50/70 p-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200">
    <p className="font-semibold flex items-center gap-1.5">
      <Info aria-hidden="true" className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
      Automatic remediation unavailable for this category
    </p>
    <p className="mt-1 break-words text-[11px] text-amber-800 dark:text-amber-300">
      {reasonCode}: {rationale}
    </p>
  </div>
);

export default RemediationUnavailableNotice;
