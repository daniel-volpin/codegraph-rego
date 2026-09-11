import { Badge } from "../../../ui/badge";
import {
  artifactStatusLabel,
  artifactStatusVariant,
} from "../policyUtils";

export interface PipelineStageCardsProps {
  explainStatus: "idle" | "running" | "ready" | "error";
  previewStatus: "idle" | "running" | "ready" | "error";
  verifyStatus: "idle" | "running" | "ready" | "error";
}

export const PipelineStageCards = ({
  explainStatus,
  previewStatus,
  verifyStatus,
}: PipelineStageCardsProps) => (
  <div className="grid gap-2.5 md:grid-cols-3 2xl:grid-cols-1">
    <div className="rounded-lg border border-zinc-200 p-2.5 bg-white dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">1. Explain</p>
        <Badge variant={artifactStatusVariant(explainStatus)} className="text-[10px]">{artifactStatusLabel(explainStatus)}</Badge>
      </div>
    </div>
    <div className="rounded-lg border border-zinc-200 p-2.5 bg-white dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">2. Preview</p>
        <Badge variant={artifactStatusVariant(previewStatus)} className="text-[10px]">{artifactStatusLabel(previewStatus)}</Badge>
      </div>
    </div>
    <div className="rounded-lg border border-zinc-200 p-2.5 bg-white dark:border-zinc-800 dark:bg-zinc-900">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">3. Verify</p>
        <Badge variant={artifactStatusVariant(verifyStatus)} className="text-[10px]">{artifactStatusLabel(verifyStatus)}</Badge>
      </div>
    </div>
  </div>
);

export default PipelineStageCards;
