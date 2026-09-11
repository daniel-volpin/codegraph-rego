import { Badge } from "../../ui/badge";
import {
  confidenceBandLabel,
  confidenceBandVariant,
  type ConfidenceSurface,
} from "./policyUtils";

interface ConfidenceBandProps {
  confidence: ConfidenceSurface;
  title?: string;
}

const ConfidenceBand = ({ confidence, title = "Confidence gate" }: ConfidenceBandProps) => {
  const scorePercent =
    confidence.score == null ? null : Math.round(Math.min(Math.max(confidence.score, 0), 1) * 100);
  const applyPercent = Math.round(confidence.thresholdApply * 100);
  const reviewPercent = Math.round(confidence.thresholdReview * 100);
  const fillPercent = scorePercent ?? 0;

  return (
    <div className="rounded-lg border border-zinc-200 bg-white p-3.5 shadow-2xs dark:border-zinc-800 dark:bg-zinc-900" data-testid="confidence-band">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">{title}</p>
          <p className="mt-0.5 text-xs text-zinc-700 dark:text-zinc-300">
            {scorePercent == null
              ? "Confidence score will appear after preview or verification completes."
              : `Score ${scorePercent}% against thesis review/apply thresholds.`}
          </p>
        </div>
        <Badge variant={confidenceBandVariant(confidence.band)} className="text-[10px]">
          {confidenceBandLabel(confidence.band)}
        </Badge>
      </div>

      <div className="mt-3 space-y-2">
        <div className="relative h-2 overflow-hidden rounded-full bg-zinc-100 dark:bg-zinc-800">
          <div
            className={`h-full rounded-full transition-all ${
              confidence.band === "apply"
                ? "bg-emerald-500"
                : confidence.band === "review"
                  ? "bg-amber-500"
                  : confidence.band === "abstain"
                    ? "bg-rose-500"
                    : "bg-zinc-300 dark:bg-zinc-700"
            }`}
            style={{ width: `${fillPercent}%` }}
          />
          <span
            aria-hidden="true"
            className="absolute inset-y-0 w-px bg-amber-600/70"
            style={{ left: `${reviewPercent}%` }}
          />
          <span
            aria-hidden="true"
            className="absolute inset-y-0 w-px bg-emerald-600/80"
            style={{ left: `${applyPercent}%` }}
          />
        </div>
        <div className="flex items-center justify-between text-[10px] font-medium text-zinc-500 dark:text-zinc-400 font-mono">
          <span>Abstain</span>
          <span>Review {reviewPercent}%</span>
          <span>Apply {applyPercent}%</span>
        </div>
        {confidence.rationale && (
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">{confidence.rationale}</p>
        )}
      </div>
    </div>
  );
};

export default ConfidenceBand;

