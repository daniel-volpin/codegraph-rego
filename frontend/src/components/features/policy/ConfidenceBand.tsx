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
    <div className="rounded-lg border border-slate-200 bg-white p-3" data-testid="confidence-band">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{title}</p>
          <p className="mt-1 text-sm text-slate-700">
            {scorePercent == null
              ? "Confidence score will appear after preview or verification completes."
              : `Score ${scorePercent}% against thesis review/apply thresholds.`}
          </p>
        </div>
        <Badge variant={confidenceBandVariant(confidence.band)}>
          {confidenceBandLabel(confidence.band)}
        </Badge>
      </div>

      <div className="mt-3 space-y-2">
        <div className="relative h-2 overflow-hidden rounded-full bg-slate-100">
          <div
            className={`h-full rounded-full transition-all ${
              confidence.band === "apply"
                ? "bg-emerald-500"
                : confidence.band === "review"
                  ? "bg-amber-500"
                  : confidence.band === "abstain"
                    ? "bg-rose-500"
                    : "bg-slate-300"
            }`}
            style={{ width: `${fillPercent}%` }}
          />
          <span
            aria-hidden="true"
            className="absolute inset-y-0 w-px bg-amber-700/60"
            style={{ left: `${reviewPercent}%` }}
          />
          <span
            aria-hidden="true"
            className="absolute inset-y-0 w-px bg-emerald-700/70"
            style={{ left: `${applyPercent}%` }}
          />
        </div>
        <div className="flex items-center justify-between text-[11px] text-slate-500">
          <span>Abstain</span>
          <span>Review {reviewPercent}%</span>
          <span>Apply {applyPercent}%</span>
        </div>
        {confidence.rationale && (
          <p className="text-xs text-slate-500">{confidence.rationale}</p>
        )}
      </div>
    </div>
  );
};

export default ConfidenceBand;
