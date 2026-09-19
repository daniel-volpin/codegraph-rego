import type { RemediationApplyResponse, RemediationConfidence } from "../../../../lib/schemas";

export type ConfidenceBandLabel = "abstain" | "review" | "apply" | "pending";

export const confidenceBandVariant = (
  band: ConfidenceBandLabel,
): "destructive" | "warning" | "success" | "secondary" => {
  if (band === "apply") return "success";
  if (band === "review") return "warning";
  if (band === "abstain") return "destructive";
  return "secondary";
};

export const confidenceBandLabel = (band: ConfidenceBandLabel) => {
  if (band === "apply") return "Apply";
  if (band === "review") return "Review";
  if (band === "abstain") return "Abstain";
  return "Pending";
};

export interface ConfidenceSurface {
  score: number | null;
  band: ConfidenceBandLabel;
  thresholdApply: number;
  thresholdReview: number;
  rationale: string | null;
}

export const deriveConfidenceSurface = (
  confidence: RemediationConfidence | null | undefined,
): ConfidenceSurface => {
  const score = typeof confidence?.score === "number" ? confidence.score : null;
  const thresholdApply =
    typeof confidence?.threshold_apply === "number" ? confidence.threshold_apply : 0.75;
  const thresholdReview =
    typeof confidence?.threshold_review === "number" ? confidence.threshold_review : 0.5;

  const bandFromScore: ConfidenceBandLabel =
    score == null ? "pending"
    : score >= thresholdApply ? "apply"
    : score >= thresholdReview ? "review"
    : "abstain";

  const band =
    confidence?.band === "apply" || confidence?.band === "review" || confidence?.band === "abstain"
      ? confidence.band
      : bandFromScore;

  return {
    score,
    band,
    thresholdApply,
    thresholdReview,
    rationale: confidence?.rationale ?? null,
  };
};

export type RemediationOutcomeCategory =
  | "fully_verified"
  | "build_failed"
  | "policy_violated"
  | "no_fix"
  | "generation_error"
  | "verification_error"
  | "unknown";

export interface CategorizedApplyOutcome {
  category: RemediationOutcomeCategory;
  title: string;
  badgeLabel: string;
  badgeVariant: "success" | "destructive" | "warning" | "secondary";
  detailMessage: string;
}

export const categorizeApplyOutcome = (applyResult: RemediationApplyResponse): CategorizedApplyOutcome => {
  const isOk = applyResult.status === "OK";
  const verification = applyResult.verification;
  const compilation = applyResult.compilation;
  const generation = applyResult.generation;

  if (generation?.decision === "no_fix") {
    return {
      category: "no_fix",
      title: "Remediation Abstained (NO_FIX)",
      badgeLabel: "Abstained / No Fix",
      badgeVariant: "secondary",
      detailMessage: generation.reason || "The remediation engine concluded that no safe automated fix could be generated for this context.",
    };
  }

  if (!isOk) {
    if (applyResult.status === "GENERATION_ERROR" || generation?.raw_response_valid === false) {
      return {
        category: "generation_error",
        title: "Generation Error",
        badgeLabel: "Generation Error",
        badgeVariant: "destructive",
        detailMessage: applyResult.error || generation?.schema_error || "LLM patch generation payload failed schema validation.",
      };
    }
    return {
      category: "verification_error",
      title: "Verification Error",
      badgeLabel: "Verification Error",
      badgeVariant: "destructive",
      detailMessage: applyResult.error || `Verification attempt returned status ${applyResult.status}.`,
    };
  }

  if (compilation?.attempted && !compilation.success) {
    return {
      category: "build_failed",
      title: "Build Verification Failed",
      badgeLabel: "Build Failed",
      badgeVariant: "destructive",
      detailMessage: compilation.skipped_reason || applyResult.error || "Compilation of the proposed patch failed.",
    };
  }

  if (
    isOk &&
    verification?.overall_status === "PASS" &&
    verification?.target_rule_status === "PASS" &&
    (verification.remaining_violations?.length ?? 0) === 0 &&
    (verification.new_violations?.length ?? 0) === 0
  ) {
    return {
      category: "fully_verified",
      title: "Fix Fully Verified",
      badgeLabel: "Fully Verified",
      badgeVariant: "success",
      detailMessage: "Patch applied cleanly in dry-run mode, compilation succeeded, and 0 policy violations remain.",
    };
  }

  if (
    verification?.overall_status === "FAIL" ||
    verification?.target_rule_status === "FAIL" ||
    (verification?.remaining_violations?.length ?? 0) > 0 ||
    (verification?.new_violations?.length ?? 0) > 0
  ) {
    const remainingCount = verification?.remaining_violations?.length ?? 0;
    const newCount = verification?.new_violations?.length ?? 0;
    return {
      category: "policy_violated",
      title: "Policy Still Violated",
      badgeLabel: "Policy Check Failed",
      badgeVariant: "warning",
      detailMessage: `Re-verification reported ${remainingCount} remaining violation${remainingCount === 1 ? "" : "s"} and ${newCount} new violation${newCount === 1 ? "" : "s"}.`,
    };
  }

  return {
    category: "unknown",
    title: "Apply Outcome Unverified",
    badgeLabel: "Unverified Outcome",
    badgeVariant: "secondary",
    detailMessage: applyResult.error || "Apply response requires manual inspection.",
  };
};
