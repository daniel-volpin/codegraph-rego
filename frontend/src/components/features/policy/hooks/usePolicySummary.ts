import { useMemo } from "react";
import type { ViolationRow } from "../policyUtils";

export interface PolicySummary {
  findingCount: number;
  ruleCount: number;
  moduleCount: number;
  fullSupportCount: number;
  guardedSupportCount: number;
  manualReviewCount: number;
}

export function usePolicySummary(
  filteredFindings: ViolationRow[],
  availableModules: string[],
  moduleFilter: string,
  ruleCount: number,
): PolicySummary {
  const visibleModules = useMemo(
    () => (moduleFilter === "all" ? availableModules : availableModules.includes(moduleFilter) ? [moduleFilter] : []),
    [availableModules, moduleFilter],
  );

  return useMemo(
    () => ({
      findingCount: filteredFindings.length,
      ruleCount,
      moduleCount: visibleModules.length,
      fullSupportCount: filteredFindings.filter((f) => f.remediation.support_tier === "full").length,
      guardedSupportCount: filteredFindings.filter((f) => f.remediation.support_tier === "guarded").length,
      manualReviewCount: filteredFindings.filter((f) => f.remediation.support_tier === "manual").length,
    }),
    [ruleCount, filteredFindings, visibleModules.length],
  );
}
