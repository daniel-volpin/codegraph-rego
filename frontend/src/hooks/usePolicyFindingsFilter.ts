import { useMemo, useState } from "react";
import { uniqueSortedModuleLabels } from "../lib/workspace";
import { groupViolationsByRule, type ViolationRow } from "../components/features/policy/policyUtils";

/**
 * Owns the module/standard/search filter state for the Policy findings view
 * and every value derived from applying those filters to the raw findings.
 */
export function usePolicyFindingsFilter(
  findings: ViolationRow[],
  uploadedModules: string[],
  options: { hasEvaluationResult: boolean; evaluationError: string | null; responseIsPartial: boolean },
) {
  const [moduleFilter, setModuleFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedStandard, setSelectedStandard] = useState<string>("all");

  const availableModules = useMemo(
    () => uniqueSortedModuleLabels([...uploadedModules, ...findings.map((f) => f.filePath)]),
    [findings, uploadedModules],
  );

  const effectiveModuleFilter =
    moduleFilter === "all" || availableModules.includes(moduleFilter) ? moduleFilter : "all";

  const standardCounts = useMemo(() => {
    const base = effectiveModuleFilter === "all" ? findings : findings.filter((f) => f.module === effectiveModuleFilter);
    const countFor = (stdId: string) => {
      if (stdId === "all") return base.length;
      if (stdId === "sarif") return base.filter((f) => f.raw.evidence?.imported_from_sarif).length;
      return base.filter((f) => {
        const rule = (f.ruleId || "").toLowerCase();
        const std = stdId.toLowerCase();
        const rawMeta = (f.raw.control_metadata || {}) as Record<string, unknown>;
        const rawStd = String(rawMeta.standard || "").toLowerCase();
        return rule.includes(std) || rawStd.includes(std);
      }).length;
    };
    return {
      all: countFor("all"),
      iso: countFor("iso"),
      pci: countFor("pci"),
      owasp: countFor("owasp"),
      nist: countFor("nist"),
      sarif: countFor("sarif"),
    };
  }, [effectiveModuleFilter, findings]);

  const filteredFindings = useMemo(() => {
    let list = findings;
    if (effectiveModuleFilter !== "all") {
      list = list.filter((f) => f.module === effectiveModuleFilter);
    }
    if (selectedStandard !== "all") {
      if (selectedStandard === "sarif") {
        list = list.filter((f) => f.raw.evidence?.imported_from_sarif);
      } else {
        list = list.filter((f) => {
          const rule = (f.ruleId || "").toLowerCase();
          const std = selectedStandard.toLowerCase();
          const rawMeta = (f.raw.control_metadata || {}) as Record<string, unknown>;
          const rawStd = String(rawMeta.standard || "").toLowerCase();
          return rule.includes(std) || rawStd.includes(std);
        });
      }
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      list = list.filter(
        (f) =>
          f.ruleId.toLowerCase().includes(q) ||
          f.targetMethod.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q) ||
          f.reason.toLowerCase().includes(q) ||
          f.controlLabel.toLowerCase().includes(q) ||
          f.cweLabel.toLowerCase().includes(q),
      );
    }
    return list;
  }, [effectiveModuleFilter, findings, searchQuery, selectedStandard]);

  const visibleModules = useMemo(
    () =>
      effectiveModuleFilter === "all"
        ? availableModules
        : availableModules.includes(effectiveModuleFilter)
          ? [effectiveModuleFilter]
          : [],
    [availableModules, effectiveModuleFilter],
  );

  const data = useMemo(() => groupViolationsByRule(filteredFindings), [filteredFindings]);

  const summary = useMemo(
    () => ({
      findingCount: filteredFindings.length,
      ruleCount: data.length,
      moduleCount: visibleModules.length,
      fullSupportCount: filteredFindings.filter((f) => f.remediation.support_tier === "full").length,
      guardedSupportCount: filteredFindings.filter((f) => f.remediation.support_tier === "guarded").length,
      manualCount: filteredFindings.filter((f) => f.remediation.support_tier === "manual").length,
    }),
    [data.length, filteredFindings, visibleModules.length],
  );

  const { hasEvaluationResult, evaluationError, responseIsPartial } = options;
  const tableEmptyMessage =
    !hasEvaluationResult
      ? "No policy evaluation has run yet. Run a scan to see rule groups."
      : responseIsPartial || evaluationError
        ? "No findings are available from this incomplete evaluation."
      : findings.length === 0
        ? "Evaluation completed successfully with zero findings for the selected scope."
        : "No findings match the current module filter.";

  return {
    moduleFilter: effectiveModuleFilter,
    setModuleFilter,
    searchQuery,
    setSearchQuery,
    selectedStandard,
    setSelectedStandard,
    availableModules,
    standardCounts,
    filteredFindings,
    visibleModules,
    data,
    summary,
    tableEmptyMessage,
  };
}
