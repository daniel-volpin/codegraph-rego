import type { SarifExportResponse } from "./types";

export interface SarifSummaryStats {
  ruleCount: number;
  resultCount: number;
  runCount: number;
}

/**
 * Summarize findings and rules from an OASIS SARIF v2.1.0 document.
 */
export function summarizeSarif(sarif: SarifExportResponse): SarifSummaryStats {
  const runs = sarif.runs ?? [];
  let ruleCount = 0;
  let resultCount = 0;

  for (const run of runs) {
    const rules = (run.tool as { driver?: { rules?: unknown[] } } | undefined)?.driver?.rules;
    if (Array.isArray(rules)) {
      ruleCount += rules.length;
    }
    const results = run.results;
    if (Array.isArray(results)) {
      resultCount += results.length;
    }
  }

  return {
    ruleCount,
    resultCount,
    runCount: runs.length,
  };
}

/**
 * Triggers a browser file download of a SARIF v2.1.0 JSON report.
 */
export function downloadSarifFile(
  data: unknown,
  filename = "codegraph-findings.sarif.json",
): boolean {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return false;
  }

  try {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/sarif+json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    return true;
  } catch {
    return false;
  }
}
