import { useRef, useState } from "react";
import { toast } from "sonner";
import { exportPolicySarif, importSarifReport } from "../lib/api";
import { downloadSarifFile } from "../lib/sarif";
import type { PolicyEvaluateResponse } from "../lib/types";

/**
 * Owns SARIF export/import state and side effects for the Policy page. The
 * caller supplies the current evaluation data and a setter so this hook
 * doesn't need to know how that data is cached.
 */
export function useSarifActions(evalData: PolicyEvaluateResponse | undefined, setEvalData: (data: PolicyEvaluateResponse) => void) {
  const [isExportingSarif, setIsExportingSarif] = useState<boolean>(false);
  const [isImportingSarif, setIsImportingSarif] = useState<boolean>(false);
  const sarifFileInputRef = useRef<HTMLInputElement>(null);

  const handleExportSarif = async () => {
    try {
      setIsExportingSarif(true);
      const doc = await exportPolicySarif();
      const filename = "codegraph-full-findings.sarif.json";
      const ok = downloadSarifFile(doc, filename);
      if (ok) {
        toast.success("SARIF v2.1.0 report exported.");
      } else {
        toast.error("Could not trigger file download.");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "SARIF export failed";
      toast.error(`SARIF export failed: ${msg}`);
    } finally {
      setIsExportingSarif(false);
    }
  };

  const handleImportSarifClick = () => {
    sarifFileInputRef.current?.click();
  };

  const handleSarifFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setIsImportingSarif(true);
    try {
      const text = await file.text();
      const res = await importSarifReport(text);
      if (res.count > 0) {
        toast.success(`Imported ${res.count} findings from SAST SARIF report.`);
        const existingData = evalData ?? {
          violations: [],
          catalog: [],
          rules_catalog: {},
          opa_runs: 1,
          bundle_count: 1,
          evaluation: {
            status: "complete",
            attempted_bundles: 1,
            evaluated_bundles: 1,
            failed_bundles: 0,
            omitted_findings: 0,
            excluded_findings: 0,
            truncated: false,
            scope_limited: false,
            rule_ids: [],
          },
        };

        const existingViolations = existingData.violations ?? [];
        const existingKeys = new Set(existingViolations.map((v) => `${v.violation_id ?? v.rule_id}:${v.method_key}`));
        const newViolations = res.violations.filter(
          (v) => !existingKeys.has(`${v.violation_id ?? v.rule_id}:${v.method_key}`),
        );

        setEvalData({
          ...existingData,
          violations: [...existingViolations, ...newViolations],
        });
      } else {
        toast.info("No findings found in the imported SARIF report.");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "SARIF import failed";
      toast.error(`SARIF import failed: ${msg}`);
    } finally {
      setIsImportingSarif(false);
      if (event.target) {
        event.target.value = "";
      }
    }
  };

  return {
    isExportingSarif,
    isImportingSarif,
    sarifFileInputRef,
    handleExportSarif,
    handleImportSarifClick,
    handleSarifFileChange,
  };
}
