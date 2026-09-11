import { AlertTriangle, CheckCircle2, ChevronRight, Loader2 } from "lucide-react";
import { Card } from "../../ui/card";

export interface EvaluationStatusCardProps {
  isFetching: boolean;
  hasEvaluationResult: boolean;
  findingCount: number;
  totalFindingCount: number;
  ruleCount: number;
  errorMessage: string | null;
  responseIsPartial: boolean;
}

export const EvaluationStatusCard = ({
  isFetching,
  hasEvaluationResult,
  findingCount,
  totalFindingCount,
  ruleCount,
  errorMessage,
  responseIsPartial,
}: EvaluationStatusCardProps) => {
  if (errorMessage) return null;

  const status =
    isFetching ? "running"
    : responseIsPartial ? "partial"
    : hasEvaluationResult && totalFindingCount === 0 ? "empty"
    : hasEvaluationResult ? "findings"
    : "initial";

  const config = {
    running: {
      icon: <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin text-zinc-700 dark:text-zinc-300" />,
      title: "Policy evaluation is running.",
      body: "The backend is evaluating the current workspace. Findings will appear when the response is validated.",
      tone: "border-zinc-300 bg-zinc-50 text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100",
    },
    partial: {
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-600 dark:text-amber-400" />,
      title: "Evaluation response is partial.",
      body: "Some bundles failed, the scan scope or findings were limited, or completeness metadata is missing. Review the available evidence and rerun without limits before treating this as a complete workspace scan.",
      tone: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200",
    },
    empty: {
      icon: <CheckCircle2 aria-hidden="true" className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />,
      title: "Evaluation completed successfully.",
      body: "Zero findings were returned. This means the policy engine evaluated the current workspace and did not report violations for the selected scope.",
      tone: "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900/60 dark:bg-emerald-950/30 dark:text-emerald-200",
    },
    findings: {
      icon: <AlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-600 dark:text-amber-400" />,
      title: "Evaluation completed with findings.",
      body: `${findingCount} visible finding${findingCount === 1 ? "" : "s"} across ${ruleCount} rule group${ruleCount === 1 ? "" : "s"}. Use the table and case dossier for evidence, explanation, and remediation availability.`,
      tone: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200",
    },
    initial: {
      icon: <ChevronRight aria-hidden="true" className="h-4 w-4 text-zinc-400" />,
      title: "Policy evaluation has not run yet.",
      body: "Run a policy scan to evaluate the uploaded workspace. A zero finding result will be shown separately after a successful backend response.",
      tone: "border-zinc-200 bg-zinc-50/70 text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900/40 dark:text-zinc-300",
    },
  }[status];

  return (
    <Card
      role="status"
      aria-label="Policy evaluation status"
      aria-live={isFetching ? "polite" : "off"}
      className={`p-3.5 text-xs shadow-2xs ${config.tone}`}
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0">{config.icon}</div>
        <div>
          <p className="font-semibold text-xs">{config.title}</p>
          <p className="mt-0.5 leading-relaxed">{config.body}</p>
        </div>
      </div>
    </Card>
  );
};

export default EvaluationStatusCard;
