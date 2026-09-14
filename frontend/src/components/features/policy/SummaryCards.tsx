import { Card } from "../../ui/card";
import { AlertCircle, Ban, Boxes, CheckCircle2, ShieldAlert, ShieldCheck } from "lucide-react";

interface SummaryCardsProps {
  findingCount: number;
  ruleCount: number;
  moduleCount: number;
  fullSupportCount: number;
  guardedSupportCount: number;
  manualCount: number;
}

const SummaryCards = ({
  findingCount,
  ruleCount,
  moduleCount,
  fullSupportCount,
  guardedSupportCount,
  manualCount,
}: SummaryCardsProps) => (
  <div className="grid gap-3 grid-cols-2 md:grid-cols-3 lg:grid-cols-6">
    <Card className="p-3.5 shadow-2xs border-zinc-200/80 dark:border-zinc-800 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xs">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Findings</p>
        <AlertCircle className="h-3.5 w-3.5 text-zinc-400" />
      </div>
      <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-zinc-900 dark:text-zinc-100">{findingCount}</p>
    </Card>
    <Card className="p-3.5 shadow-2xs border-zinc-200/80 dark:border-zinc-800 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xs">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Rules</p>
        <ShieldCheck className="h-3.5 w-3.5 text-zinc-400" />
      </div>
      <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-zinc-900 dark:text-zinc-100">{ruleCount}</p>
    </Card>
    <Card className="p-3.5 shadow-2xs border-zinc-200/80 dark:border-zinc-800 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xs">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Modules</p>
        <Boxes className="h-3.5 w-3.5 text-zinc-400" />
      </div>
      <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-zinc-900 dark:text-zinc-100">{moduleCount}</p>
    </Card>
    <Card className="p-3.5 shadow-2xs border-emerald-200/80 dark:border-emerald-900/60 bg-emerald-50/20 dark:bg-emerald-950/10 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xs">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-emerald-700 dark:text-emerald-400">Auto-fixable</p>
        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
      </div>
      <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-emerald-700 dark:text-emerald-400">{fullSupportCount}</p>
    </Card>
    <Card className="p-3.5 shadow-2xs border-amber-200/80 dark:border-amber-900/60 bg-amber-50/20 dark:bg-amber-950/10 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xs">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-400">Guarded fixes</p>
        <ShieldAlert className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
      </div>
      <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-amber-700 dark:text-amber-400">{guardedSupportCount}</p>
    </Card>
    <Card className="p-3.5 shadow-2xs border-zinc-200/80 dark:border-zinc-800 transition-all duration-200 hover:-translate-y-0.5 hover:shadow-xs">
      <div className="flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Manual only</p>
        <Ban className="h-3.5 w-3.5 text-zinc-400" />
      </div>
      <p className="mt-1.5 font-mono text-2xl font-semibold tabular-nums text-zinc-900 dark:text-zinc-100">{manualCount}</p>
    </Card>
  </div>
);

export default SummaryCards;
