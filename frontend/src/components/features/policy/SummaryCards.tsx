import { Card } from "../../ui/card";

interface SummaryCardsProps {
  findingCount: number;
  ruleCount: number;
  moduleCount: number;
  fullSupportCount: number;
  guardedSupportCount: number;
  manualReviewCount: number;
}

const SummaryCards = ({
  findingCount,
  ruleCount,
  moduleCount,
  fullSupportCount,
  guardedSupportCount,
  manualReviewCount,
}: SummaryCardsProps) => (
  <div className="grid gap-3 md:grid-cols-6">
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Findings</p>
      <p className="mt-2 text-2xl font-semibold text-slate-900">{findingCount}</p>
    </Card>
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Rules</p>
      <p className="mt-2 text-2xl font-semibold text-slate-900">{ruleCount}</p>
    </Card>
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Modules</p>
      <p className="mt-2 text-2xl font-semibold text-slate-900">{moduleCount}</p>
    </Card>
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Auto-fixable</p>
      <p className="mt-2 text-2xl font-semibold text-emerald-700">{fullSupportCount}</p>
    </Card>
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Guarded fixes</p>
      <p className="mt-2 text-2xl font-semibold text-amber-700">{guardedSupportCount}</p>
    </Card>
    <Card className="p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Manual review</p>
      <p className="mt-2 text-2xl font-semibold text-slate-900">{manualReviewCount}</p>
    </Card>
  </div>
);

export default SummaryCards;
