import { useMemo, useState } from "react";
import {
  AlertCircle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "../../ui/badge";
import { Button } from "../../ui/button";
import { Card } from "../../ui/card";
import { Input } from "../../ui/input";
import type { PolicyPackSpec } from "../../../lib/types";
import {
  deriveStandardFromRuleId,
  formatHumanRuleTitle,
  severityVariant,
  type ViolationRow,
} from "./policyUtils";

export interface StandardRulesCatalogViewProps {
  packs: PolicyPackSpec[];
  findings: ViolationRow[];
  selectedStandard: string;
  onSelectRuleInFindings: (ruleId: string) => void;
}

export const StandardRulesCatalogView = ({
  packs,
  findings,
  selectedStandard,
  onSelectRuleInFindings,
}: StandardRulesCatalogViewProps) => {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "failing" | "compliant">("all");

  // Flatten and normalize all rules across packs
  const allRulesWithStatus = useMemo(() => {
    // Collect findings count by ruleId and aliases
    const findingCountByRuleId: Record<string, number> = {};
    for (const f of findings) {
      const rid = f.ruleId;
      findingCountByRuleId[rid] = (findingCountByRuleId[rid] || 0) + 1;
    }

    const rulesList: Array<{
      id: string;
      title: string;
      control: string;
      standard: string;
      standardId: string;
      severity: string;
      summary: string;
      description: string;
      category: string;
      failingCount: number;
      isCompliant: boolean;
    }> = [];

    const seenRuleIds = new Set<string>();

    for (const pack of packs) {
      const stdId =
        pack.pack_id.includes("iso") ? "iso"
        : pack.pack_id.includes("pci") ? "pci"
        : pack.pack_id.includes("owasp") ? "owasp"
        : pack.pack_id.includes("nist") ? "nist"
        : "custom";

      for (const rule of pack.rules) {
        if (seenRuleIds.has(rule.id)) continue;
        seenRuleIds.add(rule.id);

        let failingCount = findingCountByRuleId[rule.id] || 0;
        for (const alias of rule.alias_ids || []) {
          failingCount += findingCountByRuleId[alias] || 0;
        }

        const title = formatHumanRuleTitle(rule.id, rule.title);
        const standard = deriveStandardFromRuleId(rule.id, pack.name);

        rulesList.push({
          id: rule.id,
          title,
          control: rule.control || rule.id,
          standard,
          standardId: stdId,
          severity: (rule.severity || "high").toUpperCase(),
          summary: rule.summary || "",
          description: rule.description || "",
          category: rule.category || "Security",
          failingCount,
          isCompliant: failingCount === 0,
        });
      }
    }

    return rulesList;
  }, [findings, packs]);

  // Filter rules by standard, search query, and compliance status
  const filteredRules = useMemo(() => {
    return allRulesWithStatus.filter((rule) => {
      if (selectedStandard !== "all") {
        if (rule.standardId !== selectedStandard && !rule.id.toLowerCase().includes(selectedStandard)) {
          return false;
        }
      }

      if (statusFilter === "failing" && rule.isCompliant) return false;
      if (statusFilter === "compliant" && !rule.isCompliant) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matches =
          rule.id.toLowerCase().includes(q) ||
          rule.title.toLowerCase().includes(q) ||
          rule.control.toLowerCase().includes(q) ||
          rule.summary.toLowerCase().includes(q) ||
          rule.description.toLowerCase().includes(q) ||
          rule.category.toLowerCase().includes(q);
        if (!matches) return false;
      }

      return true;
    });
  }, [allRulesWithStatus, searchQuery, selectedStandard, statusFilter]);

  const totalRulesCount = allRulesWithStatus.length;
  const failingRulesCount = allRulesWithStatus.filter((r) => !r.isCompliant).length;
  const compliantRulesCount = allRulesWithStatus.filter((r) => r.isCompliant).length;

  return (
    <div className="space-y-4" data-testid="standard-rules-catalog-view">
      {/* Controls Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-zinc-200/80 bg-white p-3 shadow-2xs dark:border-zinc-800 dark:bg-zinc-900">
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-400" />
          <Input
            type="text"
            placeholder="Search standard rules by name, control, or category…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs bg-zinc-50 dark:bg-zinc-800/60"
          />
        </div>

        {/* Status Filter Pills */}
        <div className="flex items-center gap-1.5 text-xs">
          <Button
            variant={statusFilter === "all" ? "default" : "outline"}
            size="sm"
            className="h-8 text-xs font-medium"
            onClick={() => setStatusFilter("all")}
          >
            All Rules ({totalRulesCount})
          </Button>
          <Button
            variant={statusFilter === "failing" ? "default" : "outline"}
            size="sm"
            className={`h-8 text-xs font-medium ${statusFilter === "failing" ? "bg-rose-600 hover:bg-rose-700 text-white" : "text-rose-700 dark:text-rose-400"}`}
            onClick={() => setStatusFilter("failing")}
          >
            <ShieldAlert className="mr-1 h-3.5 w-3.5" />
            Failing ({failingRulesCount})
          </Button>
          <Button
            variant={statusFilter === "compliant" ? "default" : "outline"}
            size="sm"
            className={`h-8 text-xs font-medium ${statusFilter === "compliant" ? "bg-emerald-600 hover:bg-emerald-700 text-white" : "text-emerald-700 dark:text-emerald-400"}`}
            onClick={() => setStatusFilter("compliant")}
          >
            <ShieldCheck className="mr-1 h-3.5 w-3.5" />
            Compliant ({compliantRulesCount})
          </Button>
        </div>
      </div>

      {/* Rules Grid / List */}
      <div className="grid gap-3.5 sm:grid-cols-1 md:grid-cols-2 xl:grid-cols-3">
        {filteredRules.map((rule) => (
          <Card
            key={rule.id}
            className={`p-4 flex flex-col justify-between transition-all hover:shadow-xs border rounded-xl min-w-0 ${
              rule.isCompliant
                ? "border-zinc-200/80 bg-white dark:border-zinc-800 dark:bg-zinc-900"
                : "border-rose-200/80 bg-rose-50/20 dark:border-rose-900/40 dark:bg-rose-950/10"
            }`}
          >
            <div className="space-y-3 min-w-0">
              {/* Header Badges */}
              <div className="flex items-center justify-between gap-2 border-b border-zinc-100 pb-2.5 dark:border-zinc-800">
                <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                  <Badge variant="secondary" className="text-[10px] font-medium h-5 px-1.5">
                    {rule.control}
                  </Badge>
                  <Badge variant={severityVariant(rule.severity)} className="text-[10px] h-5 px-1.5">
                    {rule.severity}
                  </Badge>
                  {rule.category && (
                    <Badge variant="outline" className="text-[10px] text-zinc-500 h-5 px-1.5">
                      {rule.category}
                    </Badge>
                  )}
                </div>

                {rule.isCompliant ? (
                  <Badge variant="success" className="text-[10px] h-5 px-1.5 shrink-0 flex items-center gap-1">
                    <CheckCircle2 className="h-3 w-3" /> Compliant
                  </Badge>
                ) : (
                  <Badge variant="destructive" className="text-[10px] h-5 px-1.5 shrink-0 flex items-center gap-1">
                    <AlertCircle className="h-3 w-3" /> {rule.failingCount} finding{rule.failingCount === 1 ? "" : "s"}
                  </Badge>
                )}
              </div>

              {/* Title & Rule ID */}
              <div className="min-w-0">
                <h3 className="font-semibold text-sm text-zinc-900 dark:text-zinc-100 leading-snug">
                  {rule.title}
                </h3>
                <p className="mt-0.5 font-mono text-[11px] text-zinc-400 dark:text-zinc-500 truncate select-all">
                  {rule.id}
                </p>
              </div>

              {/* Description & Summary */}
              <p className="text-xs text-zinc-600 dark:text-zinc-400 line-clamp-2 leading-relaxed">
                {rule.summary || rule.description}
              </p>
            </div>

            {/* Bottom Footer Action */}
            <div className="mt-4 pt-3 border-t border-zinc-100 dark:border-zinc-800 flex items-center justify-between gap-2 min-w-0">
              <Badge variant="outline" className="text-[10px] text-zinc-600 dark:text-zinc-400 font-medium shrink-0">
                {deriveStandardFromRuleId(rule.id)}
              </Badge>

              {!rule.isCompliant ? (
                <Button
                  variant="default"
                  size="sm"
                  className="h-8 px-3 text-xs bg-rose-600 hover:bg-rose-700 text-white font-medium shrink-0 whitespace-nowrap rounded-lg flex items-center gap-1.5 shadow-2xs"
                  onClick={() => onSelectRuleInFindings(rule.id)}
                >
                  <span>Triage {rule.failingCount} {rule.failingCount === 1 ? "Finding" : "Findings"}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              ) : (
                <span className="text-xs text-emerald-600 dark:text-emerald-400 font-medium flex items-center gap-1 shrink-0 whitespace-nowrap">
                  <CheckCircle2 className="h-3.5 w-3.5" /> 0 Violations
                </span>
              )}
            </div>
          </Card>
        ))}
      </div>

      {filteredRules.length === 0 && (
        <Card className="py-12 text-center p-6 border-zinc-200 dark:border-zinc-800">
          <BookOpen className="mx-auto h-8 w-8 text-zinc-400" />
          <p className="mt-3 text-sm font-semibold text-zinc-800 dark:text-zinc-200">No policy rules matched your criteria</p>
          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            Try adjusting your search query or standard filters above.
          </p>
        </Card>
      )}
    </div>
  );
};

export default StandardRulesCatalogView;
