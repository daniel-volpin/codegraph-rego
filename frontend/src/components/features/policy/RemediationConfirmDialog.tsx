import * as DialogPrimitive from "@radix-ui/react-dialog";
import { AlertTriangle, Loader2, ShieldCheck, X } from "lucide-react";
import { Button } from "../../ui/button";
import { Badge } from "../../ui/badge";
import type { ConfidenceSurface, ViolationRow } from "./policyUtils";
import {
  confidenceBandLabel,
  confidenceBandVariant,
  remediationBadgeLabel,
  remediationBadgeVariant,
  severityVariant,
} from "./policyUtils";

interface RemediationConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  finding: ViolationRow | null;
  confidence: ConfidenceSurface;
  isSubmitting?: boolean;
}

export const RemediationConfirmDialog = ({
  open,
  onOpenChange,
  onConfirm,
  finding,
  confidence,
  isSubmitting = false,
}: RemediationConfirmDialogProps) => {
  if (!finding) return null;

  const scorePercent =
    confidence.score == null ? null : Math.round(Math.min(Math.max(confidence.score, 0), 1) * 100);

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-zinc-950/50 backdrop-blur-xs motion-safe:transition-opacity" />
        <DialogPrimitive.Content
          data-testid="remediation-confirm-modal"
          className="fixed left-1/2 top-1/2 z-50 w-full max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border border-zinc-200 bg-white p-6 shadow-xl focus:outline-hidden dark:border-zinc-800 dark:bg-zinc-900"
        >
          <div className="flex items-start justify-between gap-4 border-b border-zinc-200 pb-4 dark:border-zinc-800">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-100">
                <ShieldCheck aria-hidden="true" className="h-5 w-5" />
              </div>
              <div>
                <DialogPrimitive.Title className="text-base font-semibold text-zinc-900 dark:text-zinc-100">
                  Confirm Dry-Run Remediation
                </DialogPrimitive.Title>
                <DialogPrimitive.Description className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
                  Verify fix evaluates the patch against the virtual workspace without disk mutation.
                </DialogPrimitive.Description>
              </div>
            </div>
            <DialogPrimitive.Close className="rounded-md p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-zinc-500 dark:hover:bg-zinc-800 dark:hover:text-zinc-300">
              <X aria-hidden="true" className="h-4 w-4" />
              <span className="sr-only">Close confirmation dialog</span>
            </DialogPrimitive.Close>
          </div>

          <div className="space-y-4 py-4 text-xs">
            <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3.5 space-y-2 dark:border-zinc-800 dark:bg-zinc-950/40">
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge variant="secondary" className="text-[10px]">Rule {finding.ruleId}</Badge>
                <Badge variant={severityVariant(finding.severity)} className="text-[10px]">{finding.severity}</Badge>
                <Badge variant={remediationBadgeVariant(finding.remediation)} className="text-[10px]">
                  {remediationBadgeLabel(finding.remediation)}
                </Badge>
              </div>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Target method</p>
                <p className="mt-0.5 break-all font-mono text-xs font-medium text-zinc-900 dark:text-zinc-100">{finding.targetMethod}</p>
              </div>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Target file</p>
                <p className="mt-0.5 break-all font-mono text-xs text-zinc-600 dark:text-zinc-400">{finding.filePath}</p>
              </div>
            </div>

            <div className="flex items-center justify-between rounded-lg border border-zinc-200 p-3 bg-white dark:border-zinc-800 dark:bg-zinc-900">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">Confidence gate</p>
                <p className="mt-0.5 text-xs text-zinc-700 dark:text-zinc-300">
                  {scorePercent == null
                    ? "Confidence score pending preview/verification"
                    : `Score: ${scorePercent}% (Threshold: ${Math.round(confidence.thresholdApply * 100)}%)`}
                </p>
              </div>
              <Badge variant={confidenceBandVariant(confidence.band)} className="text-[10px]">
                {confidenceBandLabel(confidence.band)}
              </Badge>
            </div>

            <div className="flex items-start gap-2.5 rounded-lg border border-amber-200 bg-amber-50/70 p-3 text-xs text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200">
              <AlertTriangle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <div>
                <p className="font-semibold">Re-verification Workflow</p>
                <p className="mt-0.5 leading-relaxed">
                  This execution will run LLM fix generation, virtual patch application, build compilation, and OPA policy re-evaluation. The source files on disk remain untouched.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-end gap-2.5 border-t border-zinc-200 pt-4 dark:border-zinc-800">
            <DialogPrimitive.Close asChild>
              <Button type="button" variant="outline" size="sm" disabled={isSubmitting}>
                Cancel
              </Button>
            </DialogPrimitive.Close>
            <Button
              type="button"
              variant="default"
              size="sm"
              disabled={isSubmitting}
              onClick={() => {
                onConfirm();
                onOpenChange(false);
              }}
            >
              {isSubmitting ? (
                <>
                  <Loader2 aria-hidden="true" className="mr-1.5 h-4 w-4 animate-spin" /> Verifying…
                </>
              ) : (
                "Confirm & verify fix"
              )}
            </Button>
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
};

