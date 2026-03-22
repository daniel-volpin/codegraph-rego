import { useCallback, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { applyRemediation, explainPolicyViolationOne, previewRemediation } from "../../../../lib/api";
import type {
  PendingAction,
  PolicyExplainOneResponse,
  RawViolation,
  RemediationApplyResponse,
  RemediationPreviewResponse,
  ViolationRow,
} from "../policyUtils";
import { normalizeViolation } from "../policyUtils";

export interface UsePolicyMutationsReturn {
  explainMutation: ReturnType<typeof useMutation<PolicyExplainOneResponse, Error, RawViolation>>;
  previewMutation: ReturnType<typeof useMutation<RemediationPreviewResponse, Error, ViolationRow>>;
  applyMutation: ReturnType<typeof useMutation<RemediationApplyResponse, Error, ViolationRow>>;
  pendingAction: Record<string, PendingAction>;
  markPending: (id: string, action: PendingAction) => void;
  clearPending: (id: string) => void;
}

export function usePolicyMutations(): UsePolicyMutationsReturn {
  const queryClient = useQueryClient();
  const [pendingAction, setPendingAction] = useState<Record<string, PendingAction>>({});

  const markPending = useCallback((id: string, action: PendingAction) => {
    setPendingAction((prev) => ({ ...prev, [id]: action }));
  }, []);

  const clearPending = useCallback((id: string) => {
    setPendingAction((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }, []);

  const explainMutation = useMutation({
    mutationFn: (violation: RawViolation) =>
      explainPolicyViolationOne({ violation, include_graph_context: true }),
    onMutate: (violation) => {
      const row = normalizeViolation(violation);
      markPending(row.id, "explain");
    },
    onSuccess: (data, violation) => {
      const row = normalizeViolation(violation);
      queryClient.setQueryData<Record<string, PolicyExplainOneResponse>>(
        ["policy:explainById"],
        (prev) => ({ ...(prev ?? {}), [row.id]: data }),
      );
      if ((data.status || "").toUpperCase() === "OK" && data.explanation) {
        toast.success("LLM explanation ready.");
        return;
      }
      const msg =
        data.error ||
        (typeof data.explanation === "string" && data.explanation.startsWith("[LLM unavailable:")
          ? "LLM is unavailable. Start your local server (e.g. LM Studio) or configure the LLM provider."
          : "LLM explanation unavailable.");
      toast.error(msg);
    },
    onSettled: (_d, _e, violation) => {
      const row = normalizeViolation(violation);
      clearPending(row.id);
    },
    onError: (error: Error) => toast.error(`Explain failed: ${error.message}`),
  });

  const previewMutation = useMutation({
    mutationFn: (row: ViolationRow) => previewRemediation(row.ruleId, row.targetMethod, row.filePath),
    onMutate: (row) => markPending(row.id, "preview"),
    onSuccess: (data, row) => {
      queryClient.setQueryData<Record<string, RemediationPreviewResponse>>(
        ["policy:previewById"],
        (prev) => ({ ...(prev ?? {}), [row.id]: data }),
      );
      const status = (data.status || "").toUpperCase();
      if (status === "OK") {
        toast.success(`Preview complete for ${row.ruleId}.`);
      } else {
        toast.error(data.error || `Preview failed (${status}) for ${row.ruleId}.`);
      }
    },
    onSettled: (_d, _e, row) => clearPending(row.id),
    onError: (error: Error) => toast.error(`Preview failed: ${error.message}`),
  });

  const applyMutation = useMutation({
    mutationFn: (row: ViolationRow) =>
      applyRemediation({ violation_id: row.ruleId, target_method: row.targetMethod, file_path: row.filePath }),
    onMutate: (row) => markPending(row.id, "apply"),
    onSuccess: (data, row) => {
      queryClient.setQueryData<Record<string, RemediationApplyResponse>>(
        ["policy:applyById"],
        (prev) => ({ ...(prev ?? {}), [row.id]: data }),
      );
      const status = (data.status || "").toUpperCase();
      if (status === "OK") {
        toast.success(`Remediation applied for ${row.ruleId}.`);
      } else {
        toast.error(data.error || `Apply failed (${status}) for ${row.ruleId}.`);
      }
    },
    onSettled: (_d, _e, row) => clearPending(row.id),
    onError: (error: Error) => toast.error(`Apply failed: ${error.message}`),
  });

  return { explainMutation, previewMutation, applyMutation, pendingAction, markPending, clearPending };
}
