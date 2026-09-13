import { useEffect, useRef } from "react";
import {
  useIsMutating,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { toast } from "sonner";
import {
  applyRemediation,
  explainPolicyViolationOne,
  previewRemediation,
  runAgenticRemediation,
} from "../lib/api";
import {
  type AgenticRemediationResponse,
  type PolicyExplainOneResponse,
  type RemediationApplyResponse,
  type RemediationPreviewResponse,
} from "../lib/types";
import {
  type ViolationRow,
} from "../components/features/policy/policyUtils";

// Cache keys (one cache entry per violation, not per resource)

export const explainKey = (id: string) => ["policy", "explain", id] as const;
export const previewKey = (id: string) => ["policy", "preview", id] as const;
export const applyKey = (id: string) => ["policy", "apply", id] as const;
export const agenticKey = (id: string) => ["policy", "agentic", id] as const;

// Base mutation keys; the per-row id lives in mutation variables so
// `useIsMutating` can filter via predicate.
const EXPLAIN_MUTATION_KEY = ["policy", "explain"] as const;
const PREVIEW_MUTATION_KEY = ["policy", "preview"] as const;
const APPLY_MUTATION_KEY = ["policy", "apply"] as const;
const AGENTIC_MUTATION_KEY = ["policy", "agentic"] as const;

export type PendingAction = "explain" | "preview" | "apply" | "agentic";

// Sentinel mutationFn for read-only cache subscriptions. The queries are
// `enabled: false`; mutations are the only writers.
const cacheOnlyFn = () => Promise.reject(new Error("manual cache only"));

// Read hooks (per-row subscriptions; precise re-renders)

export function useExplainResult(id: string | null | undefined) {
  return useQuery<PolicyExplainOneResponse | undefined>({
    queryKey: explainKey(id ?? ""),
    queryFn: cacheOnlyFn,
    enabled: false,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  }).data;
}

export function usePreviewResult(id: string | null | undefined) {
  return useQuery<RemediationPreviewResponse | undefined>({
    queryKey: previewKey(id ?? ""),
    queryFn: cacheOnlyFn,
    enabled: false,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  }).data;
}

export function useApplyResult(id: string | null | undefined) {
  return useQuery<RemediationApplyResponse | undefined>({
    queryKey: applyKey(id ?? ""),
    queryFn: cacheOnlyFn,
    enabled: false,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  }).data;
}

export function useAgenticResult(id: string | null | undefined) {
  return useQuery<AgenticRemediationResponse | undefined>({
    queryKey: agenticKey(id ?? ""),
    queryFn: cacheOnlyFn,
    enabled: false,
    staleTime: Infinity,
    gcTime: 1000 * 60 * 60 * 6,
  }).data;
}

// Cross-component pending tracking. Resolves to the in-flight action for
// `id` regardless of which component triggered the mutation.
const matchesId = (id: string | null | undefined) => (m: { state: { variables: unknown } }) => {
  const v = m.state.variables as { id?: string } | undefined;
  return !!id && v?.id === id;
};

export function usePendingAction(id: string | null | undefined): PendingAction | undefined {
  const explaining = useIsMutating({ mutationKey: EXPLAIN_MUTATION_KEY, predicate: matchesId(id) });
  const previewing = useIsMutating({ mutationKey: PREVIEW_MUTATION_KEY, predicate: matchesId(id) });
  const applying = useIsMutating({ mutationKey: APPLY_MUTATION_KEY, predicate: matchesId(id) });
  const agentic = useIsMutating({ mutationKey: AGENTIC_MUTATION_KEY, predicate: matchesId(id) });
  if (!id) return undefined;
  if (explaining > 0) return "explain";
  if (previewing > 0) return "preview";
  if (applying > 0) return "apply";
  if (agentic > 0) return "agentic";
  return undefined;
}

// Mutation hooks with per-call AbortControllers

function useAbortOnUnmount() {
  const abortRef = useRef<AbortController | null>(null);
  useEffect(() => () => abortRef.current?.abort(), []);
  return abortRef;
}

export function useExplainMutation() {
  const qc = useQueryClient();
  const abortRef = useAbortOnUnmount();
  return useMutation({
    mutationKey: [...EXPLAIN_MUTATION_KEY],
    mutationFn: async (row: ViolationRow) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      return explainPolicyViolationOne(
        { violation: row.raw, include_graph_context: true },
        ctrl.signal,
      );
    },
    onSuccess: (data, row) => {
      qc.setQueryData(explainKey(row.id), data);
      const status = (data.status || "").toUpperCase();
      if (status === "OK" && data.explanation) {
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
    onError: (error: Error) => {
      if (error.name === "AbortError") return;
      toast.error(`Explain failed: ${error.message}`);
    },
  });
}

export function usePreviewMutation() {
  const qc = useQueryClient();
  const abortRef = useAbortOnUnmount();
  return useMutation({
    mutationKey: [...PREVIEW_MUTATION_KEY],
    mutationFn: async (row: ViolationRow) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      return previewRemediation(row.ruleId, row.methodKey, row.filePath, ctrl.signal);
    },
    onSuccess: (data, row) => {
      qc.setQueryData(previewKey(row.id), data);
      const status = (data.status || "").toUpperCase();
      if (status === "OK") toast.success(`Preview complete for ${row.ruleId}.`);
      else toast.error(data.error || `Preview failed (${status}) for ${row.ruleId}.`);
    },
    onError: (error: Error) => {
      if (error.name === "AbortError") return;
      toast.error(`Preview failed: ${error.message}`);
    },
  });
}

export function useApplyMutation() {
  const qc = useQueryClient();
  const abortRef = useAbortOnUnmount();
  return useMutation({
    mutationKey: [...APPLY_MUTATION_KEY],
    mutationFn: async (row: ViolationRow) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      return applyRemediation(
        { violation_id: row.ruleId, method_key: row.methodKey, file_path: row.filePath },
        ctrl.signal,
      );
    },
    onSuccess: (data, row) => {
      qc.setQueryData(applyKey(row.id), data);
      const status = (data.status || "").toUpperCase();
      if (status === "OK") toast.success(`Remediation applied for ${row.ruleId}.`);
      else toast.error(data.error || `Apply failed (${status}) for ${row.ruleId}.`);
    },
    onError: (error: Error) => {
      if (error.name === "AbortError") return;
      toast.error(`Apply failed: ${error.message}`);
    },
  });
}

export function useAgenticMutation() {
  const qc = useQueryClient();
  const abortRef = useAbortOnUnmount();
  return useMutation({
    mutationKey: [...AGENTIC_MUTATION_KEY],
    mutationFn: async (row: ViolationRow) => {
      abortRef.current?.abort();
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      return runAgenticRemediation(
        { finding: row.raw, max_turns: 8 },
        ctrl.signal,
      );
    },
    onSuccess: (data, row) => {
      qc.setQueryData(agenticKey(row.id), data);
      const status = (data.status || "").toUpperCase();
      if (status === "SUCCESS") {
        toast.success(`Autonomous agent successfully remediated ${row.ruleId}!`);
      } else if (status === "REFUSED") {
        toast.info(`Agent refused automatic fix: ${data.reason}`);
      } else {
        toast.error(data.error || `Agentic remediation failed (${status}) for ${row.ruleId}.`);
      }
    },
    onError: (error: Error) => {
      if (error.name === "AbortError") return;
      toast.error(`Agentic remediation error: ${error.message}`);
    },
  });
}

// Used at workspace boundaries (e.g. on a new upload) to evict all
// per-violation artifacts in one sweep.
export function useResetAllPolicyArtifacts() {
  const qc = useQueryClient();
  return () => {
    qc.removeQueries({ queryKey: ["policy", "explain"] });
    qc.removeQueries({ queryKey: ["policy", "preview"] });
    qc.removeQueries({ queryKey: ["policy", "apply"] });
    qc.removeQueries({ queryKey: ["policy", "agentic"] });
  };
}
