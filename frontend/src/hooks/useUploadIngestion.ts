import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { fetchUploadStatus, ingestFromGitUrl, uploadZip } from "../lib/api";
import type { UploadResponse, UploadStatus } from "../lib/types";
import { useClearActivity, useUpsertActivity } from "../store/activity";
import { useResetAllPolicyArtifacts } from "./usePolicyArtifacts";
import { useUploadStatusStream } from "./useUploadStatusStream";
import { clearPersistedPolicyEvaluations, persistLastUpload, readPersistedLastUpload } from "../lib/persistence";
import { uniqueSortedModuleLabels } from "../lib/workspace";

/**
 * Owns the upload/ingest workflow: source selection, the upload and git-clone
 * mutations, SSE/polling status tracking, activity-store sync, and result
 * persistence. Drag-and-drop UI state stays with the page — it's presentation,
 * not ingestion.
 */
export function useUploadIngestion() {
  const queryClient = useQueryClient();
  const refetchStatusRef = useRef<(() => void) | null>(null);
  const [sourceMode, setSourceMode] = useState<"zip" | "git">("zip");
  const [repoUrl, setRepoUrl] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [localStatus, setLocalStatus] = useState<UploadStatus | null>(null);
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null);
  const upsertActivity = useUpsertActivity();
  const clearActivity = useClearActivity();
  const resetPolicyArtifacts = useResetAllPolicyArtifacts();

  const handleIngestSuccess = (data: UploadResponse) => {
    setResult(data);
    if (data.error || data.status === "error") {
      toast.error(`Upload failed: ${data.error ?? "Unknown error."}`);
      return;
    }
    toast.success("Upload complete! Embeddings rebuilt.");
    void persistLastUpload(data);
    queryClient.removeQueries({ queryKey: ["policyEvaluation:last"] });
    resetPolicyArtifacts();
    void clearPersistedPolicyEvaluations();
  };

  const handleIngestError = (error: Error) => {
    setResult({ status: "error", error: error.message });
    toast.error(`Upload failed: ${error.message}`);
  };

  const handleIngestSettled = () => {
    refetchStatusRef.current?.();
  };

  const uploadMutation = useMutation({
    mutationFn: ({ file, requestId }: { file: File; requestId: string }) => uploadZip(file, undefined, requestId),
    onSuccess: handleIngestSuccess,
    onError: handleIngestError,
    onSettled: handleIngestSettled,
  });

  const gitMutation = useMutation({
    mutationFn: ({ url, requestId }: { url: string; requestId: string }) =>
      ingestFromGitUrl(url, undefined, undefined, requestId),
    onSuccess: handleIngestSuccess,
    onError: handleIngestError,
    onSettled: handleIngestSettled,
  });

  const trackedRequestId = activeRequestId ?? result?.request_id ?? null;
  const { streamConnected } = useUploadStatusStream(trackedRequestId);
  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ["uploadStatus", trackedRequestId],
    queryFn: ({ signal }) => fetchUploadStatus(trackedRequestId, signal),
    staleTime: 0,
    refetchInterval: (query) => {
      const nextStatus = query.state.data as UploadStatus | undefined;
      const activeStatus = nextStatus ?? localStatus;
      const shouldTrack =
        uploadMutation.isPending || gitMutation.isPending || Boolean(activeStatus && !activeStatus.complete);
      if (!shouldTrack) return false;
      return streamConnected ? false : 5000;
    },
  });

  const status = statusData ?? localStatus;

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const persisted = await readPersistedLastUpload();
      if (!cancelled && persisted) {
        setResult((current) => current ?? persisted);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    refetchStatusRef.current = refetchStatus;
  }, [refetchStatus]);

  useEffect(() => {
    if (!status) {
      return;
    }
    const activityStatus = status.error
      ? "error"
      : status.phase === "idle"
        ? "idle"
      : status.complete
        ? "success"
        : "running";
    upsertActivity({
      key: "upload",
      label: "Upload & Ingestion",
      status: activityStatus,
      message: status.message,
      progress: status.progress,
      updatedAt: status.updated_at,
    });
  }, [status, upsertActivity]);

  useEffect(() => {
    return () => {
      clearActivity("upload");
    };
  }, [clearActivity]);

  const acceptFile = (file: File | null | undefined) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setSelectedFile(null);
      toast.error(`"${file.name}" is not a ZIP archive. Select a .zip file.`);
      return;
    }
    setSelectedFile(file);
  };

  const handleGitSubmit = () => {
    const url = repoUrl.trim();
    if (!url) {
      const feedback: UploadResponse = { status: "error", error: "Enter a repository URL." };
      setResult(feedback);
      toast.error(feedback.error ?? "Enter a repository URL.");
      return;
    }
    const requestId = crypto.randomUUID().replace(/-/g, "");
    setActiveRequestId(requestId);
    setResult(null);
    setLocalStatus({
      phase: "upload",
      message: `Cloning ${url}…`,
      progress: 0,
      complete: false,
      error: null,
      updated_at: new Date().toISOString(),
    });
    gitMutation.mutate({ url, requestId });
  };

  const handleSubmit = () => {
    if (sourceMode === "git") {
      handleGitSubmit();
      return;
    }
    const file = selectedFile;
    if (!file) {
      const feedback: UploadResponse = {
        status: "error",
        error: "Please select a ZIP file.",
      };
      setResult(feedback);
      toast.error(feedback.error ?? "Please select a ZIP file.");
      return;
    }
    const now = new Date().toISOString();
    const requestId = crypto.randomUUID().replace(/-/g, "");
    setActiveRequestId(requestId);
    setResult(null);
    setLocalStatus({
      phase: "upload",
      message: `Uploading ${file.name}…`,
      progress: 0,
      complete: false,
      error: null,
      updated_at: now,
      started_at: now,
      request_id: requestId,
    });
    refetchStatusRef.current?.();
    uploadMutation.mutate({ file, requestId });
  };

  const progressValue = status ? Math.min(Math.max(status.progress, 0), 100) : 0;
  const isProcessing =
    uploadMutation.isPending || gitMutation.isPending || (status ? !status.complete : false);
  const detectedRoots = result?.java_roots?.length ? result.java_roots : result?.java_root ? [result.java_root] : [];
  const detectedModules = uniqueSortedModuleLabels(detectedRoots);

  const statusTone: "destructive" | "success" | "warning" = status?.error || status?.phase === "error"
    ? "destructive"
    : status?.complete
      ? "success"
      : "warning";
  const statusLabel = status?.error || status?.phase === "error"
    ? "Failed"
    : status?.phase === "idle"
      ? "Idle"
      : status?.complete
        ? "Complete"
        : "Running";

  return {
    sourceMode,
    setSourceMode,
    repoUrl,
    setRepoUrl,
    selectedFile,
    result,
    status,
    acceptFile,
    handleSubmit,
    progressValue,
    isProcessing,
    detectedRoots,
    detectedModules,
    statusTone,
    statusLabel,
  };
}
