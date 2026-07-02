import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileArchive, UploadCloud } from "lucide-react";
import { fetchUploadStatus, uploadZip } from "../lib/api";
import type { UploadResponse, UploadStatus } from "../lib/types";
import { useClearActivity, useUpsertActivity } from "../store/activity";
import { useResetAllPolicyArtifacts } from "../hooks/usePolicyArtifacts";
import { useUploadStatusStream } from "../hooks/useUploadStatusStream";
import {
  clearPersistedPolicyEvaluations,
  persistLastUpload,
  readPersistedLastUpload,
} from "../lib/persistence";
import { toast } from "sonner";
import { Card } from "../components/ui/card";
import { Button } from "../components/ui/button";
import { Badge } from "../components/ui/badge";
import {
  deriveModuleLabel,
  relativeToUploadedWorkspace,
  uniqueSortedModuleLabels,
} from "../lib/workspace";

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

const UploadPage = () => {
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const refetchStatusRef = useRef<(() => void) | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragActive, setDragActive] = useState(false);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [localStatus, setLocalStatus] = useState<UploadStatus | null>(null);
  const upsertActivity = useUpsertActivity();
  const clearActivity = useClearActivity();
  const resetPolicyArtifacts = useResetAllPolicyArtifacts();

  const uploadMutation = useMutation({
    mutationFn: (file: File) => uploadZip(file),
    onSuccess: (data) => {
      setResult(data);
      // The backend can return HTTP 200 with an error envelope. Don't treat
      // that as a successful ingest: don't toast success, don't persist it as
      // the last-good upload, and don't evict the existing workspace caches.
      if (data.error || data.status === "error") {
        toast.error(`Upload failed: ${data.error ?? "Unknown error."}`);
        return;
      }
      toast.success("Upload complete! Embeddings rebuilt.");
      void persistLastUpload(data);
      queryClient.removeQueries({ queryKey: ["policyEvaluation:last"] });
      resetPolicyArtifacts();
      void clearPersistedPolicyEvaluations();
    },
    onError: (error: Error) => {
      const payload: UploadResponse = { status: "error", error: error.message };
      setResult(payload);
      toast.error(`Upload failed: ${error.message}`);
    },
    onSettled: () => {
      refetchStatusRef.current?.();
    },
  });

  // Bind the status query to the per-upload request_id so concurrent
  // uploads in other tabs/sessions don't clobber this one's progress.
  // When result.request_id is absent (no upload yet, or an older
  // response stored before the field existed) we fall back to the
  // back-compat path that returns the latest job.
  const trackedRequestId = result?.request_id ?? null;
  const { streamConnected } = useUploadStatusStream(trackedRequestId);
  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ["uploadStatus", trackedRequestId],
    queryFn: ({ signal }) => fetchUploadStatus(trackedRequestId, signal),
    staleTime: 0,
    refetchInterval: (query) => {
      const nextStatus = query.state.data as UploadStatus | undefined;
      const activeStatus = nextStatus ?? localStatus;
      const shouldTrack = uploadMutation.isPending || Boolean(activeStatus && !activeStatus.complete);
      if (!shouldTrack) return false;
      // Prefer SSE push updates. Fallback to bounded polling only when stream
      // is unavailable/disconnected.
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

  // A stray drop outside the dropzone would otherwise navigate the browser
  // to the zip file and destroy the upload session. Neutralize document-level
  // drops while this page is mounted; the dropzone handles its own.
  useEffect(() => {
    const prevent = (event: DragEvent) => {
      event.preventDefault();
    };
    window.addEventListener("dragover", prevent);
    window.addEventListener("drop", prevent);
    return () => {
      window.removeEventListener("dragover", prevent);
      window.removeEventListener("drop", prevent);
    };
  }, []);

  const acceptFile = (file: File | null | undefined) => {
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setSelectedFile(null);
      toast.error(`"${file.name}" is not a ZIP archive. Select a .zip file.`);
      return;
    }
    setSelectedFile(file);
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
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
    setResult(null);
    setLocalStatus({
      phase: "upload",
      message: `Uploading ${file.name}…`,
      progress: 0,
      complete: false,
      error: null,
      updated_at: now,
      started_at: now,
    });
    refetchStatusRef.current?.();
    uploadMutation.mutate(file);
  };

  const progressValue = status ? Math.min(Math.max(status.progress, 0), 100) : 0;
  const isProcessing = uploadMutation.isPending || (status ? !status.complete : false);
  const detectedRoots = result?.java_roots?.length ? result.java_roots : result?.java_root ? [result.java_root] : [];
  const detectedModules = uniqueSortedModuleLabels(detectedRoots);

  const statusTone = status?.error || status?.phase === "error"
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

  return (
    <div className="space-y-4">
      <Card className="p-6">
        <h1 className="text-2xl font-semibold text-slate-900">Upload Codebase</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Upload a ZIP archive for ingestion. The backend parses source structure, builds graph entities, and refreshes semantic embeddings.
        </p>

        <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
          <label
            data-testid="upload-dropzone"
            className={`group flex min-h-80 w-full cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-8 text-center transition focus-within:border-indigo-500 focus-within:ring-2 focus-within:ring-indigo-200 ${
              isDragActive
                ? "border-indigo-500 bg-indigo-50"
                : "border-slate-300 bg-slate-50 hover:border-indigo-400 hover:bg-indigo-50"
            }`}
            onDragOver={(event) => {
              event.preventDefault();
              if (!isProcessing) setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDragActive(false);
              if (isProcessing) return;
              acceptFile(event.dataTransfer.files?.[0]);
            }}
          >
            {/* sr-only (not display:none) keeps the input keyboard-focusable,
                so the dropzone can be operated without a pointer. */}
            <input
              ref={inputRef}
              type="file"
              accept=".zip"
              disabled={isProcessing}
              className="sr-only"
              aria-label="Select ZIP archive with Java sources"
              onChange={(event) => acceptFile(event.target.files?.[0])}
            />
            <div className="mb-4 rounded-full bg-white p-3 shadow-sm ring-1 ring-slate-200">
              <FileArchive aria-hidden="true" className="h-8 w-8 text-indigo-600" />
            </div>
            <p className="text-xl font-semibold text-slate-900">
              {selectedFile ? "File selected" : "Select or drop a ZIP archive"}
            </p>
            <p className="mt-1 text-sm text-slate-500">
              Click to browse, or drag a .zip with Java sources (ideally under src/main/java) onto this area.
            </p>
            {selectedFile && (
              <Badge variant="secondary" className="mt-4 max-w-full truncate px-3 py-1 text-xs">
                {selectedFile.name} · {formatFileSize(selectedFile.size)}
              </Badge>
            )}
          </label>

          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-slate-500">
              Uploading replaces the active workspace and re-runs ingestion and indexing.
            </p>
            <Button type="submit" disabled={isProcessing || !selectedFile}>
              <UploadCloud aria-hidden="true" className="mr-1 h-4 w-4" />
              {isProcessing ? "Processing..." : "Upload & Ingest"}
            </Button>
          </div>
        </form>
      </Card>

      {status && (
        <Card className="p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-slate-800">{status.message || "Processing upload"}</p>
            <Badge variant={statusTone}>{statusLabel}</Badge>
          </div>
          <div
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progressValue}
            aria-label="Upload and ingestion progress"
            className="h-2 overflow-hidden rounded-full bg-slate-100"
          >
            <div
              className="h-full bg-indigo-600 transition-all"
              style={{ width: `${progressValue}%` }}
            />
          </div>
        </Card>
      )}

      {result && (
        <Card className={`p-4 ${result.error ? "border-rose-200 bg-rose-50" : "border-emerald-200 bg-emerald-50"}`}>
          <p className={`text-sm font-medium ${result.error ? "text-rose-700" : "text-emerald-700"}`}>
            {result.error ? `Upload failed: ${result.error}` : "Codebase processed successfully."}
          </p>
          {!result.error && detectedRoots.length > 0 && (
            <div className="mt-3 space-y-3">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Detected modules</p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {detectedModules.map((moduleLabel) => (
                    <Badge key={moduleLabel} variant="secondary">
                      {moduleLabel}
                    </Badge>
                  ))}
                </div>
              </div>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Detected Java roots</p>
                <div className="mt-2 space-y-2">
                  {detectedRoots.map((root) => (
                    <p key={root} className="break-all text-sm text-slate-700">
                      <span className="mr-2 inline-flex min-w-[7rem] rounded bg-white px-2 py-0.5 text-xs font-medium text-slate-600">
                        {deriveModuleLabel(root)}
                      </span>
                      <code className="rounded bg-white px-1 py-0.5">
                        {relativeToUploadedWorkspace(root)}
                      </code>
                    </p>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
};

export default UploadPage;
