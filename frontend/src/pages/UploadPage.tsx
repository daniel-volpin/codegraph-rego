import { FormEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileArchive, UploadCloud, CheckCircle2, AlertCircle, Copy, FolderGit2, ShieldAlert } from "lucide-react";
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
import { copyTextToClipboard } from "../lib/utils";
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
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const refetchStatusRef = useRef<(() => void) | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragActive, setDragActive] = useState(false);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [localStatus, setLocalStatus] = useState<UploadStatus | null>(null);
  const [activeRequestId, setActiveRequestId] = useState<string | null>(null);
  const upsertActivity = useUpsertActivity();
  const clearActivity = useClearActivity();
  const resetPolicyArtifacts = useResetAllPolicyArtifacts();

  const uploadMutation = useMutation({
    mutationFn: ({ file, requestId }: { file: File; requestId: string }) => uploadZip(file, undefined, requestId),
    onSuccess: (data) => {
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

  const trackedRequestId = activeRequestId ?? result?.request_id ?? null;
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
    <div className="space-y-6">
      <Card className="p-6 sm:p-8">
        <div className="max-w-3xl space-y-1">
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Upload Codebase</h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Ingest Java source code archives into the CodeGraph engine. The backend parses AST nodes, populates
            Neo4j graph relationships, and rebuilds FAISS semantic embeddings.
          </p>
        </div>

        <form className="mt-6 space-y-4" onSubmit={handleSubmit}>
          <label
            data-testid="upload-dropzone"
            className={`group relative flex min-h-72 w-full cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-all ${
              isDragActive
                ? "border-indigo-600 bg-indigo-50/50 scale-[0.99]"
                : "border-slate-300/80 bg-slate-50/40 hover:border-indigo-400 hover:bg-indigo-50/20"
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
            <input
              ref={inputRef}
              type="file"
              accept=".zip"
              disabled={isProcessing}
              className="sr-only"
              aria-label="Select ZIP archive with Java sources"
              onChange={(event) => acceptFile(event.target.files?.[0])}
            />
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-white shadow-subtle ring-1 ring-slate-200/80 transition-transform group-hover:scale-105">
              <FileArchive aria-hidden="true" className="h-7 w-7 text-indigo-600" />
            </div>
            <p className="text-base sm:text-lg font-semibold text-slate-900">
              {selectedFile ? "File selected" : "Select or drag & drop a ZIP archive"}
            </p>
            <p className="mt-1 max-w-md text-xs sm:text-sm text-slate-500">
              Upload a .zip containing Java source roots (e.g. <code className="font-mono text-slate-700">src/main/java</code>).
            </p>
            {selectedFile && (
              <Badge variant="secondary" className="mt-4 max-w-full truncate px-3 py-1 text-xs">
                {selectedFile.name} · {formatFileSize(selectedFile.size)}
              </Badge>
            )}
          </label>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <p className="text-xs text-slate-500">
              Ingesting a new archive replaces the active workspace and re-evaluates graph indices.
            </p>
            <Button
              type="submit"
              disabled={isProcessing || !selectedFile}
              className="min-w-40 shadow-xs"
            >
              <UploadCloud aria-hidden="true" className="mr-1.5 h-4 w-4" />
              {isProcessing ? "Ingesting Codebase..." : "Upload & Ingest"}
            </Button>
          </div>
        </form>
      </Card>

      {/* Real-Time Processing Status Card */}
      {status && (
        <Card className="p-5 border-slate-200/90 shadow-soft">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-indigo-600 animate-ping" />
              <p className="text-sm font-semibold text-slate-900">
                {status.message || "Processing upload"}
              </p>
            </div>
            <Badge variant={statusTone}>{statusLabel}</Badge>
          </div>
          <div
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progressValue}
            aria-label="Upload and ingestion progress"
            className="h-2.5 overflow-hidden rounded-full bg-slate-100"
          >
            <div
              className="h-full bg-gradient-to-r from-indigo-600 to-indigo-500 transition-all duration-300 ease-out"
              style={{ width: `${progressValue}%` }}
            />
          </div>
          <div className="mt-2 flex justify-between text-[11px] font-mono text-slate-500">
            <span>Phase: {status.phase}</span>
            <span>{progressValue}%</span>
          </div>
        </Card>
      )}

      {/* Result & Partition Summary */}
      {result && (
        <Card
          className={`p-6 ${
            result.error
              ? "border-rose-200 bg-rose-50/50"
              : "border-emerald-200/80 bg-gradient-to-br from-white via-white to-emerald-50/20"
          }`}
        >
          <div className="flex items-center gap-2.5">
            {result.error ? (
              <AlertCircle className="h-5 w-5 text-rose-600 shrink-0" />
            ) : (
              <CheckCircle2 className="h-5 w-5 text-emerald-600 shrink-0" />
            )}
            <p className={`text-sm font-semibold ${result.error ? "text-rose-800" : "text-emerald-800"}`}>
              {result.error ? `Upload failed: ${result.error}` : "Codebase ingested and indexed successfully."}
            </p>
          </div>

          {!result.error && detectedRoots.length > 0 && (
            <div className="mt-5 space-y-4 border-t border-slate-100 pt-4">
              <div>
                <div className="flex items-center gap-2">
                  <FolderGit2 className="h-4 w-4 text-slate-500" />
                  <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                    Detected Modules ({detectedModules.length})
                  </p>
                </div>
                <div className="mt-2 flex flex-wrap gap-2">
                  {detectedModules.map((moduleLabel) => (
                    <Badge key={moduleLabel} variant="secondary" className="px-2.5 py-1 font-mono text-xs">
                      {moduleLabel}
                    </Badge>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                  Detected Java Roots ({detectedRoots.length})
                </p>
                <div className="mt-2 divide-y divide-slate-100 rounded-xl border border-slate-200/80 bg-white">
                  {detectedRoots.map((root) => {
                    const relPath = relativeToUploadedWorkspace(root);
                    return (
                      <div
                        key={root}
                        className="flex items-center justify-between gap-3 p-3 text-xs"
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="rounded bg-slate-100 px-2 py-0.5 font-mono font-medium text-slate-700 shrink-0">
                            {deriveModuleLabel(root)}
                          </span>
                          <code className="font-mono text-slate-600 truncate" title={root}>
                            {relPath}
                          </code>
                        </div>
                        <button
                          type="button"
                          onClick={async () => {
                            const ok = await copyTextToClipboard(relPath);
                            if (ok) toast.success("Root path copied.");
                          }}
                          className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                          title="Copy root path"
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </Card>
      )}

      {/* Universal SAST SARIF Import Card */}
      <Card className="p-6 border-zinc-200 dark:border-zinc-800">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-50 dark:bg-indigo-950/50 text-indigo-600 dark:text-indigo-400 shrink-0">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div className="space-y-1">
              <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                Universal SAST Ingestion &amp; Grounding
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Have existing findings from Semgrep, CodeQL, or SonarQube? Ingest your OASIS SARIF v2.1.0 reports on the Policy page to ground them in CodeGraph AST identities and trigger autonomous agentic repair.
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            onClick={() => navigate("/policy")}
            className="text-xs font-medium shrink-0"
          >
            Go to Policy Page
          </Button>
        </div>
      </Card>
    </div>
  );
};

export default UploadPage;
