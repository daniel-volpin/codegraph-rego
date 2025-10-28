import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { fetchUploadStatus, uploadZip } from "../lib/api";
import type { UploadResponse, UploadStatus } from "../lib/types";

const UploadPage = () => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const refetchStatusRef = useRef<(() => void) | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [status, setStatus] = useState<UploadStatus | null>(null);
  const [toast, setToast] = useState<{
    message: string;
    tone: "success" | "error";
  } | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("codegraph:lastUpload");
      if (saved) {
        const parsed: UploadResponse = JSON.parse(saved);
        setResult(parsed);
      }
    } catch {
      /* ignore serialization issues */
    }
  }, []);

  const uploadMutation = useMutation({
    mutationFn: uploadZip,
    onSuccess: (data) => {
      setResult(data);
      setToast({
        message: "Upload complete! Embeddings rebuilt.",
        tone: "success"
      });
      try {
        localStorage.setItem("codegraph:lastUpload", JSON.stringify(data));
      } catch {
        /* ignore storage errors */
      }
    },
    onError: (error: Error) => {
      const payload: UploadResponse = { status: "error", error: error.message };
      setResult(payload);
      setToast({ message: `Upload failed: ${error.message}`, tone: "error" });
    },
    onSettled: () => {
      refetchStatusRef.current?.();
    }
  });

  const shouldPoll = uploadMutation.isPending || Boolean(status && !status.complete);
  const pollInterval = shouldPoll ? 1000 : false;

  const { data: statusData, refetch: refetchStatus } = useQuery({
    queryKey: ["uploadStatus"],
    queryFn: fetchUploadStatus,
    staleTime: 0,
    refetchInterval: pollInterval
  });

  refetchStatusRef.current = refetchStatus;

  useEffect(() => {
    if (statusData) {
      setStatus(statusData);
    }
  }, [statusData]);

  useEffect(() => {
    if (!toast) {
      return;
    }
    const timeout = window.setTimeout(() => setToast(null), 4000);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const file = inputRef.current?.files?.[0];
    if (!file) {
      const feedback: UploadResponse = {
        status: "error",
        error: "Please select a ZIP file."
      };
      setResult(feedback);
      setToast({ message: feedback.error ?? "Please select a ZIP file.", tone: "error" });
      return;
    }
    const now = new Date().toISOString();
    setResult(null);
    setStatus({
      phase: "upload",
      message: `Uploading ${file.name}…`,
      progress: 0,
      complete: false,
      error: null,
      updated_at: now,
      started_at: now
    });
    setToast(null);
    refetchStatusRef.current?.();
    uploadMutation.mutate(file);
  };

  const progressValue = status ? Math.min(Math.max(status.progress, 0), 100) : 0;
  const showProgress = status ? (!status.complete || progressValue < 100) && progressValue > 0 : false;
  const isProcessing = uploadMutation.isPending || (status ? !status.complete : false);

  let statusToneClass: string | null = null;
  if (status) {
    if (status.phase === "error" || status.error) {
      statusToneClass = "status-error";
    } else if (status.phase === "complete" && !status.error) {
      statusToneClass = "status-success";
    } else {
      statusToneClass = "status-info";
    }
  }

  const shouldRenderStatusBanner = Boolean(
    status &&
      ((status.message && status.message !== "Idle") || showProgress || !status.complete)
  );

  return (
    <section className="card">
      <h1>Upload Java Project</h1>
      <p>
        Upload a ZIP file containing your Java source tree. The backend will
        parse the project, populate Neo4j, and rebuild the semantic embedding
        index.
      </p>
      <form className="upload-form" onSubmit={handleSubmit}>
        <label className="file-input">
          <span>Select ZIP archive</span>
          <input
            ref={inputRef}
            type="file"
            accept=".zip"
            disabled={isProcessing}
            onChange={(event) => {
              const file = event.target.files?.[0];
              setSelectedName(file ? file.name : null);
            }}
          />
        </label>
        {selectedName && (
          <p className="file-selected">Selected: {selectedName}</p>
        )}
        <button type="submit" disabled={isProcessing}>
          {isProcessing ? "Processing…" : "Upload & Ingest"}
        </button>
      </form>
      {showProgress && (
        <div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progressValue)}>
          <div
            className="progress-bar"
            style={{ width: `${progressValue}%` }}
          />
        </div>
      )}
      {shouldRenderStatusBanner && statusToneClass && status && (
        <div className={`status-banner ${statusToneClass}`}>{status.message}</div>
      )}
      {result && (
        <div
          className={`callout ${
            result.error ? "callout-error" : "callout-success"
          }`}
        >
          {result.error ? (
            <p>Error: {result.error}</p>
          ) : (
            <>
              <p>{result.status}</p>
              {result.java_root && (
                <p>
                  Detected Java root: <code>{result.java_root}</code>
                </p>
              )}
            </>
          )}
        </div>
      )}
      {isProcessing && (
        <div className="processing-overlay" aria-live="polite">
          <div className="spinner" role="status" aria-label="Processing upload" />
          <p>Ingestion running… this might take a moment.</p>
        </div>
      )}
      <div aria-live="polite" className="sr-only">
        {status?.message}
      </div>
      {toast && (
        <div className="toast-container">
          <div
            className={`toast ${
              toast.tone === "success" ? "toast-success" : "toast-error"
            }`}
          >
            {toast.message}
          </div>
        </div>
      )}
    </section>
  );
};

export default UploadPage;
