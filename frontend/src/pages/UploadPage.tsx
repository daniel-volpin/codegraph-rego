import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { fetchUploadStatus, uploadZip } from "../lib/api";
import type { UploadResponse, UploadStatus } from "../lib/types";
import { useActivityContext } from "../context/ActivityContext";
import { toast } from "react-hot-toast";

const UploadPage = () => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const refetchStatusRef = useRef<(() => void) | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [status, setStatus] = useState<UploadStatus | null>(null);
  const { upsert: upsertActivity, clear: clearActivity } = useActivityContext();

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
      toast.success("Upload complete! Embeddings rebuilt.");
      try {
        localStorage.setItem("codegraph:lastUpload", JSON.stringify(data));
      } catch {
        /* ignore storage errors */
      }
    },
    onError: (error: Error) => {
      const payload: UploadResponse = { status: "error", error: error.message };
      setResult(payload);
      toast.error(`Upload failed: ${error.message}`);
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
    if (!status) {
      return;
    }
    const activityStatus = status.error
      ? "error"
      : status.complete
        ? "success"
        : "running";
    upsertActivity({
      key: "upload",
      label: "Upload & Ingestion",
      status: activityStatus,
      message: status.message,
      progress: status.progress,
      updatedAt: status.updated_at
    });
  }, [status, upsertActivity]);

  useEffect(() => {
    return () => {
      clearActivity("upload");
    };
  }, [clearActivity]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const file = inputRef.current?.files?.[0];
    if (!file) {
      const feedback: UploadResponse = {
        status: "error",
        error: "Please select a ZIP file."
      };
      setResult(feedback);
      toast.error(feedback.error ?? "Please select a ZIP file.");
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
      <header style={{ marginBottom: "2rem" }}>
        <h1>Upload Codebase</h1>
        <p style={{ maxWidth: "60ch", marginTop: "0.5rem" }}>
          Upload a ZIP archive of your Java project. The system will parse the source tree,
          ingest it into the graph database, and generate semantic embeddings for search.
        </p>
      </header>
      <form className="upload-form" onSubmit={handleSubmit}>
        <div className="upload-container">
          <label className="file-input">
            <div style={{ fontSize: "3rem", marginBottom: "1rem" }}>📦</div>
            <span style={{ fontSize: "1.1rem", fontWeight: 500 }}>
              {selectedName ? "Change ZIP archive" : "Click to select ZIP archive"}
            </span>
            <span style={{ fontSize: "0.9rem", opacity: 0.8, marginTop: "0.5rem" }}>
              or drag and drop file here
            </span>
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
            {selectedName && (
              <div className="file-selected-text">
                <span>📄 {selectedName}</span>
              </div>
            )}
          </label>

          <div className="upload-actions">
            <button type="submit" className="btn-primary" disabled={isProcessing || !selectedName}>
              {isProcessing && <span className="btn-spinner" aria-hidden="true" />}
              <span>{isProcessing ? "Processing..." : "Upload & Ingest"}</span>
            </button>
          </div>
        </div>
      </form>
      {showProgress && (
        <div
          className="progress-track"
          role="progressbar"
          aria-label="Upload progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={Math.round(progressValue)}
          title="Upload progress"
        >
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
          className={`callout ${result.error ? "callout-error" : "callout-success"
            }`}
        >
          {result.error ? (
            <div>
              <p>Error: {result.error}</p>
              <button
                type="button"
                className="callout-action"
                onClick={() => {
                  uploadMutation.reset();
                  setStatus(null);
                  setResult(null);
                  inputRef.current?.click();
                }}
              >
                Retry upload
              </button>
            </div>
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
    </section>
  );
};

export default UploadPage;
