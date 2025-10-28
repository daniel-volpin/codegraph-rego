import { FormEvent, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { uploadZip } from "../lib/api";
import type { UploadResponse } from "../lib/types";

const UploadPage = () => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [status, setStatus] = useState<{
    message: string;
    tone: "info" | "success" | "error";
  } | null>(null);
  const [progress, setProgress] = useState(0);
  const [toast, setToast] = useState<{
    message: string;
    tone: "success" | "error";
  } | null>(null);

  const uploadMutation = useMutation({
    mutationFn: uploadZip,
    onSuccess: (data) => {
      setResult(data);
      setStatus({
        message: "Codebase processed successfully.",
        tone: "success"
      });
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
      const payload = { status: "error", error: error.message };
      setResult(payload);
      setStatus({ message: error.message, tone: "error" });
      setToast({ message: `Upload failed: ${error.message}`, tone: "error" });
    }
  });

  useEffect(() => {
    try {
      const saved = localStorage.getItem("codegraph:lastUpload");
      if (saved) {
        const parsed: UploadResponse = JSON.parse(saved);
        setResult(parsed);
        if (!uploadMutation.isPending) {
          setStatus({
            message: "Last successful ingestion found.",
            tone: "info"
          });
        }
      }
    } catch {
      /* ignore bad payload */
    }
  }, [uploadMutation.isPending]);

  useEffect(() => {
    let timer: number | undefined;
    if (uploadMutation.isPending) {
      setProgress(12);
      setStatus({
        message: "Uploading archive and parsing Java sources…",
        tone: "info"
      });
      timer = window.setInterval(() => {
        setProgress((prev) => (prev < 90 ? prev + Math.random() * 8 : prev));
      }, 400);
    }
    return () => {
      if (timer) {
        window.clearInterval(timer);
      }
    };
  }, [uploadMutation.isPending]);

  useEffect(() => {
    if (uploadMutation.isSuccess || uploadMutation.isError) {
      const timeout = window.setTimeout(() => setProgress(100), 150);
      const reset = window.setTimeout(() => setProgress(0), 1200);
      return () => {
        window.clearTimeout(timeout);
        window.clearTimeout(reset);
      };
    }
  }, [uploadMutation.isSuccess, uploadMutation.isError]);

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
      const feedback = {
        status: "error",
        error: "Please select a ZIP file."
      };
      setResult(feedback);
      setStatus({ message: feedback.error ?? "", tone: "error" });
      return;
    }
    setResult(null);
    setStatus({
      message: `Uploading ${file.name}…`,
      tone: "info"
    });
    setToast(null);
    uploadMutation.mutate(file);
  };

  const isProcessing = uploadMutation.isPending;
  const statusToneClass =
    status?.tone === "success"
      ? "status-success"
      : status?.tone === "error"
      ? "status-error"
      : "status-info";

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
      {progress > 0 && (
        <div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress)}>
          <div
            className="progress-bar"
            style={{ width: `${Math.min(progress, 100)}%` }}
          />
        </div>
      )}
      {status && (
        <div className={`status-banner ${statusToneClass}`}>
          {status.message}
        </div>
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
