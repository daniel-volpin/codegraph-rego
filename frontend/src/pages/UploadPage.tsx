import { FormEvent, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { uploadZip } from "../lib/api";
import type { UploadResponse } from "../lib/types";

const UploadPage = () => {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [result, setResult] = useState<UploadResponse | null>(null);

  const uploadMutation = useMutation({
    mutationFn: uploadZip,
    onSuccess: (data) => {
      setResult(data);
    },
    onError: (error: Error) => {
      setResult({ status: "error", error: error.message });
    }
  });

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const file = inputRef.current?.files?.[0];
    if (!file) {
      setResult({ status: "error", error: "Please select a ZIP file." });
      return;
    }
    setResult(null);
    uploadMutation.mutate(file);
  };

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
            onChange={(event) => {
              const file = event.target.files?.[0];
              setSelectedName(file ? file.name : null);
            }}
          />
        </label>
        {selectedName && (
          <p className="file-selected">Selected: {selectedName}</p>
        )}
        <button type="submit" disabled={uploadMutation.isLoading}>
          {uploadMutation.isLoading ? "Processing…" : "Upload & Ingest"}
        </button>
      </form>
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
    </section>
  );
};

export default UploadPage;
