import { FormEvent, RefObject } from "react";
import { FileArchive, UploadCloud } from "lucide-react";
import { Badge } from "../../ui/badge";
import { Button } from "../../ui/button";
import { Card } from "../../ui/card";

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

interface UploadSourceFormProps {
  sourceMode: "zip" | "git";
  onSourceModeChange: (mode: "zip" | "git") => void;
  repoUrl: string;
  onRepoUrlChange: (url: string) => void;
  selectedFile: File | null;
  onAcceptFile: (file: File | null | undefined) => void;
  isProcessing: boolean;
  isDragActive: boolean;
  onDragActiveChange: (active: boolean) => void;
  onSubmit: () => void;
  inputRef: RefObject<HTMLInputElement | null>;
}

export const UploadSourceForm = ({
  sourceMode,
  onSourceModeChange,
  repoUrl,
  onRepoUrlChange,
  selectedFile,
  onAcceptFile,
  isProcessing,
  isDragActive,
  onDragActiveChange,
  onSubmit,
  inputRef,
}: UploadSourceFormProps) => (
  <Card className="p-6 sm:p-8">
    <div className="max-w-3xl space-y-1">
      <h1 className="text-2xl font-bold tracking-tight text-slate-900">Upload Codebase</h1>
      <p className="text-sm text-slate-600 leading-relaxed">
        Ingest Java source code archives into the CodeGraph engine. The backend parses AST nodes, populates
        Neo4j graph relationships, and rebuilds FAISS semantic embeddings.
      </p>
    </div>

    <form
      className="mt-6 space-y-4"
      onSubmit={(event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <div className="inline-flex rounded-lg border border-slate-200 bg-slate-50 p-1" role="tablist" aria-label="Source">
        {(["zip", "git"] as const).map((mode) => (
          <button
            key={mode}
            type="button"
            role="tab"
            aria-selected={sourceMode === mode}
            data-testid={`source-mode-${mode}`}
            disabled={isProcessing}
            onClick={() => onSourceModeChange(mode)}
            className={`rounded-md px-3 py-1.5 text-sm font-medium transition disabled:opacity-50 ${
              sourceMode === mode
                ? "bg-white text-slate-900 shadow-2xs ring-1 ring-slate-200"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            {mode === "zip" ? "Upload ZIP" : "From Git URL"}
          </button>
        ))}
      </div>

      {sourceMode === "git" ? (
        <div className="space-y-2">
          <label htmlFor="repo-url" className="block text-sm font-medium text-slate-900">
            Public repository URL
          </label>
          <input
            id="repo-url"
            data-testid="repo-url-input"
            type="url"
            inputMode="url"
            placeholder="https://github.com/owner/repository"
            value={repoUrl}
            disabled={isProcessing}
            onChange={(event) => onRepoUrlChange(event.target.value)}
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm shadow-2xs focus-visible:outline focus-visible:outline-2 focus-visible:outline-indigo-500 disabled:opacity-50"
          />
          <p className="text-xs text-slate-600">
            Public HTTPS repositories only, cloned at depth 1. The server rejects hosts outside its allowlist.
          </p>
        </div>
      ) : (
        <label
          data-testid="upload-dropzone"
          className={`group relative flex min-h-72 w-full cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-all ${
            isDragActive
              ? "border-indigo-600 bg-indigo-50/50 scale-[0.99]"
              : "border-slate-300/80 bg-slate-50/40 hover:border-indigo-400 hover:bg-indigo-50/20"
          }`}
          onDragOver={(event) => {
            event.preventDefault();
            if (!isProcessing) onDragActiveChange(true);
          }}
          onDragLeave={() => onDragActiveChange(false)}
          onDrop={(event) => {
            event.preventDefault();
            onDragActiveChange(false);
            if (isProcessing) return;
            onAcceptFile(event.dataTransfer.files?.[0]);
          }}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".zip"
            disabled={isProcessing}
            className="sr-only"
            aria-label="Select ZIP archive with Java sources"
            onChange={(event) => onAcceptFile(event.target.files?.[0])}
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
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
        <p className="text-xs text-slate-500">
          Ingesting a new archive replaces the active workspace and re-evaluates graph indices.
        </p>
        <Button
          type="submit"
          disabled={isProcessing || (sourceMode === "zip" ? !selectedFile : !repoUrl.trim())}
          className="min-w-40 shadow-xs"
        >
          <UploadCloud aria-hidden="true" className="mr-1.5 h-4 w-4" />
          {isProcessing ? "Ingesting Codebase..." : sourceMode === "zip" ? "Upload & Ingest" : "Clone & Ingest"}
        </Button>
      </div>
    </form>
  </Card>
);

export default UploadSourceForm;
