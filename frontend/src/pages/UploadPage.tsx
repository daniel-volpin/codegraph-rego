import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { useUploadIngestion } from "../hooks/useUploadIngestion";
import { Card } from "../components/ui/card";
import { Button } from "../components/ui/button";
import UploadSourceForm from "../components/features/upload/UploadSourceForm";
import UploadProgressCard from "../components/features/upload/UploadProgressCard";
import UploadResultCard from "../components/features/upload/UploadResultCard";

const UploadPage = () => {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [isDragActive, setDragActive] = useState(false);

  const {
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
  } = useUploadIngestion();

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

  return (
    <div className="space-y-6">
      <UploadSourceForm
        sourceMode={sourceMode}
        onSourceModeChange={setSourceMode}
        repoUrl={repoUrl}
        onRepoUrlChange={setRepoUrl}
        selectedFile={selectedFile}
        onAcceptFile={acceptFile}
        isProcessing={isProcessing}
        isDragActive={isDragActive}
        onDragActiveChange={setDragActive}
        onSubmit={handleSubmit}
        inputRef={inputRef}
      />

      {status && (
        <UploadProgressCard
          status={status}
          progressValue={progressValue}
          statusTone={statusTone}
          statusLabel={statusLabel}
        />
      )}

      {result && (
        <UploadResultCard result={result} detectedModules={detectedModules} detectedRoots={detectedRoots} />
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
