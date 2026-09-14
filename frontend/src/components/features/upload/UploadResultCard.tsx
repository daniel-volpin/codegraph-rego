import { AlertCircle, CheckCircle2, Copy, FolderGit2 } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import { copyTextToClipboard } from "../../../lib/utils";
import { deriveModuleLabel, relativeToUploadedWorkspace } from "../../../lib/workspace";
import type { UploadResponse } from "../../../lib/types";

interface UploadResultCardProps {
  result: UploadResponse;
  detectedModules: string[];
  detectedRoots: string[];
}

/** Ingestion result summary: success/error banner plus detected modules and Java roots. */
export const UploadResultCard = ({ result, detectedModules, detectedRoots }: UploadResultCardProps) => (
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
                <div key={root} className="flex items-center justify-between gap-3 p-3 text-xs">
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
);

export default UploadResultCard;
