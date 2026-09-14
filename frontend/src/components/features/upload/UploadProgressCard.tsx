import { Badge } from "../../ui/badge";
import { Card } from "../../ui/card";
import type { UploadStatus } from "../../../lib/types";

interface UploadProgressCardProps {
  status: UploadStatus;
  progressValue: number;
  statusTone: "destructive" | "success" | "warning";
  statusLabel: string;
}

/** Real-time upload/ingest progress card, shown while a request is tracked. */
export const UploadProgressCard = ({ status, progressValue, statusTone, statusLabel }: UploadProgressCardProps) => (
  <Card className="p-5 border-slate-200/90 shadow-soft">
    <div className="mb-3 flex items-center justify-between gap-3">
      <div className="flex items-center gap-2">
        <div className="h-2 w-2 rounded-full bg-indigo-600 animate-ping" />
        <p className="text-sm font-semibold text-slate-900">{status.message || "Processing upload"}</p>
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
);

export default UploadProgressCard;
