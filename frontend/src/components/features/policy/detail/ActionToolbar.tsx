import { Loader2, Sparkles } from "lucide-react";
import { Button } from "../../../ui/button";

export interface ActionToolbarProps {
  pendingAction: "explain" | "preview" | "apply" | "agentic" | undefined;
  previewAvailable: boolean;
  verifyAvailable: boolean;
  onExplain: () => void;
  onPreview: () => void;
  onVerify: () => void;
  onAgentic: () => void;
}

export const ActionToolbar = ({
  pendingAction,
  previewAvailable,
  verifyAvailable,
  onExplain,
  onPreview,
  onVerify,
  onAgentic,
}: ActionToolbarProps) => (
  <div className="flex flex-wrap gap-2">
    <Button
      variant="outline"
      size="sm"
      disabled={pendingAction !== undefined}
      onClick={onExplain}
    >
      {pendingAction === "explain" ? (
        <>
          <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Explaining…
        </>
      ) : (
        <>
          <Sparkles aria-hidden="true" className="mr-1 h-4 w-4" /> Explain finding
        </>
      )}
    </Button>
    <Button
      variant="secondary"
      size="sm"
      disabled={pendingAction !== undefined || !previewAvailable}
      onClick={onPreview}
    >
      {pendingAction === "preview" ? (
        <>
          <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Previewing…
        </>
      ) : (
        <>Preview suggested fix</>
      )}
    </Button>
    <Button
      variant="outline"
      size="sm"
      disabled={pendingAction !== undefined || !verifyAvailable}
      onClick={onVerify}
    >
      {pendingAction === "apply" ? (
        <>
          <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Verifying…
        </>
      ) : (
        <>Verify fix (dry run)</>
      )}
    </Button>
    <Button
      variant="default"
      size="sm"
      className="bg-indigo-600 hover:bg-indigo-700 text-white dark:bg-indigo-600 dark:hover:bg-indigo-700"
      disabled={pendingAction !== undefined}
      onClick={onAgentic}
    >
      {pendingAction === "agentic" ? (
        <>
          <Loader2 aria-hidden="true" className="mr-1 h-4 w-4 animate-spin" /> Running agent…
        </>
      ) : (
        <>
          <Sparkles aria-hidden="true" className="mr-1 h-4 w-4" /> Autonomous Agent Fix
        </>
      )}
    </Button>
  </div>
);

export default ActionToolbar;
