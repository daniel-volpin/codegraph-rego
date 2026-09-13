import { useEffect, useId, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, ChevronDown, RefreshCw, X } from "lucide-react";
import { fetchHealth } from "../../lib/api";
import type { HealthCheckResponse } from "../../lib/types";
import { BACKEND_DEPENDENCY_LABELS, type BackendDependencyKey } from "../../lib/dependencies";

interface DependencyItem {
  key: string;
  label: string;
  description: string;
  healthy: boolean;
  detail: string | null;
}

const detailFor = (details: Record<string, unknown>, ...keys: string[]): string | null => {
  for (const key of keys) {
    const value = details[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return null;
};

const buildItems = (data: HealthCheckResponse): DependencyItem[] => {
  const details = (data.details ?? {}) as Record<string, unknown>;
  const definitions: Array<{
    key: BackendDependencyKey;
    healthy: boolean;
    detail: string | null;
  }> = [
    { key: "startup", healthy: data.startup_ready, detail: detailFor(details, "startup") },
    { key: "neo4j", healthy: data.neo4j, detail: detailFor(details, "neo4j") },
    {
      key: "faiss_index",
      healthy: data.faiss_index,
      detail: detailFor(details, "faiss_index", "search"),
    },
    {
      key: "signature_map",
      healthy: data.signature_map,
      detail: detailFor(details, "signature_map", "signatures"),
    },
    {
      key: "embedding_model",
      healthy: data.embedding_model,
      detail: detailFor(details, "embedding_model", "embeddings"),
    },
    { key: "opa", healthy: data.opa, detail: detailFor(details, "opa") },
  ];
  return definitions.map((item) => ({
    ...item,
    label: BACKEND_DEPENDENCY_LABELS[item.key].shortLabel,
    description: BACKEND_DEPENDENCY_LABELS[item.key].description,
  }));
};

/**
 * Backend dependency status as a native disclosure. The summary expresses
 * state in text + icon, never color alone, and the expanded panel keeps
 * per-dependency failure details available without extra live announcements.
 */
const HealthStatus = () => {
  const panelId = useId();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDetailsElement | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery<HealthCheckResponse, Error>({
    queryKey: ["health"],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 15000,
    staleTime: 10000,
  });

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  if (isLoading) {
    return (
      <div role="status" className="text-xs text-slate-500">
        Checking services…
      </div>
    );
  }

  const unreachable = isError || !data;
  const items = data ? buildItems(data) : [];
  const failed = items.filter((item) => !item.healthy);
  const overall = unreachable ? "unreachable" : data.status === "ok" ? "healthy" : "degraded";

  const summaryLabel =
    overall === "healthy" ? "Healthy" : overall === "degraded" ? `Degraded (${failed.length})` : "Backend unreachable";
  const SummaryIcon = overall === "healthy" ? Check : AlertTriangle;
  const summaryTone =
    overall === "healthy" ? "text-emerald-700" : overall === "degraded" ? "text-amber-800" : "text-rose-700";
  const accessibleSummaryLabel = `Backend status: ${summaryLabel}. ${
    open ? "Collapse dependency details" : "Expand dependency details"
  }`;

  return (
    <details
      ref={rootRef}
      open={open}
      onToggle={(event) => setOpen(event.currentTarget.open)}
      className="relative"
    >
      <summary
        aria-label={accessibleSummaryLabel}
        aria-expanded={open}
        aria-controls={panelId}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            setOpen((current) => !current);
          }
        }}
        className={`flex cursor-pointer list-none items-center gap-1.5 rounded-lg border border-slate-200/80 bg-white px-3 py-1.5 text-xs font-medium transition hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-indigo-500 shadow-2xs [&::-webkit-details-marker]:hidden ${summaryTone}`}
      >
        <span aria-hidden="true" className={`h-2 w-2 rounded-full shrink-0 motion-reduce:animate-none ${overall === "healthy" ? "bg-emerald-500 animate-pulse" : overall === "degraded" ? "bg-amber-500 animate-pulse" : "bg-rose-500 animate-pulse"}`} />
        <SummaryIcon aria-hidden="true" className="h-3.5 w-3.5" />
        {summaryLabel}
        <ChevronDown
          aria-hidden="true"
          className={`h-3.5 w-3.5 text-slate-400 transition-transform motion-reduce:transition-none ${open ? "rotate-180" : ""}`}
        />
      </summary>

      {open && (
        <div
          id={panelId}
          role="region"
          aria-label="Backend dependency status"
          className="absolute right-0 z-40 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-xl border border-slate-200 bg-white p-3.5 shadow-lg animate-in fade-in zoom-in-95 duration-100"
        >
          {unreachable ? (
            <div className="space-y-2 text-sm text-slate-700">
              <p className="font-medium text-rose-700">The backend health endpoint could not be reached.</p>
              <p className="text-xs text-slate-500">
                Check that the backend process is running and the API base URL is correct (Settings page).
              </p>
            </div>
          ) : (
            <ul className="space-y-1.5">
              {items.map((item) => (
                <li key={item.key} className="flex items-start gap-2 text-sm">
                  {item.healthy ? (
                    <Check aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600" />
                  ) : (
                    <X aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-rose-600" />
                  )}
                  <div className="min-w-0">
                    <span className="text-slate-800">{item.description}</span>
                    <span className="sr-only">{item.healthy ? " available" : " unavailable"}</span>
                    {!item.healthy && item.detail && (
                      <p className="mt-0.5 break-words text-xs text-slate-500">{item.detail}</p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
          {!unreachable && failed.length > 0 && (
            <p className="mt-2 border-t border-slate-100 pt-2 text-xs text-slate-500">
              The UI stays usable; workflows that need an unavailable dependency show inline errors.
            </p>
          )}
          <button
            type="button"
            onClick={() => refetch()}
            disabled={isFetching}
            className="mt-2 flex items-center gap-1.5 rounded-md border border-slate-200 px-2 py-1 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-60"
          >
            <RefreshCw
              aria-hidden="true"
              className={`h-3 w-3 ${isFetching ? "animate-spin motion-reduce:animate-none" : ""}`}
            />
            {isFetching ? "Checking…" : "Re-check now"}
          </button>
        </div>
      )}
    </details>
  );
};

export default HealthStatus;
