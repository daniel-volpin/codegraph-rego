import { useEffect, useId, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Check, ChevronDown, RefreshCw, X } from "lucide-react";
import { fetchHealth } from "../../lib/api";
import type { HealthCheckResponse } from "../../lib/types";

interface DependencyItem {
  key: string;
  label: string;
  description: string;
  healthy: boolean;
  detail: string | null;
}

const DEPENDENCY_DESCRIPTIONS: Record<string, string> = {
  startup: "Startup preload (graph sync, indexes)",
  neo4j: "Neo4j graph database",
  faiss_index: "FAISS semantic search index",
  signature_map: "Method signature map",
  embedding_model: "Embedding model",
  opa: "OPA policy engine",
};

const detailFor = (details: Record<string, unknown>, ...keys: string[]): string | null => {
  for (const key of keys) {
    const value = details[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return null;
};

const buildItems = (data: HealthCheckResponse): DependencyItem[] => {
  const details = (data.details ?? {}) as Record<string, unknown>;
  return [
    { key: "startup", label: "startup", healthy: data.startup_ready, detail: null },
    { key: "neo4j", label: "graph", healthy: data.neo4j, detail: detailFor(details, "neo4j") },
    { key: "faiss_index", label: "search index", healthy: data.faiss_index, detail: detailFor(details, "search") },
    { key: "signature_map", label: "signatures", healthy: data.signature_map, detail: null },
    { key: "embedding_model", label: "embeddings", healthy: data.embedding_model, detail: null },
    { key: "opa", label: "OPA", healthy: data.opa, detail: detailFor(details, "opa") },
  ].map((item) => ({
    ...item,
    description: DEPENDENCY_DESCRIPTIONS[item.key] ?? item.label,
  }));
};

/**
 * Backend dependency status as an accessible disclosure: a summary button
 * (state expressed in text + icon, never color alone) that expands into a
 * per-dependency panel with failure details and next-step guidance. Works
 * with keyboard and touch, unlike the previous tooltip-only rendering.
 */
const HealthStatus = () => {
  const panelId = useId();
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

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

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((current) => !current)}
        className={`flex items-center gap-1.5 rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium transition hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-indigo-500 ${summaryTone}`}
      >
        <SummaryIcon aria-hidden="true" className="h-3.5 w-3.5" />
        {summaryLabel}
        <ChevronDown
          aria-hidden="true"
          className={`h-3.5 w-3.5 text-slate-400 transition-transform motion-reduce:transition-none ${open ? "rotate-180" : ""}`}
        />
      </button>

      {open && (
        <div
          id={panelId}
          role="region"
          aria-label="Backend dependency status"
          className="absolute right-0 z-40 mt-2 w-80 max-w-[calc(100vw-2rem)] rounded-lg border border-slate-200 bg-white p-3 shadow-lg"
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
    </div>
  );
};

export default HealthStatus;
