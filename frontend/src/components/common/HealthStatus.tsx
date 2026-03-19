import { useQuery } from "@tanstack/react-query";
import { fetchHealth } from "../../lib/api";
import type { HealthCheckResponse } from "../../lib/types";

interface HealthStatusProps {
  variant?: "panel" | "header";
}

const HealthStatus = ({ variant = "panel" }: HealthStatusProps) => {
  const { data, isLoading, isError, refetch } = useQuery<HealthCheckResponse, Error>({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 15000,
    staleTime: 10000,
  });

  const items = data
    ? [
        { key: "startup", label: "startup", healthy: data.startup_ready },
        { key: "neo4j", label: "neo4j", healthy: data.neo4j },
        { key: "faiss_index", label: "faiss", healthy: data.faiss_index },
        { key: "signature_map", label: "sigmap", healthy: data.signature_map },
        { key: "embedding_model", label: "embed", healthy: data.embedding_model },
        { key: "opa", label: "opa", healthy: data.opa },
      ]
    : [];
  const failedLabels = items.filter((item) => !item.healthy).map((item) => item.label);
  const startupErrors = data?.startup?.errors ? Object.values(data.startup.errors) : [];
  const detailSummary = [...failedLabels, ...startupErrors].filter(Boolean).join(" | ");

  if (variant === "header") {
    if (isLoading) return <div className="text-xs text-slate-500">Checking services…</div>;
    if (isError || !data) {
      return <button onClick={() => refetch()} className="text-xs text-rose-600">Health unavailable</button>;
    }
    return (
      <div
        className="flex items-center gap-3"
        title={detailSummary || "All runtime checks healthy"}
      >
        <span className={`text-xs font-medium ${data.status === "ok" ? "text-emerald-700" : "text-amber-700"}`}>
          {data.status === "ok" ? "Healthy" : "Degraded"}
        </span>
        {items.map((item) => (
          <div key={item.key} className="flex items-center gap-1 text-xs text-slate-600">
            <span className={`h-2 w-2 rounded-full ${item.healthy ? "bg-emerald-500" : "bg-rose-500"}`} />
            <span className="hidden xl:inline">{item.label}</span>
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="text-xs text-slate-500">
      {isLoading ? "Checking services…" : isError || !data ? "Health unavailable" : data.status === "ok" ? "Healthy" : "Degraded"}
    </div>
  );
};

export default HealthStatus;
