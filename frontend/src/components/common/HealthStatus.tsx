import { useQuery } from "@tanstack/react-query";
import { fetchHealth } from "../../lib/api";
import type { HealthCheckResponse } from "../../lib/types";

const keys = ["neo4j", "faiss_index", "signature_map", "embedding_model", "opa"] as const;

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

  if (variant === "header") {
    if (isLoading) return <div className="text-xs text-slate-500">Checking services…</div>;
    if (isError || !data) {
      return <button onClick={() => refetch()} className="text-xs text-rose-600">Health unavailable</button>;
    }
    return (
      <div className="flex items-center gap-3">
        {keys.map((key) => (
          <div key={key} className="flex items-center gap-1 text-xs text-slate-600">
            <span className={`h-2 w-2 rounded-full ${data[key] ? "bg-emerald-500" : "bg-rose-500"}`} />
            <span className="hidden xl:inline">{key}</span>
          </div>
        ))}
      </div>
    );
  }

  return <div className="text-xs text-slate-500">{isLoading ? "Checking services…" : isError ? "Health unavailable" : "Healthy"}</div>;
};

export default HealthStatus;
