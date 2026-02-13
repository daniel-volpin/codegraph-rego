import { useQuery } from "@tanstack/react-query";
import { fetchHealth } from "../../lib/api";
import type { HealthCheckResponse } from "../../lib/types";
import "./HealthStatus.css";

const HEALTH_LABELS: Record<keyof HealthCheckResponse, string> = {
  neo4j: "Neo4j",
  faiss_index: "FAISS Index",
  signature_map: "Signature Map",
  embedding_model: "Embedding Model",
  opa: "OPA / Rego",
  details: "Details"
};

const keys = ["neo4j", "faiss_index", "signature_map", "embedding_model", "opa"] as const;

interface HealthStatusProps {
  variant?: "panel" | "header";
}

const HealthStatus = ({ variant = "panel" }: HealthStatusProps) => {
  const { data, isLoading, isError, refetch } = useQuery<HealthCheckResponse, Error>({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 15000,
    staleTime: 10000
  });

  if (variant === "header") {
    if (isLoading) return <div className="health-header-item muted">Checking health...</div>;
    if (isError || !data) return (
      <button onClick={() => refetch()} className="health-header-item error" title="System health check failed. Click to retry.">
        <span className="health-indicator" /> System Error
      </button>
    );

    return (
      <div className="health-header-list">
        {keys.map((key) => {
          const healthy = Boolean(data[key]);
          return (
            <div key={key} className={`health-header-item ${healthy ? "ok" : "fail"}`} title={HEALTH_LABELS[key]}>
              <span className="health-indicator" />
              <span className="health-label">{HEALTH_LABELS[key]}</span>
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <section className="health-panel">
      <header>
        <h3>System Health</h3>
        <button type="button" onClick={() => refetch()} aria-label="Refresh health status">
          Refresh
        </button>
      </header>
      {isLoading && <p className="muted">Checking services…</p>}
      {isError && (
        <div className="callout callout-error">
          Failed to load health status.{" "}
          <button type="button" onClick={() => refetch()}>
            Retry
          </button>
        </div>
      )}
      {!isLoading && !isError && data && (
        <ul>
          {keys.map((key) => {
            const healthy = Boolean(data[key]);
            return (
              <li key={key} className={healthy ? "health-ok" : "health-fail"}>
                <span className="health-indicator" aria-hidden="true" />
                <span>{HEALTH_LABELS[key]}</span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
};

export default HealthStatus;
