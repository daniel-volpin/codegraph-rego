import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Check, Scale, Search, UploadCloud, X } from "lucide-react";
import { fetchHealth } from "../lib/api";
import type { HealthCheckResponse, UploadResponse } from "../lib/types";
import { readPersistedLastUpload } from "../lib/persistence";
import { uniqueSortedModuleLabels } from "../lib/workspace";
import { BACKEND_DEPENDENCY_LABELS } from "../lib/dependencies";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";

const DEPENDENCIES: Array<{ key: keyof HealthCheckResponse; label: string }> = [
  { key: "startup_ready", label: BACKEND_DEPENDENCY_LABELS.startup_ready.homeLabel },
  { key: "neo4j", label: BACKEND_DEPENDENCY_LABELS.neo4j.homeLabel },
  { key: "faiss_index", label: BACKEND_DEPENDENCY_LABELS.faiss_index.homeLabel },
  { key: "signature_map", label: BACKEND_DEPENDENCY_LABELS.signature_map.homeLabel },
  { key: "embedding_model", label: BACKEND_DEPENDENCY_LABELS.embedding_model.homeLabel },
  { key: "opa", label: BACKEND_DEPENDENCY_LABELS.opa.homeLabel },
];

const HomePage = () => {
  const [lastUpload, setLastUpload] = useState<UploadResponse | null>(null);
  const [uploadHydrated, setUploadHydrated] = useState(false);

  const healthQuery = useQuery<HealthCheckResponse, Error>({
    queryKey: ["health"],
    queryFn: ({ signal }) => fetchHealth(signal),
    refetchInterval: 15000,
    staleTime: 10000,
  });

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const persisted = await readPersistedLastUpload();
      if (!cancelled) {
        setLastUpload(persisted);
        setUploadHydrated(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const health = healthQuery.data ?? null;
  const modules = uniqueSortedModuleLabels(
    lastUpload?.java_roots?.length ? lastUpload.java_roots : lastUpload?.java_root ? [lastUpload.java_root] : [],
  );
  const hasWorkspace = modules.length > 0;

  return (
    <div className="space-y-4">
      <Card className="p-6">
        <h1 className="text-2xl font-semibold text-slate-900">CodeGraph Workspace</h1>
        <p className="mt-2 max-w-3xl text-sm text-slate-600">
          Graph-based code understanding for JVM projects: ingest Java sources, evaluate ISO 27001 policy rules with
          OPA, inspect grounded evidence, and run bounded dry-run remediation.
        </p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="text-sm font-semibold text-slate-900">System status</h2>
            {health && (
              <Badge variant={health.status === "ok" ? "success" : "warning"}>
                {health.status === "ok" ? "Healthy" : "Degraded"}
              </Badge>
            )}
            {healthQuery.isError && <Badge variant="destructive">Unreachable</Badge>}
          </div>
          {healthQuery.isLoading ? (
            <p role="status" className="mt-3 text-sm text-slate-500">
              Checking backend dependencies…
            </p>
          ) : healthQuery.isError ? (
            <p className="mt-3 text-sm text-slate-600">
              The backend could not be reached. Start the backend process, then verify the API base URL on the{" "}
              <Link to="/settings" className="font-medium text-indigo-700 underline hover:no-underline">
                Settings page
              </Link>
              .
            </p>
          ) : (
            <ul className="mt-3 grid gap-1.5 sm:grid-cols-2">
              {DEPENDENCIES.map((dep) => {
                const healthy = Boolean(health?.[dep.key]);
                return (
                  <li key={dep.key} className="flex items-center gap-2 text-sm text-slate-700">
                    {healthy ? (
                      <Check aria-hidden="true" className="h-4 w-4 text-emerald-600" />
                    ) : (
                      <X aria-hidden="true" className="h-4 w-4 text-rose-600" />
                    )}
                    <span className="min-w-0 flex-1">{dep.label}</span>
                    <span className="text-xs text-slate-500">{healthy ? "Available" : "Unavailable"}</span>
                  </li>
                );
              })}
            </ul>
          )}
          {health && health.status !== "ok" && (
            <p className="mt-3 text-xs text-slate-600">
              Degraded dependencies usually mean the workspace has not been ingested yet or a service is still
              starting. The header status shows per-dependency details.
            </p>
          )}
        </Card>

        <Card className="p-5">
          <h2 className="text-sm font-semibold text-slate-900">Active workspace</h2>
          {!uploadHydrated ? (
            <p role="status" className="mt-3 text-sm text-slate-500">
              Loading workspace state…
            </p>
          ) : hasWorkspace ? (
            <div className="mt-3 space-y-2">
              <p className="text-sm text-slate-600">
                Last successful upload detected {modules.length} module{modules.length === 1 ? "" : "s"}:
              </p>
              <div className="flex flex-wrap gap-2">
                {modules.map((module) => (
                  <Badge key={module} variant="secondary">
                    {module}
                  </Badge>
                ))}
              </div>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-600">
              No uploaded workspace yet. Ingestion parses Java sources into the graph and builds the semantic index.
            </p>
          )}
        </Card>
      </div>

      <Card className="p-5">
        <h2 className="text-sm font-semibold text-slate-900">Next steps</h2>
        <ol className="mt-3 grid gap-3 lg:grid-cols-3">
          <li>
            <Link
              to="/upload"
              className="flex h-full items-start gap-3 rounded-lg border border-slate-200 p-4 transition hover:border-indigo-300 hover:bg-indigo-50/50"
            >
              <UploadCloud aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-indigo-600" />
              <span>
                <span className="flex items-center gap-1 text-sm font-medium text-slate-900">
                  1. {hasWorkspace ? "Replace the workspace" : "Upload a codebase"}
                  <ArrowRight aria-hidden="true" className="h-3.5 w-3.5" />
                </span>
                <span className="mt-1 block text-xs text-slate-600">
                  ZIP with Java sources under src/main/java. Replaces the active workspace.
                </span>
              </span>
            </Link>
          </li>
          <li>
            <Link
              to="/policy"
              className="flex h-full items-start gap-3 rounded-lg border border-slate-200 p-4 transition hover:border-indigo-300 hover:bg-indigo-50/50"
            >
              <Scale aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-indigo-600" />
              <span>
                <span className="flex items-center gap-1 text-sm font-medium text-slate-900">
                  2. Evaluate policies
                  <ArrowRight aria-hidden="true" className="h-3.5 w-3.5" />
                </span>
                <span className="mt-1 block text-xs text-slate-600">
                  Run the OPA rule surface, inspect findings with evidence, and preview bounded remediation.
                </span>
              </span>
            </Link>
          </li>
          <li>
            <Link
              to="/search"
              className="flex h-full items-start gap-3 rounded-lg border border-slate-200 p-4 transition hover:border-indigo-300 hover:bg-indigo-50/50"
            >
              <Search aria-hidden="true" className="mt-0.5 h-5 w-5 shrink-0 text-indigo-600" />
              <span>
                <span className="flex items-center gap-1 text-sm font-medium text-slate-900">
                  3. Search the graph
                  <ArrowRight aria-hidden="true" className="h-3.5 w-3.5" />
                </span>
                <span className="mt-1 block text-xs text-slate-600">
                  Natural-language method search with structural neighbors from the code graph.
                </span>
              </span>
            </Link>
          </li>
        </ol>
      </Card>
    </div>
  );
};

export default HomePage;
