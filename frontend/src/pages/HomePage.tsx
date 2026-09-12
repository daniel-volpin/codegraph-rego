import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Check, Scale, ShieldCheck, Sparkles, UploadCloud, X, GitGraph, FileCode2 } from "lucide-react";
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
    <div className="space-y-6">
      {/* Hero / Overview Header */}
      <Card className="relative overflow-hidden p-6 sm:p-8 bg-gradient-to-br from-white via-white to-slate-50/80 border-slate-200/80">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-3xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-indigo-200/60 bg-indigo-50/70 px-3 py-1 text-xs font-medium text-indigo-800">
              <Sparkles className="h-3.5 w-3.5 text-indigo-600" />
              <span>Neurosymbolic Security & Compliance Framework</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
              CodeGraph Workspace
            </h1>
            <p className="text-sm sm:text-base text-slate-600 leading-relaxed">
              Graph-based code understanding for JVM projects: ingest Java sources, evaluate multi-standard policy rules
              (ISO 27001, PCI-DSS, OWASP Top 10, NIST 800-53) with OPA, inspect grounded evidence, and run autonomous agentic repair.
            </p>
          </div>

          <div className="flex flex-wrap md:flex-col gap-2 shrink-0">
            <div className="flex items-center gap-2 rounded-lg border border-slate-200/70 bg-white px-3 py-2 text-xs text-slate-700 shadow-2xs">
              <ShieldCheck className="h-4 w-4 text-indigo-600" />
              <span className="font-semibold">RQ1:</span> Multi-Standard Rego Policy
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-slate-200/70 bg-white px-3 py-2 text-xs text-slate-700 shadow-2xs">
              <GitGraph className="h-4 w-4 text-sky-600" />
              <span className="font-semibold">RQ2:</span> Graph-Grounded Citations
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-slate-200/70 bg-white px-3 py-2 text-xs text-slate-700 shadow-2xs">
              <FileCode2 className="h-4 w-4 text-emerald-600" />
              <span className="font-semibold">RQ3:</span> Autonomous 3-Gate Remediation
            </div>
          </div>
        </div>
      </Card>

      {/* Grid: System Status & Active Workspace */}
      <div className="grid gap-6 lg:grid-cols-2">
        {/* System Status Card */}
        <Card className="p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-700">
                System status
              </h2>
              {health && (
                <Badge variant={health.status === "ok" ? "success" : "warning"}>
                  {health.status === "ok" ? "Healthy" : "Degraded"}
                </Badge>
              )}
              {healthQuery.isError && <Badge variant="destructive">Unreachable</Badge>}
            </div>

            {healthQuery.isLoading ? (
              <p role="status" className="py-6 text-center text-sm text-slate-500">
                Checking backend dependencies…
              </p>
            ) : healthQuery.isError ? (
              <div className="py-4 space-y-2">
                <p className="text-sm text-slate-600">
                  The backend could not be reached. Start the backend process, then verify the API base URL on the{" "}
                  <Link to="/settings" className="font-medium text-indigo-700 underline hover:no-underline">
                    Settings page
                  </Link>
                  .
                </p>
              </div>
            ) : (
              <ul className="mt-4 grid gap-2 sm:grid-cols-2">
                {DEPENDENCIES.map((dep) => {
                  const healthy = Boolean(health?.[dep.key]);
                  return (
                    <li
                      key={dep.key}
                      className="flex items-center justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 text-xs"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        {healthy ? (
                          <Check aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-emerald-600" />
                        ) : (
                          <X aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-rose-600" />
                        )}
                        <span className="font-medium text-slate-800 truncate">{dep.label}</span>
                      </div>
                      <span className={`text-[10px] font-semibold uppercase tracking-wider ${healthy ? "text-emerald-700" : "text-rose-700"}`}>
                        {healthy ? "Available" : "Unavailable"}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {health && health.status !== "ok" && (
            <p className="mt-4 border-t border-slate-100 pt-3 text-xs text-slate-600">
              Degraded dependencies usually mean the workspace has not been ingested yet or a service is still
              starting. The header status shows per-dependency details.
            </p>
          )}
        </Card>

        {/* Active Workspace Card */}
        <Card className="p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-3">
              <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-700">
                Active workspace
              </h2>
              {hasWorkspace && (
                <Badge variant="accent">
                  {modules.length} Module{modules.length === 1 ? "" : "s"}
                </Badge>
              )}
            </div>

            {!uploadHydrated ? (
              <p role="status" className="py-6 text-center text-sm text-slate-500">
                Loading workspace state…
              </p>
            ) : hasWorkspace ? (
              <div className="mt-4 space-y-3">
                <p className="text-sm text-slate-600">
                  Last successful upload detected {modules.length} module{modules.length === 1 ? "" : "s"}:
                </p>
                <div className="flex flex-wrap gap-2">
                  {modules.map((module) => (
                    <Badge key={module} variant="secondary" className="px-2.5 py-1 font-mono text-xs">
                      {module}
                    </Badge>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-6 text-center space-y-2">
                <p className="text-sm text-slate-600">
                  No uploaded workspace yet. Ingestion parses Java sources into the graph and builds the semantic index.
                </p>
              </div>
            )}
          </div>

          {hasWorkspace && (
            <div className="mt-4 border-t border-slate-100 pt-3 flex justify-end">
              <Link
                to="/policy"
                className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-600 hover:text-indigo-700"
              >
                Inspect Policy Findings &rarr;
              </Link>
            </div>
          )}
        </Card>
      </div>

      {/* Guided Workflow Cards */}
      <Card className="p-6">
        <div className="border-b border-slate-100 pb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-700">
            Next steps
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Execute the complete neurosymbolic verification pipeline step by step.
          </p>
        </div>

        <ol className="mt-4 grid gap-4 lg:grid-cols-2">
          <li>
            <Link
              to="/upload"
              className="group flex h-full flex-col justify-between rounded-xl border border-slate-200/80 p-5 transition-all hover:border-indigo-300 hover:bg-indigo-50/30 hover:shadow-subtle"
            >
              <div className="space-y-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600 transition-colors group-hover:bg-indigo-600 group-hover:text-white">
                  <UploadCloud aria-hidden="true" className="h-5 w-5" />
                </div>
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-slate-900">
                      1. {hasWorkspace ? "Replace the workspace" : "Upload a codebase"}
                    </span>
                    <ArrowRight aria-hidden="true" className="h-4 w-4 text-slate-400 transition-transform group-hover:translate-x-1 group-hover:text-indigo-600" />
                  </div>
                  <p className="mt-1 text-xs text-slate-600 leading-relaxed">
                    ZIP with Java sources under src/main/java. Replaces the active workspace and builds graph index.
                  </p>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 flex items-center text-[11px] font-medium text-indigo-600">
                <span>Ingest & Index</span>
              </div>
            </Link>
          </li>

          <li>
            <Link
              to="/policy"
              className="group flex h-full flex-col justify-between rounded-xl border border-slate-200/80 p-5 transition-all hover:border-indigo-300 hover:bg-indigo-50/30 hover:shadow-subtle"
            >
              <div className="space-y-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600 transition-colors group-hover:bg-indigo-600 group-hover:text-white">
                  <Scale aria-hidden="true" className="h-5 w-5" />
                </div>
                <div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-slate-900">
                      2. Evaluate policies & Remediate
                    </span>
                    <ArrowRight aria-hidden="true" className="h-4 w-4 text-slate-400 transition-transform group-hover:translate-x-1 group-hover:text-indigo-600" />
                  </div>
                  <p className="mt-1 text-xs text-slate-600 leading-relaxed">
                    Run the OPA rule surface, inspect findings with evidence, preview diffs, and verify dry-run fixes.
                  </p>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 flex items-center text-[11px] font-medium text-indigo-600">
                <span>Evaluate & Remediate</span>
              </div>
            </Link>
          </li>
        </ol>
      </Card>
    </div>
  );
};

export default HomePage;


