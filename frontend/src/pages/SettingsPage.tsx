import { useEffect, useState } from "react";
import { Activity, Settings as SettingsIcon, ExternalLink, Radio, Gauge, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { Switch } from "../components/ui/switch";
import { getRuntimeApiBase } from "../lib/runtimeConfig";
import { isDemoMode, setDemoMode } from "../lib/api";

const API_BASE = getRuntimeApiBase();
const CODE_TOKEN_CLASS = "rounded bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 font-mono text-zinc-800 dark:text-zinc-200";
const CODE_TOKEN_SMALL_CLASS = `${CODE_TOKEN_CLASS} text-[11px]`;

interface TracingSurface {
  enabled: boolean;
  exporter: "OTLP" | "console" | "disabled";
  endpoint: string | null;
}

const resolveTracingSurface = (): TracingSurface => {
  if (import.meta.env.VITE_OTEL_DISABLED === "true") {
    return { enabled: false, exporter: "disabled", endpoint: null };
  }
  const endpoint = (import.meta.env.VITE_OTEL_EXPORTER_OTLP_ENDPOINT ?? "").trim();
  if (endpoint) {
    return { enabled: true, exporter: "OTLP", endpoint };
  }
  return { enabled: true, exporter: "console", endpoint: null };
};

const SettingsPage = () => {
  const [demoActive, setDemoActive] = useState(() => isDemoMode());

  useEffect(() => {
    const handleDemoChange = () => setDemoActive(isDemoMode());
    window.addEventListener("demo-mode-changed", handleDemoChange);
    return () => window.removeEventListener("demo-mode-changed", handleDemoChange);
  }, []);

  const handleToggleDemo = (checked: boolean) => {
    setDemoMode(checked);
    setDemoActive(checked);
    if (checked) {
      toast.success("Interactive thesis demo mode activated.");
    } else {
      toast.info("Live backend mode activated.");
    }
  };

  const tracing = resolveTracingSurface();
  const tracingBadgeVariant: "success" | "warning" | "secondary" = tracing.enabled
    ? tracing.exporter === "OTLP"
      ? "success"
      : "warning"
    : "secondary";
  const tracingBadgeLabel = tracing.enabled
    ? tracing.exporter === "OTLP"
      ? "On · OTLP"
      : "On · console only"
    : "Disabled";

  return (
    <div className="space-y-4">
      <Card className="p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800">
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">Settings & Observability</h1>
        <p className="mt-1 text-xs text-zinc-600 dark:text-zinc-400">
          Runtime endpoints, telemetry pipeline configuration, and developer links for CodeGraph.
        </p>
      </Card>

      <Card className="space-y-3.5 p-5 shadow-xs border-amber-200/80 bg-amber-50/20 dark:border-amber-900/40 dark:bg-amber-950/10">
        <div className="flex items-center justify-between gap-3 border-b border-amber-100 pb-3 dark:border-amber-900/40">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-amber-600 dark:text-amber-400" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-amber-900 dark:text-amber-300">
              Interactive Thesis Demo Mode
            </h2>
          </div>
          <Badge variant={demoActive ? "warning" : "secondary"} className="text-[10px]">
            {demoActive ? "Active" : "Inactive"}
          </Badge>
        </div>

        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1 max-w-xl">
            <p className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
              Emulate Backend & Benchmark Dataset
            </p>
            <p className="text-[11px] text-zinc-600 dark:text-zinc-400 leading-relaxed">
              Populates realistic OWASP/ISO benchmark violations, call-graph evidence citations, virtual patch diffs, and dry-run verification without requiring local Neo4j, FAISS, or OPA containers.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Demo Mode</span>
            <Switch
              checked={demoActive}
              onCheckedChange={handleToggleDemo}
              aria-label="Toggle interactive thesis demo mode"
            />
          </div>
        </div>
      </Card>

      <Card className="space-y-3.5 p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800">
        <div className="flex items-center gap-2 border-b border-zinc-100 pb-3 dark:border-zinc-800/80">
          <SettingsIcon className="h-4 w-4 text-zinc-500" />
          <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">API Configuration</h2>
        </div>

        <div className="space-y-2.5">
          <label className="block space-y-1.5">
            <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">Runtime API Base URL</span>
            <Input type="text" value={API_BASE} readOnly className="font-mono text-xs bg-zinc-50/70 dark:bg-zinc-900" />
          </label>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            Resolved in cascade order: <code className={CODE_TOKEN_SMALL_CLASS}>/config.json</code> →{" "}
            <code className={CODE_TOKEN_SMALL_CLASS}>&lt;meta name="api-base" /&gt;</code> →{" "}
            <code className={CODE_TOKEN_SMALL_CLASS}>VITE_API_BASE_URL</code>.
          </p>
        </div>
      </Card>

      <Card className="space-y-4 p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800" data-testid="observability-card">
        <div className="flex items-center justify-between gap-3 border-b border-zinc-100 pb-3 dark:border-zinc-800/80">
          <div className="flex items-center gap-2">
            <Activity aria-hidden="true" className="h-4 w-4 text-zinc-500" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">Observability & Tracing</h2>
          </div>
          <Badge variant={tracingBadgeVariant} data-testid="tracing-status-badge" className="text-[10px]">
            {tracingBadgeLabel}
          </Badge>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-zinc-200/80 bg-zinc-50/50 p-3.5 dark:border-zinc-800 dark:bg-zinc-900/40">
            <div className="flex items-center gap-1.5">
              <Radio className="h-3.5 w-3.5 text-zinc-500" />
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-600 dark:text-zinc-400">
                Browser Tracing
              </p>
            </div>
            <p className="mt-1.5 text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">
              {tracing.enabled
                ? "OpenTelemetry FetchInstrumentation injects a traceparent header on every API request."
                : "Tracing disabled via VITE_OTEL_DISABLED."}
            </p>
            <p className="mt-2 text-[11px] text-zinc-500 dark:text-zinc-400">
              Exporter: <span className="font-mono font-medium text-zinc-700 dark:text-zinc-300">{tracing.exporter}</span>
              {tracing.endpoint ? (
                <>
                  {" "}
                  · target <code className={CODE_TOKEN_CLASS}>{tracing.endpoint}</code>
                </>
              ) : null}
            </p>
          </div>
          <div className="rounded-lg border border-zinc-200/80 bg-zinc-50/50 p-3.5 dark:border-zinc-800 dark:bg-zinc-900/40">
            <div className="flex items-center gap-1.5">
              <Gauge className="h-3.5 w-3.5 text-zinc-500" />
              <p className="text-[11px] font-semibold uppercase tracking-wider text-zinc-600 dark:text-zinc-400">
                Web Vitals Telemetry
              </p>
            </div>
            <p className="mt-1.5 text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">
              LCP / INP / CLS / FCP / TTFB metrics are dispatched via internal event bus
              (<code className={CODE_TOKEN_CLASS}>codegraph:metric</code>).
            </p>
            <p className="mt-2 text-[11px] text-zinc-500 dark:text-zinc-400">
              Listen on <code className={CODE_TOKEN_CLASS}>window</code> or configure an OTLP collector.
            </p>
          </div>
        </div>

        <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
          Set <code className={CODE_TOKEN_CLASS}>VITE_OTEL_EXPORTER_OTLP_ENDPOINT</code> at build time
          to stream spans to Tempo / Jaeger / Honeycomb collectors via OTLP/HTTP.
        </p>
      </Card>

      <Card className="space-y-3.5 p-5 shadow-xs border-zinc-200/80 dark:border-zinc-800">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">Quick Reference Links</h2>
        <div className="grid gap-2.5 sm:grid-cols-2">
          <a
            href={`${API_BASE}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white p-3.5 text-xs text-zinc-800 transition hover:border-zinc-400 hover:bg-zinc-50/80 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-zinc-700 dark:hover:bg-zinc-800/60"
          >
            <span className="font-medium">FastAPI Swagger Documentation</span>
            <ExternalLink className="h-3.5 w-3.5 text-zinc-400" />
          </a>
          <a
            href={`${API_BASE}/health`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white p-3.5 text-xs text-zinc-800 transition hover:border-zinc-400 hover:bg-zinc-50/80 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-zinc-700 dark:hover:bg-zinc-800/60"
          >
            <span className="font-medium">Direct Health Check Endpoint</span>
            <ExternalLink className="h-3.5 w-3.5 text-zinc-400" />
          </a>
        </div>
      </Card>
    </div>
  );
};

export default SettingsPage;

