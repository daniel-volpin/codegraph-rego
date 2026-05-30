import { Activity, Settings as SettingsIcon, ExternalLink } from "lucide-react";
import { Badge } from "../components/ui/badge";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { getRuntimeApiBase } from "../lib/runtimeConfig";

const API_BASE = getRuntimeApiBase();

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
      <Card className="p-6">
        <h1 className="text-2xl font-semibold text-slate-900">Settings</h1>
        <p className="mt-2 text-sm text-slate-600">
          View current configuration and environment settings for the CodeGraph framework.
        </p>
      </Card>

      {/* ── API Configuration ─────────────────────── */}
      <Card className="space-y-4 p-5">
        <div className="flex items-center gap-2">
          <SettingsIcon className="h-5 w-5 text-slate-400" />
          <h2 className="text-base font-semibold text-slate-900">API Configuration</h2>
        </div>

        <div className="space-y-3">
          <label className="block space-y-1">
            <span className="text-xs font-medium text-slate-600">Runtime API base</span>
            <Input type="text" value={API_BASE} readOnly className="font-mono text-sm bg-slate-50" />
          </label>
          <p className="text-xs text-muted-foreground">
            Resolved in order from <code className="rounded bg-slate-100 px-1 py-0.5 text-xs">/config.json</code>,
            then <code className="rounded bg-slate-100 px-1 py-0.5 text-xs">&lt;meta name="api-base" /&gt;</code>,
            then <code className="rounded bg-slate-100 px-1 py-0.5 text-xs">VITE_API_BASE_URL</code>.
          </p>
        </div>
      </Card>

      {/* ── Observability ─────────────────────────── */}
      <Card className="space-y-4 p-5" data-testid="observability-card">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Activity aria-hidden="true" className="h-5 w-5 text-slate-400" />
            <h2 className="text-base font-semibold text-slate-900">Observability</h2>
          </div>
          <Badge variant={tracingBadgeVariant} data-testid="tracing-status-badge">
            {tracingBadgeLabel}
          </Badge>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-slate-200 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Browser tracing
            </p>
            <p className="mt-1 text-sm text-slate-700">
              {tracing.enabled
                ? "OpenTelemetry FetchInstrumentation injects a traceparent header on every API request."
                : "Tracing disabled via VITE_OTEL_DISABLED."}
            </p>
            <p className="mt-2 text-xs text-slate-500">
              Exporter: <span className="font-mono">{tracing.exporter}</span>
              {tracing.endpoint ? (
                <>
                  {" "}
                  · target <code className="rounded bg-slate-100 px-1 py-0.5">{tracing.endpoint}</code>
                </>
              ) : null}
            </p>
          </div>
          <div className="rounded-lg border border-slate-200 p-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Web Vitals
            </p>
            <p className="mt-1 text-sm text-slate-700">
              LCP / INP / CLS / FCP / TTFB are reported via the observability event bus
              (<code className="rounded bg-slate-100 px-1 py-0.5">codegraph:metric</code>).
            </p>
            <p className="mt-2 text-xs text-slate-500">
              Wire a subscriber on <code className="rounded bg-slate-100 px-1 py-0.5">window</code> or
              attach an OTLP collector to forward these to your backend.
            </p>
          </div>
        </div>

        <p className="text-xs text-muted-foreground">
          Set <code className="rounded bg-slate-100 px-1 py-0.5">VITE_OTEL_EXPORTER_OTLP_ENDPOINT</code> at build time
          to ship browser spans to a Tempo / Jaeger / Honeycomb collector via OTLP/HTTP.
        </p>
      </Card>

      {/* ── Useful Links ──────────────────────────── */}
      <Card className="space-y-3 p-5">
        <h2 className="text-base font-semibold text-slate-900">Quick Links</h2>
        <div className="grid gap-2 sm:grid-cols-2">
          <a
            href={`${API_BASE}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-3 text-sm text-slate-700 transition hover:border-indigo-300 hover:bg-indigo-50"
          >
            <ExternalLink className="h-4 w-4 text-slate-400" />
            API Documentation (Swagger)
          </a>
          <a
            href={`${API_BASE}/health`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-lg border border-slate-200 px-4 py-3 text-sm text-slate-700 transition hover:border-indigo-300 hover:bg-indigo-50"
          >
            <ExternalLink className="h-4 w-4 text-slate-400" />
            Health Check Endpoint
          </a>
        </div>
      </Card>
    </div>
  );
};

export default SettingsPage;
