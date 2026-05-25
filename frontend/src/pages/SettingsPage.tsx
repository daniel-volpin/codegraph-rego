import { Settings as SettingsIcon, ExternalLink } from "lucide-react";
import { Card } from "../components/ui/card";
import { Input } from "../components/ui/input";
import { getRuntimeApiBase } from "../lib/runtimeConfig";

const API_BASE = getRuntimeApiBase();

const SettingsPage = () => {
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
