import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import {
  MutationCache,
  QueryCache,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import App from "./App";
import { reportError, reportMetric } from "./lib/observability";
import "./index.css";

// Default options are tuned for this app's workload:
// - Remediation/explain endpoints take 30s–5min. Aggressive retries waste minutes.
// - LLM endpoints must not re-fire on window focus.
// - 4xx responses are non-retriable (validation / unsupported rule).
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        const status = (error as { status?: number } | undefined)?.status;
        if (typeof status === "number" && status >= 400 && status < 500) return false;
        return failureCount < 2;
      },
      retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 30_000),
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      refetchOnWindowFocus: false,
      networkMode: "online",
    },
    mutations: {
      retry: false,
    },
  },
  queryCache: new QueryCache({
    onError: (error) => {
      reportError(error, { source: "query" });
    },
  }),
  mutationCache: new MutationCache({
    onError: (error) => {
      reportError(error, { source: "mutation" });
    },
  }),
});

async function bootstrapRuntimeConfig() {
  try {
    const response = await fetch("/config.json", { cache: "no-store" });
    if (!response.ok) return;
    const payload = (await response.json()) as { apiBaseUrl?: string };
    if (payload && typeof payload.apiBaseUrl === "string") {
      window.__CODEGRAPH_CONFIG__ = { apiBaseUrl: payload.apiBaseUrl };
    }
  } catch {
    // Ignore missing config.json; meta/env fallbacks in runtimeConfig.ts apply.
  }
}

async function enableDevAxe() {
  if (!import.meta.env.DEV) return;
  const { default: axe } = await import("@axe-core/react");
  await axe(React, ReactDOM, 1000);
}

// Core Web Vitals (LCP/INP/CLS/FCP/TTFB). Each metric fires at most a
// few times per page life; we hand them to reportMetric so business code
// stays neutral while telemetry sinks subscribe via window events.
async function enableWebVitals() {
  try {
    const { onCLS, onFCP, onINP, onLCP, onTTFB } = await import("web-vitals");
    const handler = (metric: { name: string; value: number; rating?: "good" | "needs-improvement" | "poor"; id?: string; delta?: number }) =>
      reportMetric({
        name: metric.name,
        value: metric.value,
        rating: metric.rating,
        id: metric.id,
        delta: metric.delta,
      });
    onCLS(handler);
    onFCP(handler);
    onINP(handler);
    onLCP(handler);
    onTTFB(handler);
  } catch (error) {
    // web-vitals failure is non-fatal; just surface for dev visibility.
    reportError(error, { source: "web-vitals" });
  }
}

void Promise.all([bootstrapRuntimeConfig(), enableDevAxe(), enableWebVitals()]).finally(() => {
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </QueryClientProvider>
    </React.StrictMode>,
  );
});
