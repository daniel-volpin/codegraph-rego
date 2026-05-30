// Browser-side OpenTelemetry bootstrap.
//
// Goals:
// - Inject `traceparent` headers into every `fetch()` call so the FastAPI
//   FastAPIInstrumentor.instrument_app picks up the trace and continues it
//   server-side (end-to-end request tracing across the React/FastAPI/Neo4j/
//   LLM pipeline).
// - Default to a console exporter so traces are visible during dev without
//   any collector running.
// - Switch to OTLP/HTTP when VITE_OTEL_EXPORTER_OTLP_ENDPOINT is set so
//   prod sends spans to a Tempo / Jaeger / Honeycomb backend.
//
// This module is dynamically imported at boot from main.tsx so the OTel
// SDK (~80 kB gz) lives in its own chunk and never blocks first paint.

import { ZoneContextManager } from "@opentelemetry/context-zone";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { registerInstrumentations } from "@opentelemetry/instrumentation";
import { FetchInstrumentation } from "@opentelemetry/instrumentation-fetch";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  BatchSpanProcessor,
  ConsoleSpanExporter,
  WebTracerProvider,
  type SpanExporter,
} from "@opentelemetry/sdk-trace-web";
import {
  ATTR_SERVICE_NAME,
  ATTR_SERVICE_VERSION,
} from "@opentelemetry/semantic-conventions";

import { getRuntimeApiBase } from "./runtimeConfig";

const SERVICE_NAME = "codegraph-frontend";
// __APP_VERSION__ is injected at build time by vite.config.ts so the
// service.version attribute stays in sync with package.json automatically.
declare const __APP_VERSION__: string;
const SERVICE_VERSION =
  typeof __APP_VERSION__ === "string" ? __APP_VERSION__ : "0.0.0-dev";

let initialized = false;

// Escapes regex metacharacters for safe inclusion in a `new RegExp` pattern.
// Mirrors the canonical MDN escapeRegExp implementation.
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Returns a regex/string matcher that recognises requests OpenTelemetry's
// FetchInstrumentation sees (i.e. resolved absolute URLs) as belonging to our
// own API origin. Handles both absolute (`https://api.example.com`) and
// relative (`/api`) `VITE_API_BASE_URL` values.
function buildApiOriginMatcher(apiBase: string): RegExp {
  if (apiBase.startsWith("/")) {
    // Relative API base — anchor to the resolved absolute URL on any origin.
    // FetchInstrumentation evaluates URLs after the browser resolves them, so
    // the request appears as `<scheme>://<host>{apiBase}/...` regardless of
    // whether the call site wrote `/api/...` or `http://host/api/...`.
    return new RegExp(`^https?://[^/]+${escapeRegExp(apiBase)}(?:/|$)`);
  }
  return new RegExp(`^${escapeRegExp(apiBase)}(?:/|$)`);
}

function selectExporter(): SpanExporter {
  const otlp = import.meta.env.VITE_OTEL_EXPORTER_OTLP_ENDPOINT as string | undefined;
  if (otlp && otlp.trim()) {
    return new OTLPTraceExporter({ url: `${otlp.replace(/\/+$/, "")}/v1/traces` });
  }
  return new ConsoleSpanExporter();
}

export function configureBrowserTracing(): void {
  if (initialized) return;
  if (import.meta.env.VITE_OTEL_DISABLED === "true") {
    initialized = true;
    return;
  }

  const provider = new WebTracerProvider({
    resource: resourceFromAttributes({
      [ATTR_SERVICE_NAME]: SERVICE_NAME,
      [ATTR_SERVICE_VERSION]: SERVICE_VERSION,
    }),
    spanProcessors: [new BatchSpanProcessor(selectExporter())],
  });
  provider.register({
    // ZoneContextManager keeps the trace context attached across async
    // boundaries (Promises, setTimeout, React's scheduler).
    contextManager: new ZoneContextManager(),
  });

  // Only propagate traceparent to our own API origin. Cross-origin third-party
  // calls (e.g. LM Studio talking to its own server) should not receive our
  // headers — that would either fail CORS or leak our trace context.
  const propagateUrl = buildApiOriginMatcher(getRuntimeApiBase());

  registerInstrumentations({
    instrumentations: [
      new FetchInstrumentation({
        // Only auto-instrument requests to our API; everything else passes
        // through untouched.
        propagateTraceHeaderCorsUrls: [propagateUrl],
        // Mark each request with the resolved span name for readability.
        applyCustomAttributesOnSpan: (span) => {
          span.setAttribute("app.kind", "frontend");
        },
      }),
    ],
  });
}
