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

import { context, trace } from "@opentelemetry/api";
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
const SERVICE_VERSION = "0.5.0";

let initialized = false;

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
  const apiBase = getRuntimeApiBase();
  const propagateUrl = apiBase.startsWith("/")
    ? new RegExp(`^${apiBase.replace(/[.+?^${}()|[\\]\\\\]/g, "\\$&")}`)
    : new RegExp(`^${apiBase.replace(/[.+?^${}()|[\\]\\\\]/g, "\\$&")}`);

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

// Convenience for callers that want to wrap a user action in a span
// (e.g. "policy.explain" around a mutation). Returns the active tracer.
export const getTracer = () => trace.getTracer(SERVICE_NAME, SERVICE_VERSION);

// Re-export the context API so test/wrapping code doesn't need to import
// from @opentelemetry/api directly.
export { context as otelContext };
