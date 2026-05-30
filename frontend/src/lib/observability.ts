export interface FrontendErrorContext {
  componentStack?: string | null;
  source?: string;
}

export function reportError(error: unknown, context: FrontendErrorContext = {}) {
  const normalized = error instanceof Error ? error : new Error(String(error));

  // Keep a local fallback so failures are visible during development even
  // before a remote sink (Sentry/OTel collector) is attached.
  console.error("[frontend-error]", {
    message: normalized.message,
    name: normalized.name,
    stack: normalized.stack,
    ...context,
  });

  // Emit an event so a future telemetry bridge can subscribe without touching
  // business logic again.
  if (typeof window !== "undefined") {
    window.dispatchEvent(
      new CustomEvent("codegraph:error", {
        detail: {
          message: normalized.message,
          name: normalized.name,
          stack: normalized.stack,
          ...context,
        },
      }),
    );
  }
}

export interface FrontendMetric {
  name: string;
  value: number;
  rating?: "good" | "needs-improvement" | "poor";
  id?: string;
  delta?: number;
}

export function reportMetric(metric: FrontendMetric) {
  // Dev console signal so Core Web Vitals are visible without a remote sink.
  if (import.meta.env.DEV) {
    console.info("[frontend-metric]", metric);
  }

  // Same dispatch pattern as reportError: business code stays neutral, a
  // future telemetry bridge subscribes via window.addEventListener.
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("codegraph:metric", { detail: metric }));
  }
}
