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
