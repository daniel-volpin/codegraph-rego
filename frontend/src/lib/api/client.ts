import { z } from "zod";

export const defaultHeaders = {
  Accept: "application/json",
};

export const DEMO_MODE_STORAGE_KEY = "codegraph_demo_mode";

export function isDemoMode(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("demo") === "true") return true;
    return localStorage.getItem(DEMO_MODE_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function setDemoMode(enabled: boolean): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(DEMO_MODE_STORAGE_KEY, enabled ? "true" : "false");
    window.dispatchEvent(new Event("demo-mode-changed"));
  } catch {
    // Ignore storage errors
  }
}

// Error classes

export class ApiError extends Error {
  status: number;
  payload: unknown;
  constructor(message: string, status: number, payload: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export class SchemaValidationError extends Error {
  zodError: z.ZodError;
  payload: unknown;
  constructor(zodError: z.ZodError, payload: unknown) {
    const issues = zodError.issues
      .slice(0, 3)
      .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
      .join("; ");
    super(`Response failed schema validation: ${issues}`);
    this.name = "SchemaValidationError";
    this.zodError = zodError;
    this.payload = payload;
  }
}

// Unified response parser

export async function parseApiResponse<S extends z.ZodType>(
  response: Response,
  schema: S,
): Promise<z.infer<S>> {
  const contentType = response.headers.get("content-type");
  const isJson = contentType?.includes("application/json") ?? false;
  const payload: unknown = isJson ? await response.json() : null;

  const result = schema.safeParse(payload);
  if (result.success) return result.data;

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && payload !== null && "error" in payload
        ? String((payload as { error: unknown }).error ?? response.statusText)
        : response.statusText || "Request failed";
    throw new ApiError(message, response.status, payload);
  }

  throw new SchemaValidationError(result.error, payload);
}

// Merges an externally-provided AbortSignal with an internal timeout signal
export function withTimeoutSignal(external: AbortSignal | undefined, ms: number): AbortSignal {
  if (!external) return AbortSignal.timeout(ms);
  const anyFn = (AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFn === "function") {
    return anyFn([external, AbortSignal.timeout(ms)]);
  }
  return external;
}
