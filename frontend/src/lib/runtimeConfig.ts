const ENV_DEFAULT_API_BASE = "/api";

declare global {
  interface Window {
    __CODEGRAPH_CONFIG__?: {
      apiBaseUrl?: string;
    };
  }
}

const normalizeBase = (value: string | undefined | null): string | null => {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const withoutTrailingSlash = trimmed.replace(/\/+$/, "");
  if (withoutTrailingSlash.startsWith("/") && typeof window !== "undefined") {
    return new URL(withoutTrailingSlash, window.location.origin).toString().replace(/\/+$/, "");
  }
  return withoutTrailingSlash;
};

export function getRuntimeApiBase(): string {
  const windowConfig = normalizeBase(
    typeof window !== "undefined" ? window.__CODEGRAPH_CONFIG__?.apiBaseUrl : undefined,
  );
  if (windowConfig) return windowConfig;

  const metaConfig = normalizeBase(
    typeof document !== "undefined"
      ? document.querySelector('meta[name="api-base"]')?.getAttribute("content")
      : undefined,
  );
  if (metaConfig) return metaConfig;

  const envConfig = normalizeBase(import.meta.env.VITE_API_BASE_URL as string | undefined);
  if (envConfig) return envConfig;

  return ENV_DEFAULT_API_BASE;
}

export function buildRuntimeApiUrl(path: string): URL {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const base = getRuntimeApiBase();
  if (base.startsWith("/")) {
    return new URL(`${base}${normalizedPath}`, window.location.origin);
  }
  return new URL(`${base}${normalizedPath}`);
}
