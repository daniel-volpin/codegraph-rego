const ENV_DEFAULT_API_BASE = "http://127.0.0.1:8000";

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
  return trimmed.replace(/\/+$/, "");
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
