import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { ActivityProvider } from "./context/ActivityContext";
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
});

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ActivityProvider>
          <App />
        </ActivityProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
