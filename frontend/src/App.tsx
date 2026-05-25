import { Suspense, lazy } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useQueryErrorResetBoundary } from "@tanstack/react-query";
import Layout from "./components/common/Layout";
import ErrorBoundary from "./components/common/ErrorBoundary";
import { reportError } from "./lib/observability";

const HomePage = lazy(() => import("./pages/HomePage"));
const UploadPage = lazy(() => import("./pages/UploadPage"));
const SearchPage = lazy(() => import("./pages/SearchPage"));
const PolicyPage = lazy(() => import("./pages/PolicyPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

const PageFallback = () => (
  <div
    role="status"
    aria-live="polite"
    className="rounded-lg border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-sm"
  >
    Loading workspace...
  </div>
);

const App = () => {
  const { reset } = useQueryErrorResetBoundary();
  return (
    <Layout>
      <ErrorBoundary
        onError={(error, info) => {
          reportError(error, { source: "render", componentStack: info.componentStack });
        }}
        // Reset React Query error state when the user retries; ensures stale
        // failed queries are refetched rather than re-throwing immediately.
        fallback={(error, retry) => (
          <div
            role="alert"
            aria-live="assertive"
            className="rounded-lg border border-rose-300 bg-rose-50 p-6 text-rose-900"
          >
            <h2 className="text-base font-semibold">Page failed to render</h2>
            <p className="mt-1 text-sm">{error.message}</p>
            <button
              type="button"
              className="mt-3 text-sm underline hover:no-underline"
              onClick={() => {
                reset();
                retry();
              }}
            >
              Try again
            </button>
          </div>
        )}
      >
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/policy" element={<PolicyPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/upload" replace />} />
          </Routes>
        </Suspense>
      </ErrorBoundary>
    </Layout>
  );
};

export default App;
