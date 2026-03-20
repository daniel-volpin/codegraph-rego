import { Suspense, lazy } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/common/Layout";

const HomePage = lazy(() => import("./pages/HomePage"));
const UploadPage = lazy(() => import("./pages/UploadPage"));
const SearchPage = lazy(() => import("./pages/SearchPage"));
const PolicyPage = lazy(() => import("./pages/PolicyPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

const PageFallback = () => (
  <div className="rounded-lg border border-slate-200 bg-white p-6 text-sm text-slate-600 shadow-sm">
    Loading workspace...
  </div>
);

const App = () => {
  return (
    <Layout>
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
    </Layout>
  );
};

export default App;
