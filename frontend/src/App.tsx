import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/common/Layout";
import HomePage from "./pages/HomePage";
import UploadPage from "./pages/UploadPage";
import SearchPage from "./pages/SearchPage";
import PolicyPage from "./pages/PolicyPage";
import SettingsPage from "./pages/SettingsPage";

const App = () => {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="/policy" element={<PolicyPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/upload" replace />} />
      </Routes>
    </Layout>
  );
};

export default App;
