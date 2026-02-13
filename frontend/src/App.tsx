import { Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/common/Layout";
import HomePage from "./pages/HomePage";
import UploadPage from "./pages/UploadPage";
import SearchPage from "./pages/SearchPage";
import PolicyPage from "./pages/PolicyPage";

import "./App.css";

const App = () => {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/search" element={<SearchPage />} />

        <Route path="/policy" element={<PolicyPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
};

export default App;
