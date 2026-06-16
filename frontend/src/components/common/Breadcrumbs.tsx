import { Link, useLocation } from "react-router-dom";

const routeLabels: Record<string, string> = {
  "/": "Dashboard",
  "/upload": "Upload",
  "/search": "Search",
  "/policy": "Policy",
  "/settings": "Settings",
};

const Breadcrumbs = () => {
  const location = useLocation();
  const label = routeLabels[location.pathname] ?? "Page";
  if (location.pathname === "/") {
    return (
      <div className="text-sm text-slate-500">
        <span className="font-medium text-slate-900">{label}</span>
      </div>
    );
  }

  return (
    <div className="text-sm text-slate-500">
      <Link className="hover:text-slate-900" to="/">Dashboard</Link>
      <span className="mx-2">/</span>
      <span className="font-medium text-slate-900">{label}</span>
    </div>
  );
};

export default Breadcrumbs;
