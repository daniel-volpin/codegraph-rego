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
      <nav aria-label="Breadcrumb" className="text-sm text-slate-500">
        <span aria-current="page" className="font-medium text-slate-900">{label}</span>
      </nav>
    );
  }

  return (
    <nav aria-label="Breadcrumb" className="text-sm text-slate-500">
      <Link className="hover:text-slate-900" to="/">Dashboard</Link>
      <span aria-hidden="true" className="mx-2">/</span>
      <span aria-current="page" className="font-medium text-slate-900">{label}</span>
    </nav>
  );
};

export default Breadcrumbs;
