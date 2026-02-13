import { NavLink } from "react-router-dom";
import "./Sidebar.css";

const routes = [
  { to: "/", label: "Overview" },
  { to: "/upload", label: "Upload" },
  { to: "/search", label: "Search" },
  { to: "/policy", label: "Policy" }
];

const SidebarNav = () => {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `sidebar-link${isActive ? " sidebar-link-active" : ""}`;

  return (
    <div className="sidebar-nav">
      <div className="sidebar-brand">
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
          <div style={{ width: "32px", height: "32px", borderRadius: "8px", background: "linear-gradient(135deg, var(--color-primary-500), var(--color-primary-700))" }}></div>
          <span className="nav-logo">CodeGraph</span>
        </div>
        <span className="nav-subtitle">Compliance & Search Console</span>
      </div>
      <nav>
        <ul>
          {routes.map((route) => (
            <li key={route.to}>
              <NavLink className={linkClass} to={route.to}>
                {route.label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
};

export default SidebarNav;
