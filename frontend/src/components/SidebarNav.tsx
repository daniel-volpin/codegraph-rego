import { NavLink } from "react-router-dom";

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
        <span className="nav-logo">CodeGraph</span>
        <span className="nav-subtitle">Knowledge Graph Console</span>
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
