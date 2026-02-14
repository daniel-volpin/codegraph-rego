import { NavLink } from "react-router-dom";
import { ShieldCheck, Upload, Search, Settings, Scale } from "lucide-react";
import { cn } from "../../lib/utils";

const routes = [
  { to: "/upload", label: "Upload", icon: Upload },
  { to: "/search", label: "Search", icon: Search },
  { to: "/policy", label: "Policy", icon: Scale },
  { to: "/settings", label: "Settings", icon: Settings },
];

const SidebarNav = () => {
  return (
    <aside className="sticky top-0 flex h-screen w-72 flex-col border-r border-sidebar-border bg-sidebar p-6 text-sidebar-foreground">
      <div className="mb-8 flex items-center gap-3">
        <div className="rounded-lg bg-sidebar-accent p-2">
          <ShieldCheck className="h-5 w-5 text-white" />
        </div>
        <div>
          <div className="font-semibold text-white">CodeGraph</div>
          <div className="text-xs uppercase tracking-wide text-sidebar-muted">Security Research Framework</div>
        </div>
      </div>
      <nav className="space-y-1">
        {routes.map((route) => {
          const Icon = route.icon;
          return (
            <NavLink
              key={route.to}
              to={route.to}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground transition hover:bg-sidebar-border hover:text-white",
                  isActive && "bg-sidebar-accent text-white shadow",
                )
              }
            >
              <Icon className="h-4 w-4" />
              {route.label}
            </NavLink>
          );
        })}
      </nav>
    </aside>
  );
};

export default SidebarNav;
