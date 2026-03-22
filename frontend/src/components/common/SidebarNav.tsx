import { NavLink } from "react-router-dom";
import { ShieldCheck, Upload, Search, Settings, Scale, X } from "lucide-react";
import { cn } from "../../lib/utils";

const routes = [
  { to: "/upload", label: "Upload", icon: Upload },
  { to: "/search", label: "Search", icon: Search },
  { to: "/policy", label: "Policy", icon: Scale },
  { to: "/settings", label: "Settings", icon: Settings },
];

interface SidebarNavProps {
  mode?: "desktop" | "drawer";
  className?: string;
  onNavigate?: () => void;
  onClose?: () => void;
}

const SidebarNav = ({ mode = "desktop", className, onNavigate, onClose }: SidebarNavProps) => {
  return (
    <aside
      className={cn(
        "flex flex-col border-sidebar-border bg-sidebar p-6 text-sidebar-foreground",
        mode === "desktop" && "sticky top-0 h-screen w-72 border-r",
        mode === "drawer" && "h-full w-72",
        className,
      )}
    >
      {mode === "drawer" && (
        <div className="mb-4 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-sidebar-foreground transition hover:bg-sidebar-border hover:text-white"
            aria-label="Close navigation"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
      )}
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
              onClick={onNavigate}
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
