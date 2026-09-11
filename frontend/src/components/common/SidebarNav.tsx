import { useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { ShieldCheck, Upload, Settings, Scale, X, LayoutDashboard, Sparkles } from "lucide-react";
import { cn } from "../../lib/utils";
import { isDemoMode } from "../../lib/api";

const routes = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/upload", label: "Upload & Ingest", icon: Upload },
  { to: "/policy", label: "Policy Workbench", icon: Scale },
  { to: "/settings", label: "Settings", icon: Settings },
];

interface SidebarNavProps {
  mode?: "desktop" | "drawer";
  className?: string;
  onNavigate?: () => void;
  onClose?: () => void;
}

const SidebarNav = ({ mode = "desktop", className, onNavigate, onClose }: SidebarNavProps) => {
  const [demoActive, setDemoActive] = useState(() => isDemoMode());

  useEffect(() => {
    const handleDemoChange = () => setDemoActive(isDemoMode());
    window.addEventListener("demo-mode-changed", handleDemoChange);
    return () => window.removeEventListener("demo-mode-changed", handleDemoChange);
  }, []);

  return (
    <aside
      className={cn(
        "flex flex-col border-sidebar-border bg-sidebar p-5 text-sidebar-foreground select-none",
        mode === "desktop" && "sticky top-0 h-screen w-72 border-r",
        mode === "drawer" && "h-full w-72",
        className,
      )}
    >
      {mode === "drawer" && (
        <div className="mb-3 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-sidebar-muted transition hover:bg-sidebar-border hover:text-white"
            aria-label="Close navigation"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
      )}

      {/* Brand Header */}
      <div className="mb-6 flex items-center gap-3 px-2 pt-1">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white shadow-sm ring-1 ring-white/20">
          <ShieldCheck className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <div className="font-semibold tracking-tight text-white flex items-center gap-2">
            <span>CodeGraph</span>
            <span className="rounded bg-indigo-950/80 px-1.5 py-0.5 text-[10px] font-mono font-medium text-indigo-300 border border-indigo-800/60">
              REGO
            </span>
          </div>
          <div className="text-[11px] font-medium tracking-wide text-sidebar-muted truncate">
            Compliance Workbench
          </div>
        </div>
      </div>

      <div className="px-2 pb-2">
        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
          Workspace
        </p>
      </div>

      <nav aria-label="Primary" className="space-y-1">
        {routes.map((route) => {
          const Icon = route.icon;
          return (
            <NavLink
              key={route.to}
              to={route.to}
              end={route.to === "/"}
              onClick={onNavigate}
              className={({ isActive }) =>
                cn(
                  "group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all",
                  isActive
                    ? "bg-indigo-600/90 text-white shadow-xs"
                    : "text-slate-300 hover:bg-slate-800/70 hover:text-white",
                )
              }
            >
              <Icon className="h-4 w-4 shrink-0 transition-transform group-hover:scale-105" />
              <span className="truncate">{route.label}</span>
            </NavLink>
          );
        })}
      </nav>

      <div className="mt-auto pt-6 border-t border-slate-800/80 px-2 space-y-2">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span>Engine Status</span>
          {demoActive ? (
            <span className="inline-flex items-center gap-1 font-mono text-amber-300">
              <Sparkles className="h-3 w-3 text-amber-400" />
              Demo
            </span>
          ) : (
            <span className="inline-flex items-center gap-1 font-mono text-slate-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Live
            </span>
          )}
        </div>
        <div className="text-[10px] text-slate-400 font-mono">
          {demoActive ? "Interactive Thesis Fixtures" : "Neurosymbolic OPA v0.5.0"}
        </div>
      </div>
    </aside>
  );
};

export default SidebarNav;

