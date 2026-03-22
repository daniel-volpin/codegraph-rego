import { PropsWithChildren, useEffect, useState } from "react";
import { Menu, ShieldCheck } from "lucide-react";
import SidebarNav from "./SidebarNav";
import Breadcrumbs from "./Breadcrumbs";
import ActivityTray from "./ActivityTray";
import { Toaster } from "sonner";
import HealthStatus from "./HealthStatus";

const Layout = ({ children }: PropsWithChildren) => {
  const [isDrawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    if (!isDrawerOpen) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawerOpen(false);
      }
    };

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [isDrawerOpen]);

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="sticky top-0 z-30 flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 lg:hidden">
        <button
          type="button"
          aria-label="Open navigation"
          onClick={() => setDrawerOpen(true)}
          className="rounded-md p-2 text-slate-700 transition hover:bg-slate-100"
        >
          <Menu className="h-5 w-5" />
        </button>
        <div className="flex items-center gap-2">
          <div className="rounded-md bg-indigo-600 p-1.5 text-white">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <span className="text-sm font-semibold text-slate-900">CodeGraph</span>
        </div>
        <div className="w-9" />
      </div>

      {isDrawerOpen && (
        <div className="fixed inset-0 z-40 bg-slate-900/50 lg:hidden" onClick={() => setDrawerOpen(false)}>
          <div className="h-full" onClick={(event) => event.stopPropagation()}>
            <SidebarNav
              mode="drawer"
              onClose={() => setDrawerOpen(false)}
              onNavigate={() => setDrawerOpen(false)}
            />
          </div>
        </div>
      )}

      <div className="lg:grid lg:min-h-screen lg:grid-cols-[18rem_1fr]">
        <SidebarNav className="hidden lg:flex" />
        <div className="p-4 sm:p-6 xl:p-8">
          <header className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3">
            <div className="min-w-0">
              <Breadcrumbs />
            </div>
            <div className="hidden sm:block">
              <HealthStatus variant="header" />
            </div>
            <div className="sm:hidden">
              <HealthStatus variant="panel" />
            </div>
          </header>
          <div className="flex flex-col gap-6 lg:flex-row">
            <main className="min-w-0 flex-1">{children}</main>
            <ActivityTray />
          </div>
        </div>
      </div>
      <Toaster richColors position="top-right" />
    </div>
  );
};

export default Layout;
