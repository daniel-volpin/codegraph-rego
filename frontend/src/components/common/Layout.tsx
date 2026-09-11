import { type CSSProperties, type PropsWithChildren, useState } from "react";
import { Menu, ShieldCheck } from "lucide-react";
import SidebarNav from "./SidebarNav";
import Breadcrumbs from "./Breadcrumbs";
import ActivityTray from "./ActivityTray";
import { Toaster } from "sonner";
import HealthStatus from "./HealthStatus";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
} from "../ui/dialog";

type ToastColorVars = CSSProperties & Record<`--${string}`, string>;

const toastColorVars: ToastColorVars = {
  "--success-bg": "#ecfdf5",
  "--success-border": "#a7f3d0",
  "--success-text": "#064e3b",
  "--info-bg": "#eef2ff",
  "--info-border": "#c7d2fe",
  "--info-text": "#312e81",
  "--warning-bg": "#fffbeb",
  "--warning-border": "#fde68a",
  "--warning-text": "#78350f",
  "--error-bg": "#fff1f2",
  "--error-border": "#fecdd3",
  "--error-text": "#881337",
};

const Layout = ({ children }: PropsWithChildren) => {
  const [isDrawerOpen, setDrawerOpen] = useState(false);

  return (
    <div className="min-h-screen bg-slate-50/80 text-slate-900 antialiased">
      {/* Skip-to-content link (WCAG 2.4.1) — visually hidden until focused. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-indigo-600 focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-white focus:shadow-md"
      >
        Skip to main content
      </a>

      <Dialog open={isDrawerOpen} onOpenChange={setDrawerOpen}>
        <header className="sticky top-0 z-30 flex items-center justify-between border-b border-slate-200 bg-white/95 px-4 py-2.5 backdrop-blur-xs lg:hidden">
          <button
            type="button"
            aria-label="Open navigation"
            onClick={() => setDrawerOpen(true)}
            className="rounded-lg p-2 text-slate-700 transition hover:bg-slate-100"
          >
            <Menu aria-hidden="true" className="h-5 w-5" />
          </button>
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-600 text-white shadow-xs">
              <ShieldCheck aria-hidden="true" className="h-4 w-4" />
            </div>
            <span className="text-sm font-semibold tracking-tight text-slate-900">CodeGraph</span>
          </div>
          <div className="w-9" />
        </header>

        <DialogPortal>
          <DialogOverlay className="lg:hidden" />
          <DialogContent
            className="lg:hidden w-72"
            onOpenAutoFocus={(event) => event.preventDefault()}
          >
            <DialogTitle className="sr-only">Primary navigation</DialogTitle>
            <DialogDescription className="sr-only">
              Navigate between CodeGraph workspace pages.
            </DialogDescription>
            <SidebarNav
              mode="drawer"
              onClose={() => setDrawerOpen(false)}
              onNavigate={() => setDrawerOpen(false)}
            />
          </DialogContent>
        </DialogPortal>
      </Dialog>

      <div className="lg:grid lg:min-h-screen lg:grid-cols-[18rem_1fr]">
        <SidebarNav className="hidden lg:flex" />
        <div className="p-4 sm:p-6 xl:p-8 min-w-0">
          <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200/80 bg-white px-4 py-2.5 shadow-subtle">
            <div className="min-w-0">
              <Breadcrumbs />
            </div>
            <div className="flex items-center gap-3">
              <HealthStatus />
            </div>
          </div>
          <div className="flex flex-col gap-6 lg:flex-row">
            <main id="main-content" className="min-w-0 flex-1">
              {children}
            </main>
            <ActivityTray />
          </div>
        </div>
      </div>
      <Toaster
        richColors
        position="top-right"
        style={toastColorVars}
        toastOptions={{
          classNames: {
            success: "border-emerald-300 bg-emerald-50 text-emerald-950 font-medium",
            error: "border-rose-300 bg-rose-50 text-rose-950 font-medium",
            warning: "border-amber-300 bg-amber-50 text-amber-950 font-medium",
            info: "border-indigo-300 bg-indigo-50 text-indigo-950 font-medium",
            title: "text-current",
            description: "text-current",
          },
        }}
      />
    </div>
  );
};

export default Layout;

