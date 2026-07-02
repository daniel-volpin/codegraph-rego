import { PropsWithChildren, useState } from "react";
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

const Layout = ({ children }: PropsWithChildren) => {
  const [isDrawerOpen, setDrawerOpen] = useState(false);

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Skip-to-content link (WCAG 2.4.1) — visually hidden until focused. */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-white focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-slate-900 focus:shadow"
      >
        Skip to main content
      </a>

      <Dialog open={isDrawerOpen} onOpenChange={setDrawerOpen}>
        <div className="sticky top-0 z-30 flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 lg:hidden">
          {/* Radix manages aria-expanded/aria-controls and focus return for us. */}
          <button
            type="button"
            aria-label="Open navigation"
            onClick={() => setDrawerOpen(true)}
            className="rounded-md p-2 text-slate-700 transition hover:bg-slate-100"
          >
            <Menu aria-hidden="true" className="h-5 w-5" />
          </button>
          <div className="flex items-center gap-2">
            <div className="rounded-md bg-indigo-600 p-1.5 text-white">
              <ShieldCheck aria-hidden="true" className="h-4 w-4" />
            </div>
            <span className="text-sm font-semibold text-slate-900">CodeGraph</span>
          </div>
          <div className="w-9" />
        </div>

        <DialogPortal>
          <DialogOverlay className="lg:hidden" />
          <DialogContent
            className="lg:hidden w-72"
            // Radix Dialog gives us focus trap, scroll lock, Escape-to-close,
            // overlay-click dismiss, and focus restoration by construction.
            // We still suppress its default "focus first element" so the
            // drawer's nav close button isn't auto-focused on every open.
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
        <div className="p-4 sm:p-6 xl:p-8">
          <header className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3">
            <div className="min-w-0">
              <Breadcrumbs />
            </div>
            <HealthStatus />
          </header>
          <div className="flex flex-col gap-6 lg:flex-row">
            <main id="main-content" className="min-w-0 flex-1">
              {children}
            </main>
            <ActivityTray />
          </div>
        </div>
      </div>
      <Toaster richColors position="top-right" />
    </div>
  );
};

export default Layout;
