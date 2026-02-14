import { PropsWithChildren } from "react";
import SidebarNav from "./SidebarNav";
import Breadcrumbs from "./Breadcrumbs";
import ActivityTray from "./ActivityTray";
import { Toaster } from "sonner";
import HealthStatus from "./HealthStatus";

const Layout = ({ children }: PropsWithChildren) => {
  return (
    <div className="grid min-h-screen grid-cols-[18rem_1fr] bg-slate-50">
      <SidebarNav />
      <div className="p-6 xl:p-8">
        <header className="mb-6 flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3">
          <Breadcrumbs />
          <HealthStatus variant="header" />
        </header>
        <div className="flex gap-6">
          <main className="min-w-0 flex-1">{children}</main>
          <ActivityTray />
        </div>
      </div>
      <Toaster richColors position="top-right" />
    </div>
  );
};

export default Layout;
