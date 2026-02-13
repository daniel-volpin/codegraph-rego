import { PropsWithChildren } from "react";
import SidebarNav from "./SidebarNav";
import Breadcrumbs from "./Breadcrumbs";
import ActivityTray from "./ActivityTray";
import { Toaster } from "react-hot-toast";
import { useActivityContext } from "../../context/ActivityContext";

import HealthStatus from "./HealthStatus";

const Layout = ({ children }: PropsWithChildren) => {
  useActivityContext();

  return (
    <div className="app-shell">
      <SidebarNav />
      <div className="app-body">
        <header className="app-header">
          <Breadcrumbs />
          <HealthStatus variant="header" />
        </header>
        <div className="app-body-content">
          <main className="app-content">{children}</main>
          <ActivityTray />
        </div>
      </div>
      <Toaster position="top-right" toastOptions={{ duration: 4000 }} />
    </div>
  );
};

export default Layout;
