import { PropsWithChildren } from "react";
import SidebarNav from "./SidebarNav";
import Breadcrumbs from "./Breadcrumbs";
import ActivityTray from "./ActivityTray";
import { useActivityContext } from "../context/ActivityContext";

const Layout = ({ children }: PropsWithChildren) => {
  const { activities } = useActivityContext();
  const bodyContentClass =
    activities.length > 0 ? "app-body-content has-activity" : "app-body-content";

  return (
    <div className="app-shell">
      <SidebarNav />
      <div className="app-body">
        <header className="app-header">
          <Breadcrumbs />
        </header>
        <div className={bodyContentClass}>
          <main className="app-content">{children}</main>
          <ActivityTray />
        </div>
      </div>
    </div>
  );
};

export default Layout;
