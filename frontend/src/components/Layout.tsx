import { PropsWithChildren } from "react";
import NavBar from "./NavBar";

const Layout = ({ children }: PropsWithChildren) => {
  return (
    <div className="app-shell">
      <NavBar />
      <main className="app-content">{children}</main>
    </div>
  );
};

export default Layout;
