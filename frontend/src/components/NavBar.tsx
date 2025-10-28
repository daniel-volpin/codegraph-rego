import { NavLink } from "react-router-dom";

const NavBar = () => {
  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `nav-link${isActive ? " nav-link-active" : ""}`;

  return (
    <header className="nav-bar">
      <div className="nav-brand">
        <span className="nav-logo">CodeGraph</span>
        <span className="nav-subtitle">Java knowledge graph & policy insights</span>
      </div>
      <nav className="nav-links">
        <NavLink className={linkClass} to="/upload">
          Upload
        </NavLink>
        <NavLink className={linkClass} to="/search">
          Search
        </NavLink>
        <NavLink className={linkClass} to="/policy">
          Policy
        </NavLink>
      </nav>
    </header>
  );
};

export default NavBar;
