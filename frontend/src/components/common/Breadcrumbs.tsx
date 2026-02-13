import { Link, useLocation } from "react-router-dom";

const routeLabels: Record<string, string> = {
  "/": "Overview",
  "/upload": "Upload",
  "/search": "Search",
  "/policy": "Policy"
};

const Breadcrumbs = () => {
  const location = useLocation();
  const segments = location.pathname.split("/").filter(Boolean);

  const paths = segments.reduce<string[]>((acc, segment) => {
    const previous = acc.length > 0 ? acc[acc.length - 1] : "";
    acc.push(`${previous}/${segment}`);
    return acc;
  }, []);

  const crumbs = location.pathname === "/" ? ["/"] : ["/", ...paths];

  return (
    <nav aria-label="Breadcrumb" className="breadcrumbs">
      <ol>
        {crumbs.map((path, index) => {
          const label = routeLabels[path] ?? path.split("/").pop() ?? "Home";
          const isLast = index === crumbs.length - 1;
          return (
            <li key={path}>
              {isLast ? (
                <span aria-current="page">{label}</span>
              ) : (
                <Link to={path === "/" ? "/" : path}>{label}</Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
};

export default Breadcrumbs;
