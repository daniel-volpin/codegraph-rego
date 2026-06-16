import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Breadcrumbs from "./Breadcrumbs";

describe("Breadcrumbs", () => {
  it("renders the dashboard crumb only once on the dashboard route", () => {
    render(
      <MemoryRouter initialEntries={["/"]}>
        <Breadcrumbs />
      </MemoryRouter>,
    );

    expect(screen.getAllByText("Dashboard")).toHaveLength(1);
    expect(screen.queryByText("/")).not.toBeInTheDocument();
  });
});
