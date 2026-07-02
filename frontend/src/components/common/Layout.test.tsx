import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Layout from "./Layout";

vi.mock("./HealthStatus", () => ({
  default: () => <div>Healthy</div>,
}));

describe("Layout", () => {
  it("keeps the mobile brand bar inside the banner landmark", () => {
    render(
      <MemoryRouter>
        <Layout>
          <h1>Workspace</h1>
        </Layout>
      </MemoryRouter>,
    );

    const banner = screen.getByRole("banner");
    expect(within(banner).getByText("CodeGraph")).toBeInTheDocument();
    expect(within(banner).getByRole("button", { name: /open navigation/i })).toBeInTheDocument();
  });
});
