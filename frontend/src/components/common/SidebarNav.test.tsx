import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import SidebarNav from "./SidebarNav";
import { DEMO_MODE_STORAGE_KEY } from "../../lib/api";

describe("SidebarNav", () => {
  afterEach(() => {
    localStorage.removeItem(DEMO_MODE_STORAGE_KEY);
  });

  it("desktop mode has no close button", () => {
    render(
      <MemoryRouter>
        <SidebarNav mode="desktop" />
      </MemoryRouter>,
    );

    expect(screen.queryByRole("button", { name: "Close navigation" })).not.toBeInTheDocument();
  });

  it("drawer mode renders a close button that calls onClose", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <MemoryRouter>
        <SidebarNav mode="drawer" onClose={onClose} />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("button", { name: "Close navigation" }));

    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("calls onNavigate when a nav link is clicked", async () => {
    const user = userEvent.setup();
    const onNavigate = vi.fn();
    render(
      <MemoryRouter>
        <SidebarNav mode="drawer" onNavigate={onNavigate} />
      </MemoryRouter>,
    );

    await user.click(screen.getByRole("link", { name: /Upload & Ingest/ }));

    expect(onNavigate).toHaveBeenCalledTimes(1);
  });

  it("shows Live status by default, and switches to Demo when demo mode turns on", () => {
    render(
      <MemoryRouter>
        <SidebarNav />
      </MemoryRouter>,
    );

    expect(screen.getByText("Live")).toBeInTheDocument();
    expect(screen.queryByText("Demo")).not.toBeInTheDocument();

    localStorage.setItem(DEMO_MODE_STORAGE_KEY, "true");
    act(() => {
      window.dispatchEvent(new Event("demo-mode-changed"));
    });

    expect(screen.getByText("Demo")).toBeInTheDocument();
    expect(screen.queryByText("Live")).not.toBeInTheDocument();
  });
});
