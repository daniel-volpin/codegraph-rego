import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import HealthStatus from "./HealthStatus";
import { fetchHealth } from "../../lib/api";
import { renderWithProviders } from "../../test/render";

vi.mock("../../lib/api", () => ({
  fetchHealth: vi.fn(),
}));

const healthyPayload = {
  status: "ok" as const,
  startup_ready: true,
  neo4j: true,
  faiss_index: true,
  signature_map: true,
  embedding_model: true,
  opa: true,
  startup: { ready: true, phase: "ready" as const, checks: {}, errors: {} },
  details: {},
};

describe("HealthStatus", () => {
  beforeEach(() => {
    vi.mocked(fetchHealth).mockReset();
  });

  it("summarizes a healthy backend and expands to per-dependency detail", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    const summary = await screen.findByRole("button", { name: /healthy/i });
    expect(summary).toHaveAttribute("aria-expanded", "false");

    await user.click(summary);
    expect(summary).toHaveAttribute("aria-expanded", "true");
    const region = screen.getByRole("region", { name: /backend dependency status/i });
    expect(region).toHaveTextContent("Neo4j graph database");
    expect(region).toHaveTextContent("OPA policy engine");
  });

  it("shows degraded count and failure detail without relying on color", async () => {
    vi.mocked(fetchHealth).mockResolvedValue({
      ...healthyPayload,
      status: "degraded" as const,
      neo4j: false,
      opa: false,
      details: { neo4j: "connection refused", opa: "opa executable not found on PATH" },
    });
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    await user.click(await screen.findByRole("button", { name: /degraded \(2\)/i }));

    expect(screen.getByText("connection refused")).toBeInTheDocument();
    expect(screen.getByText("opa executable not found on PATH")).toBeInTheDocument();
    // State is exposed to assistive tech as text, not only as color.
    expect(screen.getAllByText(/unavailable/i).length).toBeGreaterThanOrEqual(2);
  });

  it("offers guidance and a manual re-check when the backend is unreachable", async () => {
    vi.mocked(fetchHealth).mockRejectedValue(new Error("network down"));
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    await user.click(await screen.findByRole("button", { name: /backend unreachable/i }));

    expect(screen.getByText(/health endpoint could not be reached/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /re-check now/i })).toBeInTheDocument();
  });

  it("closes the detail panel on Escape", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    await user.click(await screen.findByRole("button", { name: /healthy/i }));
    expect(screen.getByRole("region", { name: /backend dependency status/i })).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("region", { name: /backend dependency status/i })).not.toBeInTheDocument();
  });
});
