import { screen, within } from "@testing-library/react";
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

  const findDisclosureControl = (name: RegExp) => screen.findByLabelText(name, { selector: "summary" });

  it("renders a healthy state as a collapsed native disclosure", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    renderWithProviders(<HealthStatus />);

    const summary = await findDisclosureControl(/backend status: healthy\. expand dependency details/i);
    const disclosure = summary.closest("details");

    expect(summary.tagName).toBe("SUMMARY");
    expect(disclosure).not.toHaveAttribute("open");
    expect(summary).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("region", { name: /backend dependency status/i })).not.toBeInTheDocument();
  });

  it("expands to per-dependency detail", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    const summary = await findDisclosureControl(/backend status: healthy\. expand dependency details/i);

    await user.click(summary);
    expect(summary.closest("details")).toHaveAttribute("open");
    expect(summary).toHaveAttribute("aria-expanded", "true");
    expect(summary).toHaveAccessibleName(/backend status: healthy\. collapse dependency details/i);

    const region = screen.getByRole("region", { name: /backend dependency status/i });
    expect(region).toHaveTextContent("Neo4j code knowledge graph");
    expect(region).toHaveTextContent("OPA policy compliance engine");
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

    const summary = await findDisclosureControl(/backend status: degraded \(2\)\. expand dependency details/i);
    expect(summary).toHaveTextContent("Degraded (2)");

    await user.click(summary);

    expect(screen.getByText("connection refused")).toBeInTheDocument();
    expect(screen.getByText("opa executable not found on PATH")).toBeInTheDocument();

    const region = screen.getByRole("region", { name: /backend dependency status/i });
    expect(within(region).getByText(/neo4j code knowledge graph/i).parentElement).toHaveTextContent(/unavailable/i);
    expect(within(region).getByText(/opa policy compliance engine/i).parentElement).toHaveTextContent(/unavailable/i);
  });

  it("shows backend detail strings for every degraded dependency family", async () => {
    vi.mocked(fetchHealth).mockResolvedValue({
      ...healthyPayload,
      status: "degraded" as const,
      startup_ready: false,
      signature_map: false,
      details: {
        startup: "preload still running",
        signature_map: "signature map missing",
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    await user.click(await findDisclosureControl(/backend status: degraded \(2\)\. expand dependency details/i));

    expect(screen.getByText("preload still running")).toBeInTheDocument();
    expect(screen.getByText("signature map missing")).toBeInTheDocument();
  });

  it("offers guidance and a manual re-check when the backend is unreachable", async () => {
    vi.mocked(fetchHealth).mockRejectedValue(new Error("network down"));
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    await user.click(await findDisclosureControl(/backend status: backend unreachable\. expand dependency details/i));

    expect(screen.getByText(/health endpoint could not be reached/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /re-check now/i })).toBeInTheDocument();
  });

  it("closes the detail panel on Escape", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    const summary = await findDisclosureControl(/backend status: healthy\. expand dependency details/i);
    await user.click(summary);
    expect(screen.getByRole("region", { name: /backend dependency status/i })).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("region", { name: /backend dependency status/i })).not.toBeInTheDocument();
  });

  it("toggles through native keyboard-compatible disclosure behavior", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    const user = userEvent.setup();
    renderWithProviders(<HealthStatus />);

    const summary = await findDisclosureControl(/backend status: healthy\. expand dependency details/i);
    summary.focus();

    await user.keyboard("{Enter}");
    expect(summary.closest("details")).toHaveAttribute("open");
    expect(screen.getByRole("region", { name: /backend dependency status/i })).toBeInTheDocument();

    await user.keyboard("{Enter}");
    expect(summary.closest("details")).not.toHaveAttribute("open");
    expect(screen.queryByRole("region", { name: /backend dependency status/i })).not.toBeInTheDocument();
  });
});
