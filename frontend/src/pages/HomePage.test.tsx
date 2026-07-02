import { screen } from "@testing-library/react";
import { vi } from "vitest";
import HomePage from "./HomePage";
import { fetchHealth } from "../lib/api";
import { readPersistedLastUpload } from "../lib/persistence";
import { renderWithProviders } from "../test/render";

vi.mock("../lib/api", () => ({
  fetchHealth: vi.fn(),
}));

vi.mock("../lib/persistence", () => ({
  readPersistedLastUpload: vi.fn(),
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

describe("HomePage", () => {
  beforeEach(() => {
    vi.mocked(fetchHealth).mockReset();
    vi.mocked(readPersistedLastUpload).mockReset();
  });

  it("renders loading states for backend health and workspace hydration", () => {
    vi.mocked(fetchHealth).mockReturnValue(new Promise(() => {}));
    vi.mocked(readPersistedLastUpload).mockReturnValue(new Promise(() => {}));

    renderWithProviders(<HomePage />);

    expect(screen.getByRole("heading", { name: /codegraph workspace/i })).toBeInTheDocument();
    expect(screen.getByText(/checking backend dependencies/i)).toBeInTheDocument();
    expect(screen.getByText(/loading workspace state/i)).toBeInTheDocument();
  });

  it("renders a healthy backend and empty workspace next step", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    vi.mocked(readPersistedLastUpload).mockResolvedValue(null);

    renderWithProviders(<HomePage />);

    expect(await screen.findByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("Startup preload")).toBeInTheDocument();
    expect(screen.getByText("Signature map")).toBeInTheDocument();
    expect(screen.getAllByText("Available")).toHaveLength(6);
    expect(await screen.findByText(/no uploaded workspace yet/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /1\. upload a codebase/i })).toHaveAttribute("href", "/upload");
  });

  it("renders degraded dependency meaning as text, not color alone", async () => {
    vi.mocked(fetchHealth).mockResolvedValue({
      ...healthyPayload,
      status: "degraded" as const,
      startup_ready: false,
      signature_map: false,
    });
    vi.mocked(readPersistedLastUpload).mockResolvedValue(null);

    renderWithProviders(<HomePage />);

    expect(await screen.findByText("Degraded")).toBeInTheDocument();
    expect(screen.getAllByText("Unavailable")).toHaveLength(2);
    expect(screen.getByText(/degraded dependencies usually mean/i)).toBeInTheDocument();
  });

  it("guides users to settings when the backend is unreachable", async () => {
    vi.mocked(fetchHealth).mockRejectedValue(new Error("network down"));
    vi.mocked(readPersistedLastUpload).mockResolvedValue(null);

    renderWithProviders(<HomePage />);

    expect(await screen.findByText("Unreachable")).toBeInTheDocument();
    expect(screen.getByText(/backend could not be reached/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /settings page/i })).toHaveAttribute("href", "/settings");
  });

  it("summarizes persisted modules and changes the upload action", async () => {
    vi.mocked(fetchHealth).mockResolvedValue(healthyPayload);
    vi.mocked(readPersistedLastUpload).mockResolvedValue({
      status: "success",
      java_roots: ["/tmp/uploaded_code/api/src/main/java", "/tmp/uploaded_code/web/src/main/java"],
    });

    renderWithProviders(<HomePage />);

    expect(await screen.findByText(/last successful upload detected 2 modules/i)).toBeInTheDocument();
    expect(screen.getByText("api")).toBeInTheDocument();
    expect(screen.getByText("web")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /1\. replace the workspace/i })).toHaveAttribute("href", "/upload");
  });
});
