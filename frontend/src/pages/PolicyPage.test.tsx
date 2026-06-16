import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import PolicyPage from "./PolicyPage";
import { evaluatePolicies } from "../lib/api";
import { renderWithProviders } from "../test/render";

vi.mock("../lib/api", () => ({
  fetchPolicyCatalog: vi.fn().mockResolvedValue({
    benchmark_categories: [],
    framework_demo_rule_ids: [],
  }),
  evaluatePolicies: vi.fn(),
}));

vi.mock("../lib/persistence", () => ({
  persistPolicyEvaluation: vi.fn().mockResolvedValue(undefined),
  readPersistedUploadedModules: vi.fn().mockResolvedValue([]),
  readPersistedPolicyEvaluation: vi.fn().mockResolvedValue(null),
}));

describe("PolicyPage", () => {
  beforeEach(() => {
    vi.mocked(evaluatePolicies).mockReset();
  });

  it("renders a top-level page heading", async () => {
    renderWithProviders(<PolicyPage />);

    expect(
      await screen.findByRole("heading", { level: 1, name: /policy evaluation/i }),
    ).toBeInTheDocument();
  });

  it("shows a persistent error when policy evaluation fails", async () => {
    vi.mocked(evaluatePolicies).mockRejectedValue(new Error("internal"));
    const user = userEvent.setup();

    renderWithProviders(<PolicyPage />);

    const runButton = await screen.findByRole("button", { name: /run .*policy scan|run .*demo scan/i });
    await waitFor(() => expect(runButton).toBeEnabled());
    await user.click(runButton);

    expect(await screen.findByRole("alert")).toHaveTextContent("Policy evaluation failed.");
    expect(screen.getByRole("alert")).toHaveTextContent("internal");
  });
});
