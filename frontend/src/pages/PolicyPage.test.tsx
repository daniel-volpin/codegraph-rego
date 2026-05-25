import { screen } from "@testing-library/react";
import { vi } from "vitest";
import PolicyPage from "./PolicyPage";
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
  it("renders a top-level page heading", async () => {
    renderWithProviders(<PolicyPage />);

    expect(
      await screen.findByRole("heading", { level: 1, name: /policy evaluation/i }),
    ).toBeInTheDocument();
  });
});
