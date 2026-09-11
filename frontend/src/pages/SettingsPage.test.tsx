import { screen } from "@testing-library/react";
import SettingsPage from "./SettingsPage";
import { renderWithProviders } from "../test/render";

describe("SettingsPage", () => {
  it("renders API configuration and runtime settings", () => {
    renderWithProviders(<SettingsPage />);

    expect(screen.getByRole("heading", { level: 1, name: /settings & observability/i })).toBeInTheDocument();
    expect(screen.getByText(/runtime api base url/i)).toBeInTheDocument();
    expect(screen.getByTestId("observability-card")).toBeInTheDocument();
    expect(screen.getByTestId("tracing-status-badge")).toBeInTheDocument();
  });

  it("renders quick reference links", () => {
    renderWithProviders(<SettingsPage />);

    expect(screen.getByRole("link", { name: /fastapi swagger documentation/i })).toHaveAttribute("target", "_blank");
    expect(screen.getByRole("link", { name: /direct health check endpoint/i })).toHaveAttribute("target", "_blank");
  });
});
