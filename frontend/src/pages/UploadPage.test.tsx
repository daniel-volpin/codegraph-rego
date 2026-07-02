import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import UploadPage from "./UploadPage";
import { renderWithProviders } from "../test/render";

vi.mock("../lib/api", () => ({
  uploadZip: vi.fn(),
  fetchUploadStatus: vi.fn().mockResolvedValue({
    phase: "idle",
    message: "",
    progress: 0,
    complete: true,
    error: null,
    updated_at: new Date().toISOString(),
  }),
}));

vi.mock("../hooks/useUploadStatusStream", () => ({
  useUploadStatusStream: vi.fn().mockReturnValue({ streamConnected: false }),
}));

vi.mock("../lib/persistence", () => ({
  clearPersistedPolicyEvaluations: vi.fn().mockResolvedValue(undefined),
  persistLastUpload: vi.fn().mockResolvedValue(undefined),
  readPersistedLastUpload: vi.fn().mockResolvedValue(null),
}));

const dropFile = (target: HTMLElement, file: File) => {
  fireEvent.drop(target, { dataTransfer: { files: [file] } });
};

describe("UploadPage", () => {
  it("keeps the file input keyboard-focusable (not display:none)", async () => {
    renderWithProviders(<UploadPage />);

    const input = await screen.findByLabelText(/select zip archive/i);
    expect(input).toBeVisible(); // sr-only elements remain visible to AT and focus
    input.focus();
    expect(input).toHaveFocus();
  });

  it("accepts a dropped .zip and shows name and size", async () => {
    renderWithProviders(<UploadPage />);

    const dropzone = await screen.findByTestId("upload-dropzone");
    dropFile(dropzone, new File(["x".repeat(2048)], "workspace.zip", { type: "application/zip" }));

    expect(await screen.findByText(/workspace\.zip · 2\.0 KB/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /upload & ingest/i })).toBeEnabled();
  });

  it("rejects a dropped non-zip file and keeps upload disabled", async () => {
    renderWithProviders(<UploadPage />);

    const dropzone = await screen.findByTestId("upload-dropzone");
    dropFile(dropzone, new File(["x"], "notes.txt", { type: "text/plain" }));

    expect(screen.queryByText(/notes\.txt/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /upload & ingest/i })).toBeDisabled();
  });

  it("accepts a file chosen through the input", async () => {
    const user = userEvent.setup();
    renderWithProviders(<UploadPage />);

    const input = await screen.findByLabelText(/select zip archive/i);
    await user.upload(input, new File(["zipbytes"], "app.zip", { type: "application/zip" }));

    expect(await screen.findByText(/app\.zip/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /upload & ingest/i })).toBeEnabled();
  });
});
