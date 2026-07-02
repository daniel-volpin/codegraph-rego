import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { vi } from "vitest";
import SearchPage from "./SearchPage";
import { searchCode } from "../lib/api";
import { renderWithProviders } from "../test/render";

vi.mock("../lib/api", () => ({
  searchCode: vi.fn(),
}));

describe("SearchPage", () => {
  beforeEach(() => {
    vi.mocked(searchCode).mockReset();
  });

  it("submits with the keyboard and exposes loading state", async () => {
    const user = userEvent.setup();
    vi.mocked(searchCode).mockReturnValue(new Promise(() => undefined));

    renderWithProviders(<SearchPage />);

    await user.type(screen.getByRole("searchbox", { name: /search query/i }), "MessageDigest{Enter}");

    expect(searchCode).toHaveBeenCalledWith("MessageDigest", expect.any(AbortSignal));
    expect(screen.getByRole("status", { name: /search status/i })).toHaveTextContent(/searching the code graph/i);
  });

  it("renders no-results guidance after a successful empty search", async () => {
    vi.mocked(searchCode).mockResolvedValue({ matches: [], contexts: [] });
    const user = userEvent.setup();

    renderWithProviders(<SearchPage />);

    await user.type(screen.getByRole("searchbox", { name: /search query/i }), "missing pattern");
    await user.click(screen.getByRole("button", { name: /^search$/i }));

    expect(await screen.findByRole("status", { name: /search status/i })).toHaveTextContent(/0 results/i);
    expect(screen.getByText(/no results found/i)).toBeInTheDocument();
    expect(screen.getByText(/try a more specific method name/i)).toBeInTheDocument();
  });

  it("renders results, selected state, and details from backend contexts", async () => {
    vi.mocked(searchCode).mockResolvedValue({
      matches: [
        "com.acme.crypto.HashService.md5(java.lang.String)",
        "com.acme.web.SearchController.search(java.lang.String)",
      ],
      contexts: [
        [
          {
            method: "com.acme.crypto.HashService.md5(java.lang.String)",
            neighbors: [{ file_path: "src/main/java/com/acme/HashService.java", code_snippet: "MessageDigest.getInstance(\"MD5\")" }],
          },
        ],
        [
          {
            method: "com.acme.web.SearchController.search(java.lang.String)",
            neighbors: [{ file_path: "src/main/java/com/acme/SearchController.java" }],
          },
        ],
      ],
    });
    const user = userEvent.setup();

    renderWithProviders(<SearchPage />);

    await user.type(screen.getByRole("searchbox", { name: /search query/i }), "hashing");
    await user.click(screen.getByRole("button", { name: /^search$/i }));

    expect(await screen.findByRole("status", { name: /search status/i })).toHaveTextContent(/2 results/i);

    const results = screen.getByRole("list", { name: /search results/i });
    expect(within(results).getAllByRole("button")).toHaveLength(2);
    expect(within(results).getByRole("button", { name: /HashService\.md5/i })).toHaveAttribute("aria-current", "true");
    expect(screen.getByText("MessageDigest")).toBeInTheDocument();
    expect(screen.getByText("getInstance")).toBeInTheDocument();

    await user.click(within(results).getByRole("button", { name: /SearchController\.search/i }));

    expect(within(results).getByRole("button", { name: /SearchController\.search/i })).toHaveAttribute(
      "aria-current",
      "true",
    );
    expect(screen.getByText(/SearchController.java/i)).toBeInTheDocument();
  });

  it("renders recoverable failed request guidance", async () => {
    vi.mocked(searchCode).mockRejectedValue(new Error("FAISS index unavailable"));
    const user = userEvent.setup();

    renderWithProviders(<SearchPage />);

    await user.type(screen.getByRole("searchbox", { name: /search query/i }), "query builder");
    await user.click(screen.getByRole("button", { name: /^search$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/search failed/i);
    expect(screen.getByRole("alert")).toHaveTextContent(/backend search dependency unavailable/i);
    expect(screen.getByRole("alert")).toHaveTextContent(/faiss index unavailable/i);
  });
});
