import { describe, expect, it, vi, beforeEach } from "vitest";
import { downloadSarifFile, summarizeSarif } from "./sarif";
import { DEMO_SARIF_DOCUMENT } from "./demoData";

describe("sarif utilities", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("summarizeSarif", () => {
    it("computes stats from SARIF document", () => {
      const summary = summarizeSarif(DEMO_SARIF_DOCUMENT);
      expect(summary.runCount).toBe(1);
      expect(summary.ruleCount).toBe(4);
      expect(summary.resultCount).toBe(2);
    });

    it("handles empty SARIF runs cleanly", () => {
      const summary = summarizeSarif({ version: "2.1.0", runs: [] });
      expect(summary.runCount).toBe(0);
      expect(summary.ruleCount).toBe(0);
      expect(summary.resultCount).toBe(0);
    });
  });

  describe("downloadSarifFile", () => {
    it("creates blob and clicks anchor for download", () => {
      const createObjectURLMock = vi.fn().mockReturnValue("blob:http://localhost/dummy-sarif");
      const revokeObjectURLMock = vi.fn();
      globalThis.URL.createObjectURL = createObjectURLMock;
      globalThis.URL.revokeObjectURL = revokeObjectURLMock;

      const clickMock = vi.fn();
      const appendChildSpy = vi.spyOn(document.body, "appendChild");
      const removeChildSpy = vi.spyOn(document.body, "removeChild");

      const origCreateElement = document.createElement.bind(document);
      vi.spyOn(document, "createElement").mockImplementation((tagName: string) => {
        const el = origCreateElement(tagName);
        if (tagName === "a") {
          el.click = clickMock;
        }
        return el;
      });

      const ok = downloadSarifFile(DEMO_SARIF_DOCUMENT, "custom-test.sarif.json");
      expect(ok).toBe(true);
      expect(createObjectURLMock).toHaveBeenCalled();
      expect(clickMock).toHaveBeenCalled();
      expect(appendChildSpy).toHaveBeenCalled();
      expect(removeChildSpy).toHaveBeenCalled();
      expect(revokeObjectURLMock).toHaveBeenCalledWith("blob:http://localhost/dummy-sarif");
    });
  });
});
