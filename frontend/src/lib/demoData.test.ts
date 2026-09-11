import { describe, expect, it, beforeEach } from "vitest";
import {
  isDemoMode,
  setDemoMode,
  DEMO_MODE_STORAGE_KEY,
  fetchHealth,
  fetchPolicyCatalog,
  evaluatePolicies,
  previewRemediation,
  applyRemediation,
  searchCode,
} from "./api";

describe("Demo & Offline Mode", () => {
  beforeEach(() => {
    localStorage.removeItem(DEMO_MODE_STORAGE_KEY);
  });

  it("defaults to false when no storage key exists", () => {
    expect(isDemoMode()).toBe(false);
  });

  it("can be enabled and disabled via setDemoMode", () => {
    setDemoMode(true);
    expect(isDemoMode()).toBe(true);
    expect(localStorage.getItem(DEMO_MODE_STORAGE_KEY)).toBe("true");

    setDemoMode(false);
    expect(isDemoMode()).toBe(false);
    expect(localStorage.getItem(DEMO_MODE_STORAGE_KEY)).toBe("false");
  });

  it("returns realistic thesis mock data when demo mode is active", async () => {
    setDemoMode(true);

    const health = await fetchHealth();
    expect(health.status).toBe("ok");
    expect(health.details).toHaveProperty("mode", "interactive_thesis_demo");

    const catalog = await fetchPolicyCatalog();
    expect(catalog.rules.length).toBeGreaterThan(0);
    expect(catalog.benchmark_categories.length).toBeGreaterThan(0);

    const evalResult = await evaluatePolicies();
    expect(evalResult.violations?.length).toBeGreaterThan(0);

    const preview = await previewRemediation("ISO-A.10-WEAK-HASH");
    expect(preview.status).toBe("OK");
    expect(preview.diff).toContain("SHA-256");

    const applyResult = await applyRemediation({ violation_id: "ISO-A.10-WEAK-HASH" });
    expect(applyResult.verification?.overall_status).toBe("PASS");

    const searchResult = await searchCode("password");
    expect(searchResult.matches.length).toBeGreaterThan(0);
  });
});
