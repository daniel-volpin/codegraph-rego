import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  document.head.innerHTML = "";
  delete window.__CODEGRAPH_CONFIG__;
  vi.unstubAllGlobals();
});

describe("runtimeConfig", () => {
  it("defaults to the same-origin /api base", async () => {
    vi.stubGlobal(
      "location",
      new URL("http://127.0.0.1:5173/app") as unknown as Location,
    );

    const { buildRuntimeApiUrl, getRuntimeApiBase } = await import("./runtimeConfig");

    expect(getRuntimeApiBase()).toBe("/api");
    expect(buildRuntimeApiUrl("/health").toString()).toBe("http://127.0.0.1:5173/api/health");
  });

  it("resolves relative runtime config against the current origin", async () => {
    vi.stubGlobal(
      "location",
      new URL("http://127.0.0.1:5173/app") as unknown as Location,
    );
    window.__CODEGRAPH_CONFIG__ = { apiBaseUrl: "/backend" };

    const { getRuntimeApiBase } = await import("./runtimeConfig");

    expect(getRuntimeApiBase()).toBe("http://127.0.0.1:5173/backend");
  });
});
