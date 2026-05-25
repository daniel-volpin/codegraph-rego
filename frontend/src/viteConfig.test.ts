import config from "../vite.config";

describe("vite config", () => {
  it("uses a strict dev port", () => {
    expect(config.server?.port).toBe(5173);
    expect(config.server?.strictPort).toBe(true);
  });

  it("proxies api requests in development", () => {
    expect(config.server?.proxy).toMatchObject({
      "/api": {
        changeOrigin: true,
      },
    });
  });
});
