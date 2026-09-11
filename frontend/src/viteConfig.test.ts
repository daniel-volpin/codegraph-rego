import { matchesGlob } from "node:path";
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
    expect(config.test?.projects).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          test: expect.objectContaining({
            name: "dom-vm",
            pool: "vmForks",
            vmMemoryLimit: "512MB",
            environment: "jsdom",
          }),
        }),
        expect.objectContaining({
          test: expect.objectContaining({
            name: "dom-forks",
            pool: "forks",
            environment: "jsdom",
          }),
        }),
        expect.objectContaining({
          test: expect.objectContaining({
            name: "node-forks",
            pool: "forks",
            environment: "node",
          }),
        }),
      ]),
    );
  });

  it.each([
    ["src/newFeature.test.ts", "dom-vm"],
    ["src/pages/NewPage.test.tsx", "dom-vm"],
    ["src/lib/runtimeConfig.test.ts", "dom-forks"],
    ["src/lib/api.test.ts", "node-forks"],
    ["src/viteConfig.test.ts", "node-forks"],
  ])("assigns %s to exactly one test project", (file, expectedProject) => {
    const selected = (config.test?.projects ?? []).flatMap((project) => {
      if (typeof project !== "object" || !project || !("test" in project) || !project.test) {
        return [];
      }
      const { include = [], exclude = [], name } = project.test;
      return include.some((pattern) => matchesGlob(file, pattern))
        && !exclude.some((pattern) => matchesGlob(file, pattern))
        ? [name]
        : [];
    });
    expect(selected).toEqual([expectedProject]);
  });
});
