import { defineConfig } from "@playwright/test";

const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:4174";
const serverPort = Number(new URL(baseURL).port || "4174");

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  outputDir: "test-results",
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  webServer: {
    command: `yarn dev --host 127.0.0.1 --port ${serverPort}`,
    port: serverPort,
    reuseExistingServer: true,
  },
  projects: [
    {
      name: "desktop-1280x900",
      use: { browserName: "chromium", viewport: { width: 1280, height: 900 } },
    },
    {
      name: "tablet-820x1180",
      use: { browserName: "chromium", viewport: { width: 820, height: 1180 }, hasTouch: true },
    },
    {
      name: "mobile-390x844",
      use: {
        browserName: "chromium",
        viewport: { width: 390, height: 844 },
        isMobile: true,
        hasTouch: true,
      },
    },
  ],
});
