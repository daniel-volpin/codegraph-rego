import { expect, test, type Page } from "@playwright/test";

const BACKEND_URL = process.env.LIVE_BACKEND_URL ?? "http://127.0.0.1:8000";

test.skip(!process.env.LIVE_BACKEND_URL, "LIVE_BACKEND_URL is required for live backend smoke tests.");

async function expectAppShell(page: Page, heading: RegExp | string) {
  await expect(page.getByRole("heading", { level: 1, name: heading })).toBeVisible();
  await expect(page.locator("body")).not.toContainText("Page failed to render");
  await expect(page.getByText(/Healthy|Degraded|Health unavailable/).first()).toBeVisible();
}

test.describe("@live frontend against real backend", () => {
  test("renders dashboard, settings, and upload status from the live backend", async ({ page, request }, testInfo) => {
    const healthResponse = await request.get(`${BACKEND_URL}/health`);
    expect([200, 503]).toContain(healthResponse.status());
    const health = await healthResponse.json();
    expect(health).toMatchObject({
      status: expect.stringMatching(/^(ok|degraded)$/),
      startup: expect.any(Object),
    });

    await page.goto("/");
    await expectAppShell(page, /CodeGraph Workspace|security research dashboard/i);
    await expect(page.getByText(health.status === "ok" ? "Healthy" : /Degraded/).first()).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("live-dashboard.png"), fullPage: true });

    await page.goto("/settings");
    await expectAppShell(page, /settings/i);
    await expect(page.getByLabel(/runtime api base/i)).toHaveValue(BACKEND_URL);
    await page.screenshot({ path: testInfo.outputPath("live-settings.png"), fullPage: true });

    const uploadStatusResponse = await request.get(`${BACKEND_URL}/upload/status`);
    expect(uploadStatusResponse.status()).toBe(200);
    const uploadStatus = await uploadStatusResponse.json();
    expect(uploadStatus).toMatchObject({
      phase: expect.any(String),
      complete: expect.any(Boolean),
    });

    const uploadStreamResponse = await request.get(`${BACKEND_URL}/upload/status/stream`, { timeout: 10_000 });
    expect(uploadStreamResponse.status()).toBe(200);
    await expect(uploadStreamResponse.text()).resolves.toContain("event: status");

    await page.goto("/upload");
    await expectAppShell(page, /upload codebase/i);
    await expect(page.getByRole("button", { name: /upload & ingest/i })).toBeDisabled();
    await page.screenshot({ path: testInfo.outputPath("live-upload.png"), fullPage: true });
  });

  test("renders live degraded search, policy, and remediation-empty states", async ({ page }, testInfo) => {
    await page.goto("/search");
    await expectAppShell(page, /semantic search/i);
    await page.getByPlaceholder(/describe a method/i).fill("MessageDigest");
    await page.getByRole("button", { name: /^search$/i }).click();
    await expect(page.locator("#main-content").getByText(/search failed/i)).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("live-search-error.png"), fullPage: true });

    await page.goto("/policy");
    await expectAppShell(page, /policy evaluation/i);
    const runButton = page.getByRole("button", { name: /run .*scan/i });
    await expect(runButton).toBeEnabled();
    await runButton.click();
    await expect(page.getByRole("alert")).toContainText("Policy evaluation failed.");
    await expect(page.getByTestId("finding-dossier")).toContainText(
      "Run a policy scan and select a finding to open a case dossier.",
    );
    await page.screenshot({ path: testInfo.outputPath("live-policy-error.png"), fullPage: true });
  });
});
