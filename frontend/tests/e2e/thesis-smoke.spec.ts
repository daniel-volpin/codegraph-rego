import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const screenshotPath = (pageName: string, filename: string) =>
  fileURLToPath(new URL(`../../../playwright-screenshots/${pageName}/${filename}`, import.meta.url));

async function expectNoSeriousA11yViolations(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  const blockingViolations = results.violations.filter((violation) =>
    violation.impact === "critical" || violation.impact === "serious",
  );

  expect(
    blockingViolations,
    blockingViolations
      .map((violation) => `${violation.id}: ${violation.help} (${violation.impact})`)
      .join("\n"),
  ).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.route("**/health", async (route) => {
    await route.fulfill({
      json: {
        status: "ok",
        startup_ready: true,
        neo4j: true,
        faiss_index: true,
        signature_map: true,
        embedding_model: true,
        opa: true,
        startup: {
          ready: true,
          phase: "ready",
          checks: {},
          errors: {},
        },
        details: {},
      },
    });
  });

  await page.route("**/policy/catalog", async (route) => {
    await route.fulfill({
      json: {
        controls: [],
        rules: [],
        benchmark_categories: [],
        framework_demo_rule_ids: [],
      },
    });
  });
});

test("@thesis home smoke is accessible", async ({ page }) => {
  await page.goto("/");
  await expectNoSeriousA11yViolations(page);
  await page.screenshot({ path: screenshotPath("home", "desktop-1280x900.png"), fullPage: true });
});

test("@thesis upload smoke is accessible", async ({ page }) => {
  await page.goto("/upload");
  await expectNoSeriousA11yViolations(page);
  await page.screenshot({ path: screenshotPath("upload", "desktop-1280x900.png"), fullPage: true });
});

test("@thesis settings smoke is accessible", async ({ page }) => {
  await page.goto("/settings");
  await expectNoSeriousA11yViolations(page);
  await page.screenshot({ path: screenshotPath("settings", "desktop-1280x900.png"), fullPage: true });
});

test("@thesis policy shell is accessible", async ({ page }) => {
  await page.goto("/policy");
  await expectNoSeriousA11yViolations(page);
  await page.screenshot({ path: screenshotPath("policy", "desktop-1280x900.png"), fullPage: true });
});
