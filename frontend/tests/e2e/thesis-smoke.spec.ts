import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

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

const HEALTH_OK = {
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
};

const IDLE_UPLOAD_STATUS = {
  phase: "idle",
  message: "No upload running.",
  progress: 0,
  complete: true,
  error: null,
  updated_at: "2026-06-16T00:00:00.000Z",
  started_at: null,
  request_id: null,
};

const MOCK_POLICY_VIOLATION = {
  violation_id: "ISO-A.10-WEAK-HASH",
  target_method: "com.acme.Demo.hashPassword(String)",
  file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java",
  severity: "HIGH",
  reason: "Weak hash usage detected",
  code_snippet: "public String hashPassword(String input) {\n  return md5(input);\n}",
  snippet_start_line: 40,
  snippet_end_line: 42,
  evidence: {
    source_code: "public String hashPassword(String input) {\n  return md5(input);\n}",
    graph_context: {
      callers: ["com.acme.DemoController.submit()"],
    },
    vector_context: ["com.acme.HashHelper.hashValue()"],
  },
  remediation: {
    supported: true,
    support_tier: "full",
    reason_code: "supported_rule_for_auto_fix",
    strategy: "replace_weak_hash",
    preview_available: true,
    verify_available: true,
    ui_apply_mode: "dry_run",
    rationale: "Bounded weak-hash replacement is supported.",
    safe_refusal_possible: false,
  },
};

const REMEDIATION_DIFF = "@@ -1,3 +1,3 @@\n-md5(input)\n+sha256(input)";
const REMEDIATION_CONFIDENCE = {
  score: 0.92,
  band: "apply",
  threshold_apply: 0.75,
  threshold_review: 0.5,
  rationale: "High-confidence bounded replacement.",
};

test.beforeEach(async ({ page }) => {
  await page.route("**/config.json", async (route) => {
    await route.fulfill({
      json: {
        apiBaseUrl: "/api",
      },
    });
  });

  await page.route("**/api/health", async (route) => {
    await route.fulfill({
      json: HEALTH_OK,
    });
  });

  await page.route("**/api/upload/status**", async (route) => {
    await route.fulfill({
      json: IDLE_UPLOAD_STATUS,
    });
  });

  await page.route("**/api/upload/status/stream**", async (route) => {
    await route.fulfill({
      status: 204,
      body: "",
    });
  });

  await page.route("**/api/policy/catalog", async (route) => {
    await route.fulfill({
      json: {
        controls: [],
        rules: [],
        benchmark_categories: [],
        framework_demo_rule_ids: [],
      },
    });
  });

  await page.route("**/api/policy/evaluate**", async (route) => {
    await route.fulfill({
      json: {
        violations: [MOCK_POLICY_VIOLATION],
        opa_output: {},
        enriched: [],
      },
    });
  });

  await page.route("**/api/remediation/preview", async (route) => {
    await route.fulfill({
      json: {
        status: "OK",
        violation_id: "ISO-A.10-WEAK-HASH",
        rule_id: "ISO-A.10-WEAK-HASH",
        target_method: "com.acme.Demo.hashPassword(String)",
        file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java",
        diff: REMEDIATION_DIFF,
        confidence: REMEDIATION_CONFIDENCE,
        error: null,
      },
    });
  });

  await page.route("**/api/remediation/apply", async (route) => {
    await route.fulfill({
      json: {
        status: "OK",
        violation_id: "ISO-A.10-WEAK-HASH",
        rule_id: "ISO-A.10-WEAK-HASH",
        target_method: "com.acme.Demo.hashPassword(String)",
        file_path: "/tmp/uploaded_code/app/src/main/java/com/acme/Demo.java",
        diff: REMEDIATION_DIFF,
        verification: {
          overall_status: "PASS",
          target_rule_status: "PASS",
          remaining_violations: [],
          new_violations: [],
        },
        compilation: {
          attempted: true,
          success: true,
        },
        generation: {
          decision: "apply_edits",
          reason: "Weak hash replaced with SHA-256.",
        },
        confidence: REMEDIATION_CONFIDENCE,
        error: null,
      },
    });
  });

  await page.route("**/api/search", async (route) => {
    await route.fulfill({
      json: {
        matches: ["com.acme.HashController.hashPassword(String)"],
        contexts: [
          [
            {
              method: "com.acme.HashController.hashPassword(String)",
              neighbors: [],
            },
          ],
        ],
      },
    });
  });
});

const pageShells = [
  { name: "home", path: "/", heading: /CodeGraph Workspace|Security Research Dashboard/i },
  { name: "upload", path: "/upload", heading: "Upload Codebase" },
  { name: "search", path: "/search", heading: "Semantic Search" },
  { name: "policy", path: "/policy", heading: "Policy Evaluation" },
  { name: "settings", path: "/settings", heading: "Settings" },
];

for (const route of pageShells) {
  test(`@thesis ${route.name} shell is accessible`, async ({ page }, testInfo) => {
    await page.goto(route.path);
    await expect(page.getByRole("heading", { level: 1, name: route.heading })).toBeVisible();
    await expect(page.getByText("Page failed to render")).toHaveCount(0);
    await expectNoSeriousA11yViolations(page);
    await page.screenshot({ path: testInfo.outputPath(`${route.name}.png`), fullPage: true });
  });
}

test("@thesis search submits and renders backend results", async ({ page }) => {
  await page.goto("/search");
  await page.getByPlaceholder("Describe a method, vulnerability pattern, or control...").fill("password hashing logic");
  await page.getByRole("button", { name: "Search" }).click();

  await expect(
    page.getByRole("heading", {
      level: 3,
      name: "com.acme.HashController.hashPassword(String)",
    }),
  ).toBeVisible();
  await expect(page.getByText("Search failed")).toHaveCount(0);
});

test("@thesis upload submits and renders detected Java roots", async ({ page }) => {
  await page.route("**/api/upload", async (route) => {
    await route.fulfill({
      json: {
        status: "Codebase processed!",
        java_root: "/tmp/uploaded_code/app/src/main/java",
        java_roots: ["/tmp/uploaded_code/app/src/main/java"],
        request_id: "upload-test-1",
      },
    });
  });

  await page.goto("/upload");
  await page.locator('input[type="file"]').setInputFiles({
    name: "demo.zip",
    mimeType: "application/zip",
    buffer: Buffer.from("PK"),
  });
  await expect(page.getByText("File selected")).toBeVisible();
  await page.getByRole("button", { name: "Upload & Ingest" }).click();

  await expect(page.getByText("Codebase processed successfully.")).toBeVisible();
  await expect(page.getByText("Detected modules")).toBeVisible();
  await expect(page.getByText("app/src/main/java")).toBeVisible();
});

test("@thesis policy scan renders findings and remediation artifacts", async ({ page }) => {
  await page.goto("/policy");
  await page.getByRole("button", { name: "Run Full Policy Scan" }).click();

  await expect(page.getByText("ISO-A.10-WEAK-HASH")).toBeVisible();
  await expect(page.getByTitle("com.acme.Demo.hashPassword(String)")).toBeVisible();
  await expect(page.getByText("Weak hash usage detected")).toBeVisible();
  await expect(page.getByText("app/src/main/java/com/acme/Demo.java:40-42")).toBeVisible();

  await page.getByRole("button", { name: "Preview suggested fix" }).click();
  await expect(page.getByText("Proposed diff")).toBeVisible();
  await expect(page.getByText("+sha256(input)")).toBeVisible();
  await expect(page.getByText("High-confidence bounded replacement.")).toBeVisible();

  await page.getByRole("button", { name: "Verify fix (dry run)" }).click();
  await expect(page.getByText("Verification summary")).toBeVisible();
  await expect(page.getByText("Overall PASS")).toBeVisible();
  await expect(page.getByText("Compilation success")).toBeVisible();
});

test("@thesis responsive drawer navigation reaches search", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name === "desktop-1280x900", "drawer is hidden on desktop");

  await page.goto("/");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("link", { name: "Search" }).click();
  await expect(page.getByRole("heading", { level: 1, name: "Semantic Search" })).toBeVisible();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("mobile-drawer-search.png"), fullPage: true });
});
