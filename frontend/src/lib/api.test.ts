import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  applyRemediation,
  evaluatePolicies,
  exportPolicySarif,
  previewRemediation,
  searchCode,
  uploadZip,
} from "./api";
import { RemediationGenerationResultSchema, ViolationSchema } from "./schemas";

const jsonResponse = (payload: unknown, status: number) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("API error handling", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects failed search responses with backend error details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({ error: "FAISS index not found. Build embeddings first." }, 400),
      ),
    );

    await expect(searchCode("MessageDigest")).rejects.toMatchObject({
      name: "ApiError",
      status: 400,
      message: "FAISS index not found. Build embeddings first.",
    } satisfies Partial<ApiError>);
  });

  it("rejects failed policy evaluation responses with backend error details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({ error: "internal", request_id: "live-smoke" }, 500),
      ),
    );

    await expect(evaluatePolicies()).rejects.toMatchObject({
      name: "ApiError",
      status: 500,
      message: "internal",
    } satisfies Partial<ApiError>);
  });

  it("sends the preallocated upload request id", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ status: "Codebase processed!", request_id: "upload-job-1" }, 200),
    );
    vi.stubGlobal("fetch", fetchMock);

    await uploadZip(new File(["zip"], "code.zip"), undefined, "upload-job-1");

    expect(fetchMock.mock.calls[0][1]).toMatchObject({
      method: "POST",
      headers: { "X-Request-Id": "upload-job-1" },
    });
  });

  it("sends canonical method identity for preview and apply", async () => {
    const fetchMock = vi.fn().mockImplementation(async () =>
      jsonResponse({ status: "NO_FIX", violation_id: "rule", error: "No candidate" }, 200),
    );
    vi.stubGlobal("fetch", fetchMock);
    const methodKey = "workspace@revision:Demo.java#method:42";
    await previewRemediation("rule", methodKey, "/workspace/Demo.java");
    await applyRemediation({ violation_id: "rule", method_key: methodKey });
    for (const [, options] of fetchMock.mock.calls) {
      expect(JSON.parse(options.body)).toMatchObject({ method_key: methodKey });
      expect(JSON.parse(options.body)).not.toHaveProperty("target_method");
    }
  });

  it("refuses findings without an operational identity", () => {
    expect(ViolationSchema.safeParse({
      violation_id: "rule",
      target_method: "demo.Demo.method()",
    }).success).toBe(false);
  });

  it("exports SARIF report with optional rule filters", async () => {
    const fetchMock = vi.fn().mockImplementation(async () =>
      jsonResponse({
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [],
      }, 200),
    );
    vi.stubGlobal("fetch", fetchMock);

    const doc = await exportPolicySarif({ ruleIds: ["ISO-A.10-WEAK-HASH"] });
    expect(doc.version).toBe("2.1.0");
    expect(fetchMock).toHaveBeenCalled();
    const [url] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/policy/export/sarif?rule_ids=ISO-A.10-WEAK-HASH");
  });
});

describe("RemediationGenerationResult schema/DTO alignment", () => {
  // Backend sends schema_error: null on success; `.optional()` alone rejected it.
  it("accepts schema_error: null from a successful generation", () => {
    const parsed = RemediationGenerationResultSchema.parse({
      decision: "apply_edits",
      replacement_method_lines: ["@PreAuthorize(\"isAuthenticated()\")"],
      replacement_method_code: "@PreAuthorize(\"isAuthenticated()\")",
      reason: "",
      raw_response_valid: true,
      schema_error: null,
    });
    expect(parsed.raw_response_valid).toBe(true);
    expect(parsed.schema_error).toBeNull();
  });

  it("still accepts a schema_error string when generation failed", () => {
    const parsed = RemediationGenerationResultSchema.parse({
      decision: "no_fix",
      raw_response_valid: false,
      schema_error: "missing replacement_method_lines",
    });
    expect(parsed.schema_error).toBe("missing replacement_method_lines");
  });
});
