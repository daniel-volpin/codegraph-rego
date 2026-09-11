import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, applyRemediation, evaluatePolicies, previewRemediation, searchCode } from "./api";
import { ViolationSchema } from "./schemas";

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
});
