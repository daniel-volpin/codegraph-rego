import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, evaluatePolicies, searchCode } from "./api";

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
});
