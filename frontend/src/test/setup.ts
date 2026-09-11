import "fake-indexeddb/auto";
import "@testing-library/jest-dom/vitest";
import { TransformStream } from "node:stream/web";
import { afterAll, afterEach, beforeAll } from "vitest";
import { cleanup } from "@testing-library/react";

if (!globalThis.TransformStream) {
  globalThis.TransformStream = TransformStream;
}

const { server } = await import("./server");

beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  cleanup();
  globalThis.localStorage?.clear?.();
  globalThis.sessionStorage?.clear?.();
  server.resetHandlers();
});

afterAll(() => {
  server.close();
});
