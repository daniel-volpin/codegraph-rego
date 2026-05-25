import "fake-indexeddb/auto";
import "@testing-library/jest-dom/vitest";
import { afterAll, afterEach, beforeAll } from "vitest";
import { cleanup } from "@testing-library/react";
import { server } from "./server";

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
