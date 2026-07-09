import { describe, expect, test, beforeEach, afterEach } from "bun:test";
import { getCsrfToken } from "./csrf";

describe("getCsrfToken", () => {
  beforeEach(() => {
    for (const el of document.querySelectorAll('meta[name="csrf-token"]')) {
      el.remove();
    }
  });

  afterEach(() => {
    for (const el of document.querySelectorAll('meta[name="csrf-token"]')) {
      el.remove();
    }
  });

  test("returns undefined when meta is absent", () => {
    expect(getCsrfToken()).toBeUndefined();
  });

  test("reads content from csrf-token meta", () => {
    const meta = document.createElement("meta");
    meta.setAttribute("name", "csrf-token");
    meta.setAttribute("content", "csrf-abc");
    document.head.appendChild(meta);
    expect(getCsrfToken()).toBe("csrf-abc");
  });
});
