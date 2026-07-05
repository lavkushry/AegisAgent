import { describe, expect, it } from "vitest";

import { hashPreview, isRedactedDisplay, redactSecret } from "./redactSecret";

describe("redactSecret", () => {
  it("redacts non-empty secrets", () => {
    expect(redactSecret("super-secret-token")).toBe("••••••••");
    expect(isRedactedDisplay(redactSecret("x"))).toBe(true);
  });

  it("shows dash for empty values", () => {
    expect(redactSecret("")).toBe("—");
    expect(redactSecret(null)).toBe("—");
    expect(redactSecret(undefined)).toBe("—");
  });
});

describe("hashPreview", () => {
  it("truncates long hashes", () => {
    const hash = "a".repeat(64);
    expect(hashPreview(hash)).toBe(`${"a".repeat(8)}…${"a".repeat(8)}`);
  });

  it("returns short hashes unchanged", () => {
    expect(hashPreview("abc123")).toBe("abc123");
    expect(hashPreview(null)).toBe("—");
  });
});