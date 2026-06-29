import { describe, expect, it } from "vitest";

import { normalizeVerification } from "./receiptVerification";

describe("receipt verification normalization", () => {
  it.each([
    [{ verified: true }, "verified"],
    [{ ok: true }, "verified"],
    [{ status: "verified" }, "verified"],
    [{ verified: false }, "failed"],
    [{ ok: false }, "failed"],
    [{ error: "hash mismatch" }, "failed"],
    [{ broken_at_row: 4 }, "failed"],
    [{}, "unknown"],
    [{ message: "done" }, "unknown"],
  ] as const)("normalizes %o as %s", (input, expected) => {
    expect(normalizeVerification(input).status).toBe(expected);
  });

  it("preserves the broken row and never marks it successful", () => {
    const result = normalizeVerification({ ok: true, broken_at_row: 7 });

    expect(result).toMatchObject({ status: "failed", ok: false, brokenAtRow: 7 });
  });

  it("maps the gateway's zero-based chain error index to a one-based UI row", () => {
    expect(normalizeVerification({ verified: false, error: "Hash mismatch at index 3" })).toMatchObject({
      status: "failed",
      brokenAtRow: 4,
    });
  });
});
