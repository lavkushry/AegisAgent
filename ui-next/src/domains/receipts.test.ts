import { describe, expect, test } from "bun:test";
import { normalizeVerification } from "./receipts";

describe("normalizeVerification", () => {
  test("verified true is success", () => {
    const r = normalizeVerification({ verified: true, receipt_hash: "h1" });
    expect(r.status).toBe("verified");
    expect(r.ok).toBe(true);
    expect(r.receiptHash).toBe("h1");
  });

  test("verified false is fail-closed failure", () => {
    const r = normalizeVerification({
      verified: false,
      error: "hash mismatch",
    });
    expect(r.status).toBe("failed");
    expect(r.ok).toBe(false);
    expect(r.message).toContain("hash mismatch");
  });

  test("ambiguous response is unknown (fail-closed)", () => {
    const r = normalizeVerification({ receipt_id: "x" });
    expect(r.status).toBe("unknown");
    expect(r.ok).toBe(false);
  });
});
