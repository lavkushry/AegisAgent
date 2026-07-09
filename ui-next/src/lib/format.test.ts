import { describe, expect, test } from "bun:test";
import { asRecordArray, truncateHash } from "./format";

describe("truncateHash", () => {
  test("keeps short hashes intact", () => {
    expect(truncateHash("abcdef")).toBe("abcdef");
  });

  test("truncates long hashes with head…tail", () => {
    const h = "sha256:" + "a".repeat(64);
    const t = truncateHash(h, 8, 4);
    expect(t.startsWith("sha256:aaaaaaaa")).toBe(true);
    expect(t.endsWith("aaaa")).toBe(true);
    expect(t.includes("…")).toBe(true);
  });
});

describe("asRecordArray", () => {
  test("accepts bare arrays", () => {
    expect(asRecordArray([{ id: 1 }])).toHaveLength(1);
  });

  test("unwraps envelope keys", () => {
    expect(asRecordArray({ items: [{ a: 1 }, { b: 2 }] })).toHaveLength(2);
    expect(asRecordArray({ receipts: [{ id: "r" }] })[0].id).toBe("r");
  });

  test("empty for garbage", () => {
    expect(asRecordArray(null)).toEqual([]);
    expect(asRecordArray("x")).toEqual([]);
  });
});
