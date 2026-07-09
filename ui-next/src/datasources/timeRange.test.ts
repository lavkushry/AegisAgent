import { describe, expect, test } from "bun:test";
import { resolveTimeRange, resolveTimeToken } from "./timeRange";

const NOW = Date.parse("2026-06-28T12:00:00.000Z");

describe("resolveTimeToken", () => {
  test("resolves now", () => {
    expect(resolveTimeToken("now", NOW)).toBe("2026-06-28T12:00:00.000Z");
  });

  test("resolves now-24h", () => {
    expect(resolveTimeToken("now-24h", NOW)).toBe("2026-06-27T12:00:00.000Z");
  });

  test("resolves now-7d", () => {
    expect(resolveTimeToken("now-7d", NOW)).toBe("2026-06-21T12:00:00.000Z");
  });

  test("passes through ISO", () => {
    expect(resolveTimeToken("2026-01-01T00:00:00.000Z", NOW)).toBe(
      "2026-01-01T00:00:00.000Z",
    );
  });

  test("rejects garbage", () => {
    expect(resolveTimeToken("yesterday", NOW)).toBeNull();
  });
});

describe("resolveTimeRange", () => {
  test("resolves both ends", () => {
    // Use fixed clock via resolveTimeToken in isolation; range uses Date.now.
    // Just ensure shape is stable for relative pair.
    const r = resolveTimeRange({ from: "now-1h", to: "now" });
    expect(r.from).toBeTruthy();
    expect(r.to).toBeTruthy();
    expect(Date.parse(r.from!)).toBeLessThan(Date.parse(r.to!));
  });
});
