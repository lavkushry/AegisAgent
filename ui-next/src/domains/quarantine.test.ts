import { describe, expect, test } from "bun:test";
import { quarantineStatusColorVar } from "./quarantine";

describe("quarantineStatusColorVar", () => {
  test("maps known statuses", () => {
    expect(quarantineStatusColorVar("active")).toBe("--decision-approval");
    expect(quarantineStatusColorVar("released")).toBe("--state-verified");
    expect(quarantineStatusColorVar("deleted")).toBe("--text-muted");
  });

  test("falls back for unknown status", () => {
    expect(quarantineStatusColorVar("weird")).toBe("--sev-info");
  });
});
