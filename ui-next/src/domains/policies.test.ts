import { describe, expect, test } from "bun:test";
import { policyStatusColorVar } from "./policies";

describe("policyStatusColorVar", () => {
  test("maps known statuses", () => {
    expect(policyStatusColorVar("active")).toBe("--state-verified");
    expect(policyStatusColorVar("draft")).toBe("--sev-info");
    expect(policyStatusColorVar("archived")).toBe("--text-muted");
  });

  test("falls back for unknown status", () => {
    expect(policyStatusColorVar("weird")).toBe("--sev-low");
  });
});
