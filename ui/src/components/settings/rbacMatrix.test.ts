import { describe, expect, it } from "vitest";

import { roleCapabilitySummary, roleOverrideDisabledReason } from "./rbacMatrix";

describe("rbacMatrix", () => {
  it("summarizes analyst capabilities", () => {
    expect(roleCapabilitySummary("analyst")).toContain("Active response");
    expect(roleCapabilitySummary("analyst")).not.toContain("Approvals");
  });

  it("blocks production role override outside demo mode", () => {
    expect(roleOverrideDisabledReason(false)).toContain("gateway session");
    expect(roleOverrideDisabledReason(true)).toBeNull();
  });
});