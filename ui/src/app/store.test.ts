import { describe, expect, it } from "vitest";

import { canApprove } from "./store";

describe("approval role gating", () => {
  it("keeps viewer and analyst roles read-only", () => {
    expect(canApprove("viewer")).toBe(false);
    expect(canApprove("analyst")).toBe(false);
  });

  it("allows only approver and admin roles to request approval decisions", () => {
    expect(canApprove("approver")).toBe(true);
    expect(canApprove("admin")).toBe(true);
  });
});
