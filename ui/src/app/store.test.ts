import { describe, expect, it } from "vitest";

import { canApprove, canRespond, canRevokeAgent } from "./store";

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

describe("active-response role gating", () => {
  it("keeps viewers read-only for freeze/restore controls", () => {
    expect(canRespond("viewer")).toBe(false);
    expect(canRespond("analyst")).toBe(true);
  });

  it("limits permanent revoke to admin", () => {
    expect(canRevokeAgent("analyst")).toBe(false);
    expect(canRevokeAgent("admin")).toBe(true);
  });
});
