import { describe, expect, it } from "vitest";

import { controlDisabledReason } from "./agentControls";

describe("agentControls", () => {
  it("blocks viewer role from freeze and restore controls", () => {
    expect(controlDisabledReason("freeze", "active", "viewer")).toContain("Requires analyst");
    expect(controlDisabledReason("restore", "quarantined", "viewer")).toContain("Requires analyst");
  });

  it("allows analyst to freeze active agents", () => {
    expect(controlDisabledReason("freeze", "active", "analyst")).toBeNull();
  });

  it("restricts revoke to admin and terminal statuses", () => {
    expect(controlDisabledReason("revoke", "active", "analyst")).toContain("admin");
    expect(controlDisabledReason("revoke", "revoked", "admin")).toContain("revoked");
    expect(controlDisabledReason("revoke", "active", "admin")).toBeNull();
  });

  it("enforces status-specific freeze and restore transitions", () => {
    expect(controlDisabledReason("freeze", "frozen", "admin")).toContain("already frozen");
    expect(controlDisabledReason("unfreeze", "active", "admin")).toContain("Only frozen");
    expect(controlDisabledReason("restore", "quarantined", "admin")).toBeNull();
  });
});