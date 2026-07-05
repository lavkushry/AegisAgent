import { describe, expect, it } from "vitest";

import { mcpControlDisabledReason } from "./mcpControls";

describe("mcpControlDisabledReason", () => {
  it("blocks viewers from containment actions", () => {
    expect(mcpControlDisabledReason("quarantine", "active", "viewer")).toContain("Requires analyst");
  });

  it("allows analysts to quarantine active servers", () => {
    expect(mcpControlDisabledReason("quarantine", "active", "analyst")).toBeNull();
  });

  it("only allows restore on quarantined servers", () => {
    expect(mcpControlDisabledReason("restore", "active", "admin")).toContain("Only quarantined");
    expect(mcpControlDisabledReason("restore", "quarantined", "admin")).toBeNull();
  });
});