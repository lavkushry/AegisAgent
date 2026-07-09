import { describe, expect, test } from "bun:test";
import { controlDisabledReason, statusColorVar } from "./agents";

describe("controlDisabledReason", () => {
  test("freeze only on active", () => {
    expect(controlDisabledReason("freeze", "active")).toBeNull();
    expect(controlDisabledReason("freeze", "frozen")).toMatch(/already frozen/i);
    expect(controlDisabledReason("freeze", "quarantined")).toMatch(
      /restored first/i,
    );
  });

  test("unfreeze only on frozen", () => {
    expect(controlDisabledReason("unfreeze", "frozen")).toBeNull();
    expect(controlDisabledReason("unfreeze", "active")).toMatch(/Only frozen/i);
  });

  test("terminal blocks controls", () => {
    expect(controlDisabledReason("freeze", "revoked")).toMatch(/revoked/i);
    expect(controlDisabledReason("revoke", "deleted")).toMatch(/already/i);
  });
});

describe("statusColorVar", () => {
  test("maps known statuses", () => {
    expect(statusColorVar("active")).toBe("--state-verified");
    expect(statusColorVar("frozen")).toBe("--sev-low");
    expect(statusColorVar("revoked")).toBe("--decision-deny");
  });
});
