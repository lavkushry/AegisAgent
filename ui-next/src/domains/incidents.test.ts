import { describe, expect, test } from "bun:test";
import { severityColorVar } from "./incidents";

describe("severityColorVar", () => {
  test("maps severity ramp", () => {
    expect(severityColorVar("critical")).toBe("--sev-critical");
    expect(severityColorVar("high")).toBe("--sev-high");
    expect(severityColorVar("medium")).toBe("--sev-medium");
    expect(severityColorVar(undefined)).toBe("--sev-info");
  });
});
