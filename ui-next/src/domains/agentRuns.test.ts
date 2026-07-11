import { describe, expect, test } from "bun:test";
import { runControlDisabledReason, runStatusColorVar } from "./agentRuns";

describe("runControlDisabledReason", () => {
  test("pause blocked when already paused", () => {
    expect(runControlDisabledReason("pause", "running")).toBeNull();
    expect(runControlDisabledReason("pause", "paused")).toMatch(
      /already paused/i,
    );
  });

  test("resume only valid from paused", () => {
    expect(runControlDisabledReason("resume", "paused")).toBeNull();
    expect(runControlDisabledReason("resume", "running")).toMatch(
      /only paused/i,
    );
  });

  test("terminal statuses block every control", () => {
    for (const kind of ["pause", "resume", "kill", "quarantine"] as const) {
      expect(runControlDisabledReason(kind, "killed")).toMatch(/already/i);
      expect(runControlDisabledReason(kind, "finished")).toMatch(/already/i);
    }
  });

  test("kill and quarantine allowed while running", () => {
    expect(runControlDisabledReason("kill", "running")).toBeNull();
    expect(runControlDisabledReason("quarantine", "running")).toBeNull();
  });
});

describe("runStatusColorVar", () => {
  test("maps known statuses", () => {
    expect(runStatusColorVar("running")).toBe("--state-verified");
    expect(runStatusColorVar("paused")).toBe("--sev-low");
    expect(runStatusColorVar("killed")).toBe("--decision-deny");
    expect(runStatusColorVar("finished")).toBe("--text-muted");
  });
});
