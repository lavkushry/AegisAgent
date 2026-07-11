import { describe, expect, test } from "bun:test";
import { banStatusColorVar } from "./bans";

describe("banStatusColorVar", () => {
  test("maps known statuses", () => {
    expect(banStatusColorVar("active")).toBe("--decision-deny");
    expect(banStatusColorVar("revoked")).toBe("--text-muted");
  });

  test("falls back for unknown status", () => {
    expect(banStatusColorVar("weird")).toBe("--sev-info");
  });
});
