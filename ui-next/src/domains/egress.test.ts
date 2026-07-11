import { describe, expect, test } from "bun:test";
import { egressDecisionColorVar } from "./egress";

describe("egressDecisionColorVar", () => {
  test("maps deny/blocked to the deny color", () => {
    expect(egressDecisionColorVar("deny")).toBe("--decision-deny");
    expect(egressDecisionColorVar("blocked")).toBe("--decision-deny");
  });

  test("maps allow/allowed to the verified color", () => {
    expect(egressDecisionColorVar("allow")).toBe("--state-verified");
    expect(egressDecisionColorVar("allowed")).toBe("--state-verified");
  });

  test("falls back for missing/unknown decision", () => {
    expect(egressDecisionColorVar(null)).toBe("--sev-info");
    expect(egressDecisionColorVar("weird")).toBe("--sev-info");
  });
});
