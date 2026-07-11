import { describe, expect, test } from "bun:test";
import { modelCallStatusColorVar, parseTokenCounts } from "./modelCalls";

describe("modelCallStatusColorVar", () => {
  test("maps known statuses", () => {
    expect(modelCallStatusColorVar("success")).toBe("--state-verified");
    expect(modelCallStatusColorVar("error")).toBe("--decision-deny");
    expect(modelCallStatusColorVar("timeout")).toBe("--sev-low");
    expect(modelCallStatusColorVar("cancelled")).toBe("--sev-low");
  });

  test("falls back for unknown status", () => {
    expect(modelCallStatusColorVar("weird")).toBe("--sev-info");
  });
});

describe("parseTokenCounts", () => {
  test("parses a valid numeric token-counts JSON blob", () => {
    expect(parseTokenCounts('{"prompt":10,"completion":20}')).toEqual({
      prompt: 10,
      completion: 20,
    });
  });

  test("drops non-numeric fields", () => {
    expect(parseTokenCounts('{"prompt":10,"note":"x"}')).toEqual({
      prompt: 10,
    });
  });

  test("returns null for missing or malformed input", () => {
    expect(parseTokenCounts(undefined)).toBeNull();
    expect(parseTokenCounts(null)).toBeNull();
    expect(parseTokenCounts("not json")).toBeNull();
    expect(parseTokenCounts("[1,2,3]")).toBeNull();
  });
});
