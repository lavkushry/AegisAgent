import { describe, expect, test } from "bun:test";
import {
  compileExploreAql,
  parseSimpleExploreQuery,
  validateExploreAql,
} from "./decisions";

describe("compileExploreAql", () => {
  test("compiles AND field filters", () => {
    const f = compileExploreAql(
      "decision:deny AND agent_id:ag_1 AND source_trust:untrusted_external",
    );
    expect(f.decision).toBe("deny");
    expect(f.agentId).toBe("ag_1");
    expect(f.sourceTrust).toBe("untrusted_external");
    expect(f.limit).toBe(50);
  });

  test("empty query yields empty filters", () => {
    const f = compileExploreAql("  ");
    expect(f.decision).toBeUndefined();
    expect(f.q).toBeUndefined();
  });

  test("tool maps to skill filter for decisions API", () => {
    const f = compileExploreAql("tool:github");
    expect(f.skill).toBe("github");
  });
});

describe("validateExploreAql", () => {
  test("returns error for unknown field", () => {
    expect(validateExploreAql("not_a_field:x")).toMatch(/unknown|field|not/i);
  });

  test("null for valid or empty", () => {
    expect(validateExploreAql("")).toBeNull();
    expect(validateExploreAql("decision:allow")).toBeNull();
  });
});

describe("parseSimpleExploreQuery (compat)", () => {
  test("delegates to AQL compile", () => {
    const f = parseSimpleExploreQuery("decision:deny AND agent_id:ag_1");
    expect(f.decision).toBe("deny");
    expect(f.agentId).toBe("ag_1");
  });
});
