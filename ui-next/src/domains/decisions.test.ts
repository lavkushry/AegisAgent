import { describe, expect, test } from "bun:test";
import { parseSimpleExploreQuery } from "./decisions";

describe("parseSimpleExploreQuery", () => {
  test("parses field chips and free text", () => {
    const f = parseSimpleExploreQuery(
      "decision:deny agent_id:ag_1 trust:untrusted_external leak",
    );
    expect(f.decision).toBe("deny");
    expect(f.agentId).toBe("ag_1");
    expect(f.sourceTrust).toBe("untrusted_external");
    expect(f.q).toBe("leak");
  });

  test("empty query has only limit", () => {
    const f = parseSimpleExploreQuery("  ");
    expect(f.decision).toBeUndefined();
    expect(f.q).toBeUndefined();
    expect(f.limit).toBe(50);
  });

  test("skill: maps to skill filter", () => {
    const f = parseSimpleExploreQuery("skill:github.merge");
    expect(f.skill).toBe("github.merge");
  });
});
