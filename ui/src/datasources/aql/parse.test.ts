import { describe, expect, it } from "vitest";

import { parseAql } from "./parse";

describe("AQL parser", () => {
  it("compiles supported field filters into typed gateway parameters", () => {
    expect(
      parseAql("agent_id:agent-1 AND decision:deny AND source_trust:untrusted_external AND tool:github"),
    ).toEqual({
      agentId: "agent-1",
      decision: "deny",
      sourceTrust: "untrusted_external",
      skill: "github",
      q: undefined,
    });
  });

  it("keeps free terms and unsupported field values in the safe full-text parameter", () => {
    expect(parseAql("event_type:approval hash mismatch")).toMatchObject({
      q: "approval hash mismatch",
    });
  });

  it("returns an empty query for whitespace", () => {
    expect(parseAql("   ")).toEqual({});
  });
});
