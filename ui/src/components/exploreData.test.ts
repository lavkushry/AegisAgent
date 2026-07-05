import { describe, expect, it } from "vitest";

import { buildExploreDecisionRequest, decisionRowsFromFrame } from "./exploreData";
import type { DataFrame } from "../datasources/types";

describe("Explore datasource helpers", () => {
  it("builds a decision datasource request with query, time range, and abort signal", () => {
    const controller = new AbortController();

    expect(buildExploreDecisionRequest("agent_id:agent-1 decision:deny", "24h", controller.signal)).toEqual({
      entity: "decision",
      aql: "agent_id:agent-1 decision:deny",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
      limit: 50,
      signal: controller.signal,
    });
  });

  it("converts datasource frames to decision rows at the render boundary", () => {
    const frame: DataFrame = {
      fields: [
        { name: "id", type: "string", values: ["decision-1"] },
        { name: "decision", type: "decision", values: ["deny"] },
        { name: "action_hash", type: "hash", values: ["sha256:abc"] },
      ],
      length: 1,
      meta: { total: 1 },
    };

    expect(decisionRowsFromFrame(frame)).toEqual([
      { id: "decision-1", decision: "deny", action_hash: "sha256:abc" },
    ]);
    expect(decisionRowsFromFrame(undefined)).toEqual([]);
  });

  it("drops malformed frame rows without stable decision ids", () => {
    const frame: DataFrame = {
      fields: [
        { name: "id", type: "string", values: [null, "decision-2"] },
        { name: "decision", type: "decision", values: ["deny", "allow"] },
      ],
      length: 2,
      meta: { total: 2 },
    };

    expect(decisionRowsFromFrame(frame)).toEqual([
      { id: "decision-2", decision: "allow" },
    ]);
  });
});
