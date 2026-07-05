import { describe, expect, it } from "vitest";

import {
  appendAqlFilter,
  buildExploreDecisionRequest,
  buildExploreRequest,
  decisionRowsFromFrame,
  exploreReceiptId,
  parsedAqlChips,
} from "./exploreData";
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

  it("builds ASE explore requests through the soc-query datasource", () => {
    expect(buildExploreRequest("ase", "event_type:approval", "1h")).toEqual({
      entity: "ase",
      aql: "event_type:approval",
      timeRange: { from: "now-1h", to: "now" },
      variables: {},
      limit: 50,
      signal: undefined,
    });
  });

  it("appends facet filters with AND instead of replacing the active query", () => {
    expect(appendAqlFilter("agent_id:agent-1", "decision", "deny")).toBe(
      "agent_id:agent-1 AND decision:deny",
    );
    expect(appendAqlFilter("", "tool", "github")).toBe("tool:github");
    expect(appendAqlFilter("decision:deny", "decision", "deny")).toBe("decision:deny");
  });

  it("renders parsed AQL chips for inline filter visibility", () => {
    expect(parsedAqlChips("agent_id:agent-1 decision:deny hash")).toEqual([
      { field: "agent_id", value: "agent-1" },
      { field: "decision", value: "deny" },
      { field: "q", value: "hash" },
    ]);
  });

  it("requires receipt_id before explore verification can run", () => {
    expect(exploreReceiptId({ id: "decision-1", receipt_id: "receipt-9" })).toBe("receipt-9");
    expect(exploreReceiptId({ id: "decision-1", receipt_hash: "hash-1" })).toBeUndefined();
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
