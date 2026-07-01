import { describe, expect, it } from "vitest";

import { parseAql } from "./parse";

describe("AQL parser", () => {
  it("compiles supported field filters into typed gateway parameters", () => {
    expect(
      parseAql("agent_id:agent-1 AND decision:deny AND source_trust:untrusted_external AND tool:github"),
    ).toMatchObject({
      agentId: "agent-1",
      decision: "deny",
      sourceTrust: "untrusted_external",
      skill: "github",
      q: undefined,
    });
  });

  it("compiles investigation identifiers and evidence hashes as typed filters", () => {
    expect(
      parseAql(
        "action:write resource:repo run_id:run-1 trace_id:trace-1 action_hash:sha256:a receipt_hash:sha256:r",
      ),
    ).toMatchObject({
      action: "write",
      resource: "repo",
      runId: "run-1",
      traceId: "trace-1",
      actionHash: "sha256:a",
      receiptHash: "sha256:r",
      q: undefined,
    });
  });

  it("compiles ASE fields and keeps free terms in the safe full-text parameter", () => {
    expect(parseAql("event_type:approval severity:high source_component:node-sensor hash mismatch")).toMatchObject({
      eventType: "approval",
      severity: "high",
      sourceComponent: "node-sensor",
      q: "hash mismatch",
    });
  });

  it("returns an empty query for whitespace", () => {
    expect(parseAql("   ")).toEqual({});
  });
});
