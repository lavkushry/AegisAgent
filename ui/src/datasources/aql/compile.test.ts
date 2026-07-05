import { describe, expect, it } from "vitest";

import { AqlCompileError } from "./types";
import { aqlToCompiledRequest, compileAqlString } from "./compile";

describe("AQL compiler", () => {
  it("compiles AND-only filters to flat gateway parameters", () => {
    expect(aqlToCompiledRequest("agent_id:agent-1 AND decision:deny", "decision")).toEqual({
      filters: {
        agent_id: "agent-1",
        decision: "deny",
      },
    });
  });

  it("maps aliases and time ranges into gateway filter keys", () => {
    expect(aqlToCompiledRequest("skill:github AND @time:[now-1h TO now]", "decision").filters).toMatchObject({
      tool: "github",
      from: "now-1h",
      to: "now",
    });
  });

  it("compiles aggregate metadata for structured /v1/soc/query requests", () => {
    expect(aqlToCompiledRequest("decision:deny | stats count() by agent_id", "decision")).toEqual({
      filters: { decision: "deny" },
      aggregate: "count_by",
      groupBy: "agent_id",
    });
    expect(aqlToCompiledRequest("decision:deny | stats count_over_time(day)", "decision")).toEqual({
      filters: { decision: "deny" },
      aggregate: "count_over_time",
      interval: "day",
    });
  });

  it("fails closed on OR execution instead of silently broadening", () => {
    expect(() => aqlToCompiledRequest("agent_id:a OR agent_id:b", "decision")).toThrow(AqlCompileError);
  });

  it("preserves legacy compileAqlString shape for decisions fallback", () => {
    expect(
      compileAqlString("agent_id:agent-1 AND decision:deny AND source_trust:untrusted_external AND tool:github"),
    ).toMatchObject({
      agentId: "agent-1",
      decision: "deny",
      sourceTrust: "untrusted_external",
      skill: "github",
      q: undefined,
    });
  });
});