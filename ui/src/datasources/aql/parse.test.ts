import { describe, expect, it } from "vitest";

import { AqlParseError } from "./types";
import { decodeAqlParam, encodeAqlParam, parseAql, serializeAql } from "./parse";

describe("AQL parser", () => {
  it("compiles supported field filters into typed gateway parameters", () => {
    const query = parseAql(
      "agent_id:agent-1 AND decision:deny AND source_trust:untrusted_external AND tool:github",
      { entity: "decision" },
    );
    expect(query.filter).toMatchObject({
      kind: "bool",
      op: "and",
      children: expect.arrayContaining([
        { kind: "term", field: "agent_id", op: "eq", value: "agent-1" },
        { kind: "term", field: "decision", op: "eq", value: "deny" },
        { kind: "term", field: "source_trust", op: "eq", value: "untrusted_external" },
        { kind: "term", field: "tool", op: "eq", value: "github" },
      ]),
    });
  });

  it("compiles investigation identifiers and evidence hashes as typed filters", () => {
    const query = parseAql(
      "action:write resource:repo run_id:run-1 trace_id:trace-1 action_hash:sha256:a receipt_hash:sha256:r",
      { entity: "decision" },
    );
    expect(serializeAql(query)).toContain("action:write");
    expect(serializeAql(query)).toContain("action_hash:sha256:a");
  });

  it("compiles ASE fields and keeps free terms in q", () => {
    const query = parseAql("event_type:approval severity:high source_component:node-sensor hash mismatch", {
      entity: "ase",
    });
    expect(query.filter).toMatchObject({
      kind: "bool",
      op: "and",
      children: expect.arrayContaining([
        { kind: "term", field: "event_type", op: "eq", value: "approval" },
        { kind: "text", value: "hash" },
        { kind: "text", value: "mismatch" },
      ]),
    });
  });

  it("returns an empty filter for whitespace", () => {
    expect(parseAql("   ")).toEqual({ filter: { kind: "bool", op: "and", children: [] } });
  });

  it("respects OR precedence below AND", () => {
    const query = parseAql("agent_id:a OR decision:deny AND tool:github", { entity: "decision" });
    expect(query.filter).toEqual({
      kind: "bool",
      op: "or",
      children: [
        { kind: "term", field: "agent_id", op: "eq", value: "a" },
        {
          kind: "bool",
          op: "and",
          children: [
            { kind: "term", field: "decision", op: "eq", value: "deny" },
            { kind: "term", field: "tool", op: "eq", value: "github" },
          ],
        },
      ],
    });
  });

  it("parses grouped boolean filters", () => {
    const input = "(agent_id:a OR agent_id:b) AND decision:deny";
    const query = parseAql(input, { entity: "decision" });
    expect(serializeAql(query)).toBe(input);
  });

  it("parses time ranges on @time", () => {
    const query = parseAql("decision:deny AND @time:[now-24h TO now]", { entity: "decision" });
    expect(query.filter).toMatchObject({
      kind: "bool",
      op: "and",
      children: expect.arrayContaining([
        { kind: "term", field: "@time", op: "range", value: "now-24h", to: "now" },
      ]),
    });
  });

  it("parses aggregate stages", () => {
    expect(parseAql("decision:deny | stats count() by agent_id", { entity: "decision" }).aggregate).toEqual({
      func: "count",
      by: "agent_id",
    });
    expect(parseAql("decision:deny | stats count_over_time(hour)", { entity: "decision" }).aggregate).toEqual({
      func: "count_over_time",
      interval: "hour",
    });
  });

  it("rejects unknown fields with positional errors", () => {
    expect(() => parseAql("totally_unknown:value", { entity: "decision" })).toThrow(AqlParseError);
    try {
      parseAql("totally_unknown:value", { entity: "decision" });
    } catch (error) {
      expect(error).toMatchObject({ position: 0, message: expect.stringContaining("Unknown field") });
    }
  });

  it("rejects unsupported intervals and operators in aggregates", () => {
    expect(() => parseAql("decision:deny | stats count_over_time(week)", { entity: "decision" })).toThrow(
      AqlParseError,
    );
    expect(() => parseAql("decision:deny | stats sum()", { entity: "decision" })).toThrow(AqlParseError);
  });

  it("bounds input length and injection-like strings without broadening fields", () => {
    const injection = String.raw`agent_id:"safe'; DROP TABLE decisions; --"`;
    const query = parseAql(injection, { entity: "decision" });
    expect(query.filter).toMatchObject({
      kind: "term",
      field: "agent_id",
      op: "eq",
      value: "safe'; DROP TABLE decisions; --",
    });
    expect(() => parseAql("x".repeat(3000), { entity: "decision" })).toThrow(AqlParseError);
  });

  it("round-trips valid queries through serialize and URL encoding", () => {
    const input = 'agent_id:agent-1 AND decision:deny AND @time:[now-24h TO now] | stats count() by decision';
    const serialized = serializeAql(parseAql(input, { entity: "decision" }));
    expect(serialized).toBe(input);
    const roundTrip = decodeAqlParam(encodeAqlParam(serialized));
    expect(serializeAql(parseAql(roundTrip, { entity: "decision" }))).toBe(serialized);
  });
});