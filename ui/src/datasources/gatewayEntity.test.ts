import { afterEach, describe, expect, it, vi } from "vitest";

import { GatewayEntityDatasource } from "./gatewayEntity";

describe("GatewayEntityDatasource", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects ASE reads instead of calling an unregistered GET endpoint", async () => {
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    await expect(datasource.query({
      entity: "ase",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    })).rejects.toThrow("requires the soc-query datasource");

    await expect(datasource.query({
      entity: "ase",
      aggregate: "count_over_time",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    })).rejects.toThrow("requires the soc-query datasource");
  });

  it("rejects count_over_time for entities without a timeseries endpoint", async () => {
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    await expect(datasource.query({
      entity: "incident",
      aggregate: "count_over_time",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    })).rejects.toThrow("only supported for the 'decision' entity");
  });

  it("propagates query abort signals to gateway entity reads", async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ id: "decision-1" }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    await datasource.query({
      entity: "decision",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
      signal: controller.signal,
    });

    expect(fetchMock.mock.calls[0][1]?.signal).toBe(controller.signal);
  });

  it("forwards cursor pagination to entity list endpoints", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    await datasource.query({
      entity: "approval",
      cursor: "cursor-42",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(fetchMock.mock.calls[0][0]).toContain("cursor=cursor-42");
  });

  it("fetches tenant snapshot objects as single-row frames", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ total_decisions: 42, decisions_allow: 40 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    const frame = await datasource.query({
      snapshot: "tenant-stats",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(fetchMock.mock.calls[0][0]).toContain("/v1/stats");
    expect(frame.length).toBe(1);
    expect(frame.fields.find((field) => field.name === "total_decisions")?.values[0]).toBe(42);
  });

  it("derives untrusted_source_count from tenant stats trust breakdown", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          total_decisions: 42,
          trust_level_breakdown: [
            { trust_level: "trusted_internal_signed", count: 30 },
            { trust_level: "untrusted_external", count: 4 },
            { trust_level: "malicious_suspected", count: 2 },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    const frame = await datasource.query({
      snapshot: "tenant-stats",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(frame.fields.find((field) => field.name === "untrusted_source_count")?.values[0]).toBe(6);
  });

  it("expands trust breakdown snapshots into row frames", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          trust_level_breakdown: [
            { trust_level: "trusted_internal_signed", count: 10 },
            { trust_level: "unknown", count: 1 },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    const frame = await datasource.query({
      snapshot: "trust-breakdown",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(fetchMock.mock.calls[0][0]).toContain("/v1/stats");
    expect(frame.length).toBe(2);
    expect(frame.fields.find((field) => field.name === "trust_level")?.values[0]).toBe(
      "trusted_internal_signed",
    );
  });

  it("fetches agent scoreboard snapshots as row frames", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify([{ agent_id: "agent-1", avg_risk_score: 0.9 }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    const frame = await datasource.query({
      snapshot: "agent-scoreboard",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(fetchMock.mock.calls[0][0]).toContain("/v1/agents/risk-scoreboard");
    expect(frame.length).toBe(1);
    expect(frame.fields.find((field) => field.name === "agent_id")?.values[0]).toBe("agent-1");
  });

  it("routes rules catalog reads to SOC and detection endpoints", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify([{ rule_key: "deny-storm", name: "Deny storm" }]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    await datasource.query({
      rulesCatalog: "soc",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });
    await datasource.query({
      rulesCatalog: "detection",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(fetchMock.mock.calls[0][0]).toContain("/v1/soc/rules");
    expect(fetchMock.mock.calls[1][0]).toContain("/v1/detection_rules");
  });

  it("fetches incident sub-resources and manifest history", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ nodes: [{ id: "node-1", group: "receipt" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ narrative: "Root cause identified." }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ snapshots: [{ event_type: "drift", manifest_hash: "abc" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    const graphFrame = await datasource.query({
      entity: "incident",
      entityId: "incident-1",
      subResource: "graph",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });
    const narrateFrame = await datasource.query({
      entity: "incident",
      entityId: "incident-1",
      subResource: "narrate",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });
    const historyFrame = await datasource.query({
      entity: "mcp_server",
      entityId: "github",
      subResource: "manifest-history",
      timeRange: { from: "now-24h", to: "now" },
      variables: {},
    });

    expect(fetchMock.mock.calls[0][0]).toContain("/v1/graph/incident/incident-1");
    expect(fetchMock.mock.calls[1][0]).toContain("/v1/incidents/incident-1/narrate");
    expect(fetchMock.mock.calls[2][0]).toContain("/v1/mcp/servers/github/manifest-history");
    expect(graphFrame.fields.find((field) => field.name === "nodes")?.values[0]).toEqual([
      { id: "node-1", group: "receipt" },
    ]);
    expect(narrateFrame.fields.find((field) => field.name === "narrative")?.values[0]).toBe(
      "Root cause identified.",
    );
    expect(historyFrame.length).toBe(1);
    expect(historyFrame.fields.find((field) => field.name === "event_type")?.values[0]).toBe("drift");
  });

  it("returns shared field catalogs for non-decision gateway entities", async () => {
    const datasource = new GatewayEntityDatasource({
      gatewayUrl: "http://gateway.test",
      bearerToken: "token",
      tenantId: "tenant-a",
    });

    const approvalFields = await datasource.fields("approval");

    expect(approvalFields.map((field) => field.name)).toEqual(
      expect.arrayContaining(["status", "tool_name", "action_hash", "effective_action_hash", "expires_at"]),
    );
    expect(approvalFields.find((field) => field.name === "action_hash")).toMatchObject({
      type: "hash",
      facetable: false,
    });
  });
});
