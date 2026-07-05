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
