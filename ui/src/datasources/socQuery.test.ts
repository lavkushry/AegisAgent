import { afterEach, describe, expect, it, vi } from "vitest";

import { SocQueryDatasource } from "./socQuery";

const options = {
  gatewayUrl: "http://gateway.test",
  bearerToken: "token",
  tenantId: "tenant-a",
};

const request = {
  entity: "decision" as const,
  aql: "agent_id:agent-1 AND decision:deny",
  timeRange: { from: "now-24h", to: "now" },
  variables: {},
};

describe("SocQueryDatasource", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("sends structured filters instead of a raw query string", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({
        rows: [{ decision: "deny" }],
        field_descriptors: [{ name: "decision", type: "decision", facetable: true }],
        meta: { total: 1 },
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const frame = await new SocQueryDatasource(options).query(request);

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(String(init.body));
    expect(body).toEqual({
      version: 1,
      entity: "decision",
      filters: {
        agent_id: "agent-1",
        decision: "deny",
        from: "now-24h",
        to: "now",
      },
      limit: 50,
    });
    expect(body).not.toHaveProperty("aql");
    expect(body).not.toHaveProperty("time_range");
    expect(body).not.toHaveProperty("pagination");
    expect(frame.length).toBe(1);
    expect(frame.meta?.total).toBe(1);
    expect(frame.meta?.fieldDescriptors?.[0]?.name).toBe("decision");
  });

  it("sends bounded group-by requests with complete typed investigation filters", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ rows: [{ value: "deny", count: 2 }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await new SocQueryDatasource(options).query({
      ...request,
      aql: "action:write run_id:run-1 trace_id:trace-1 action_hash:ah receipt_hash:rh",
      aggregate: "count_by",
      groupBy: "decision",
      limit: 20,
    });

    const body = JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body));
    expect(body).toMatchObject({
      version: 1,
      aggregate: "count_by",
      group_by: "decision",
      limit: 20,
      filters: {
        action: "write",
        run_id: "run-1",
        trace_id: "trace-1",
        action_hash: "ah",
        receipt_hash: "rh",
      },
    });
  });

  it("falls back to parameterized decisions search when the query API is absent", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response("{}", { status: 404, statusText: "Not Found" }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify([{ id: "decision-1", decision: "deny" }]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const frame = await new SocQueryDatasource(options).query(request);

    expect(String(fetchMock.mock.calls[1][0])).toContain("agent_id=agent-1");
    expect(String(fetchMock.mock.calls[1][0])).toContain("decision=deny");
    expect(frame.length).toBe(1);
  });
});
