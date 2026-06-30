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
      new Response(JSON.stringify({ rows: [{ decision: "deny" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const frame = await new SocQueryDatasource(options).query(request);

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(String(init.body));
    expect(body).toEqual({
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
