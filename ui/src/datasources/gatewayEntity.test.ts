import { describe, expect, it } from "vitest";

import { GatewayEntityDatasource } from "./gatewayEntity";

describe("GatewayEntityDatasource", () => {
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
});
