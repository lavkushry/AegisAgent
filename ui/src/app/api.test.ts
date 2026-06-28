import { afterEach, describe, expect, it, vi } from "vitest";

import { buildGatewayHeaders, fetchFromGateway } from "./api";

describe("gateway transport", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("binds authentication and tenant context to every request", () => {
    expect(
      buildGatewayHeaders(
        {
          gatewayUrl: "http://127.0.0.1:8080",
          bearerToken: "secret-token",
          tenantId: "tenant-a",
        },
        true,
      ),
    ).toEqual({
      Accept: "application/json",
      Authorization: "Bearer secret-token",
      "Content-Type": "application/json",
      "X-Aegis-Tenant-ID": "tenant-a",
    });
  });

  it("fails before network access when tenant context is missing", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchFromGateway(
        {
          gatewayUrl: "http://127.0.0.1:8080",
          bearerToken: "secret-token",
          tenantId: "",
        },
        "/v1/stats",
      ),
    ).rejects.toThrow("tenant");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
