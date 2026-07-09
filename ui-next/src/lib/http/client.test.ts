import { describe, expect, test } from "bun:test";
import { buildGatewayHeaders } from "./client";
import { TenantRequiredError } from "./errors";

describe("buildGatewayHeaders", () => {
  test("throws when tenant is empty", () => {
    expect(() =>
      buildGatewayHeaders({
        gatewayUrl: "http://127.0.0.1:8080",
        bearerToken: "x",
        tenantId: "  ",
      }),
    ).toThrow(TenantRequiredError);
  });

  test("sets tenant and authorization headers", () => {
    const h = buildGatewayHeaders({
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "tenant_123",
      tenantId: "tenant_123",
    });
    expect(h["X-Aegis-Tenant-ID"]).toBe("tenant_123");
    expect(h.Authorization).toBe("Bearer tenant_123");
    expect(h.Accept).toBe("application/json");
  });

  test("sets content-type only when body present", () => {
    const noBody = buildGatewayHeaders(
      {
        gatewayUrl: "http://127.0.0.1:8080",
        bearerToken: "t",
        tenantId: "t",
      },
      false,
    );
    expect(noBody["Content-Type"]).toBeUndefined();

    const withBody = buildGatewayHeaders(
      {
        gatewayUrl: "http://127.0.0.1:8080",
        bearerToken: "t",
        tenantId: "t",
      },
      true,
    );
    expect(withBody["Content-Type"]).toBe("application/json");
  });
});
