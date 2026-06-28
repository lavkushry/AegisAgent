import { describe, expect, it, vi } from "vitest";

import { loadConnectionSettings, persistBearerToken, type StorageLike } from "./runtimeConfig";

function storageWith(values: Record<string, string> = {}): StorageLike {
  return {
    getItem: vi.fn((key: string) => values[key] ?? null),
    setItem: vi.fn(),
    removeItem: vi.fn(),
  };
}

describe("runtime connection configuration", () => {
  it("provides local demo credentials only when demo mode is explicit", () => {
    expect(loadConnectionSettings(null, true)).toEqual({
      gatewayUrl: "http://127.0.0.1:8080",
      bearerToken: "tenant_123",
      activeTenant: "tenant_123",
    });
  });

  it("does not load a persisted bearer token in production mode", () => {
    const storage = storageWith({
      aegis_gateway_url: "https://gateway.example",
      aegis_bearer_token: "legacy-secret",
      aegis_active_tenant: "tenant-a",
    });

    expect(loadConnectionSettings(storage, false)).toEqual({
      gatewayUrl: "https://gateway.example",
      bearerToken: "",
      activeTenant: "tenant-a",
    });
    expect(storage.removeItem).toHaveBeenCalledWith("aegis_bearer_token");
  });

  it("never persists production bearer tokens", () => {
    const storage = storageWith();

    persistBearerToken(storage, "new-secret", false);

    expect(storage.setItem).not.toHaveBeenCalled();
    expect(storage.removeItem).toHaveBeenCalledWith("aegis_bearer_token");
  });
});
