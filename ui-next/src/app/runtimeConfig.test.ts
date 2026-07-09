import { describe, expect, test } from "bun:test";
import {
  loadConnectionSettings,
  persistBearerToken,
  type StorageLike,
} from "./runtimeConfig";

function memStorage(seed: Record<string, string> = {}): StorageLike {
  const map = new Map(Object.entries(seed));
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      map.set(k, v);
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

describe("loadConnectionSettings", () => {
  test("demo mode prefills tenant and bearer", () => {
    const s = loadConnectionSettings(memStorage(), true);
    expect(s.activeTenant).toBe("tenant_123");
    expect(s.bearerToken).toBe("tenant_123");
    expect(s.gatewayUrl).toContain("8080");
  });

  test("production mode leaves tenant empty and strips stored bearer", () => {
    const storage = memStorage({
      aegis_bearer_token: "secret",
      aegis_active_tenant: "",
    });
    const s = loadConnectionSettings(storage, false);
    expect(s.activeTenant).toBe("");
    expect(s.bearerToken).toBe("");
    expect(storage.getItem("aegis_bearer_token")).toBeNull();
  });
});

describe("persistBearerToken", () => {
  test("demo mode stores token", () => {
    const storage = memStorage();
    persistBearerToken(storage, "tenant_abc", true);
    expect(storage.getItem("aegis_bearer_token")).toBe("tenant_abc");
  });

  test("production mode never stores token", () => {
    const storage = memStorage({ aegis_bearer_token: "old" });
    persistBearerToken(storage, "new", false);
    expect(storage.getItem("aegis_bearer_token")).toBeNull();
  });
});
