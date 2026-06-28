export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface ConnectionSettings {
  gatewayUrl: string;
  bearerToken: string;
  activeTenant: string;
}

export const DEMO_MODE = process.env.NEXT_PUBLIC_AEGIS_DEMO_MODE === "true";

const DEFAULT_GATEWAY_URL =
  process.env.NEXT_PUBLIC_AEGIS_GATEWAY_URL || "http://127.0.0.1:8080";
const DEMO_TENANT = "tenant_123";

export function loadConnectionSettings(
  storage: StorageLike | null,
  demoMode = DEMO_MODE,
): ConnectionSettings {
  const gatewayUrl = storage?.getItem("aegis_gateway_url") || DEFAULT_GATEWAY_URL;
  const activeTenant =
    storage?.getItem("aegis_active_tenant") || (demoMode ? DEMO_TENANT : "");

  if (!demoMode) {
    // Remove credentials persisted by older UI releases. Production credentials
    // remain in memory only; the gateway remains the authorization authority.
    storage?.removeItem("aegis_bearer_token");
  }

  return {
    gatewayUrl,
    bearerToken: demoMode
      ? storage?.getItem("aegis_bearer_token") || DEMO_TENANT
      : "",
    activeTenant,
  };
}

export function persistBearerToken(
  storage: StorageLike | null,
  token: string,
  demoMode = DEMO_MODE,
): void {
  if (!storage) return;

  if (demoMode && token) {
    storage.setItem("aegis_bearer_token", token);
    return;
  }

  storage.removeItem("aegis_bearer_token");
}
