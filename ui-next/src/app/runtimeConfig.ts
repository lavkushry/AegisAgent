/** Connection + demo mode (ported from legacy ui/src/app/runtimeConfig.ts). */

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

/** Vite: VITE_AEGIS_DEMO_MODE=true for local Docker defaults. */
export const DEMO_MODE = import.meta.env.VITE_AEGIS_DEMO_MODE === "true";

const DEFAULT_GATEWAY_URL =
  import.meta.env.VITE_AEGIS_GATEWAY_URL || "http://127.0.0.1:8080";

const DEMO_TENANT = "tenant_123";

export function loadConnectionSettings(
  storage: StorageLike | null,
  demoMode = DEMO_MODE,
): ConnectionSettings {
  const gatewayUrl =
    storage?.getItem("aegis_gateway_url") || DEFAULT_GATEWAY_URL;
  const activeTenant =
    storage?.getItem("aegis_active_tenant") || (demoMode ? DEMO_TENANT : "");

  if (!demoMode) {
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

export function persistConnection(
  storage: StorageLike | null,
  settings: Pick<ConnectionSettings, "gatewayUrl" | "activeTenant">,
): void {
  if (!storage) return;
  storage.setItem("aegis_gateway_url", settings.gatewayUrl);
  storage.setItem("aegis_active_tenant", settings.activeTenant);
}
