import { create } from "zustand";

interface AppState {
  gatewayUrl: string;
  bearerToken: string;
  activeTenant: string;
  timeRange: string; // "1h", "24h", "7d", etc.
  setGatewayUrl: (url: string) => void;
  setBearerToken: (token: string) => void;
  setActiveTenant: (tenant: string) => void;
  setTimeRange: (range: string) => void;
}

// Initializing values from localStorage if available in browser context
const getInitialValue = (key: string, fallback: string) => {
  if (typeof window !== "undefined") {
    return localStorage.getItem(key) || fallback;
  }
  return fallback;
};

export const useAppStore = create<AppState>((set) => ({
  gatewayUrl: getInitialValue("aegis_gateway_url", "http://127.0.0.1:8080"),
  bearerToken: getInitialValue("aegis_bearer_token", "tenant_123"),
  activeTenant: getInitialValue("aegis_active_tenant", "tenant_123"),
  timeRange: "24h",
  setGatewayUrl: (url) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_gateway_url", url);
    set({ gatewayUrl: url });
  },
  setBearerToken: (token) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_bearer_token", token);
    set({ bearerToken: token });
  },
  setActiveTenant: (tenant) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_active_tenant", tenant);
    set({ activeTenant: tenant });
  },
  setTimeRange: (range) => set({ timeRange: range }),
}));
