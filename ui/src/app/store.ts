import { create } from "zustand";

export type Theme = "dark-soc" | "light" | "oled";
export type Density = "compact" | "cozy";

interface AppState {
  gatewayUrl: string;
  bearerToken: string;
  activeTenant: string;
  timeRange: string; // "1h", "24h", "7d", etc.
  theme: Theme;
  density: Density;
  setGatewayUrl: (url: string) => void;
  setBearerToken: (token: string) => void;
  setActiveTenant: (tenant: string) => void;
  setTimeRange: (range: string) => void;
  setTheme: (theme: Theme) => void;
  setDensity: (density: Density) => void;
}

// Initializing values from localStorage if available in browser context
const getInitialValue = (key: string, fallback: string) => {
  if (typeof window !== "undefined") {
    return localStorage.getItem(key) || fallback;
  }
  return fallback;
};

const VALID_THEMES: ReadonlyArray<Theme> = ["dark-soc", "light", "oled"];
const VALID_DENSITIES: ReadonlyArray<Density> = ["compact", "cozy"];

const getInitialTheme = (): Theme => {
  const stored = getInitialValue("aegis_theme", "dark-soc");
  return VALID_THEMES.includes(stored as Theme) ? (stored as Theme) : "dark-soc";
};

const getInitialDensity = (): Density => {
  const stored = getInitialValue("aegis_density", "compact");
  return VALID_DENSITIES.includes(stored as Density)
    ? (stored as Density)
    : "compact";
};

// Reflect a preference onto <html> so token overrides apply immediately.
const applyAttribute = (attr: "data-theme" | "data-density", value: string) => {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute(attr, value);
  }
};

export const useAppStore = create<AppState>((set) => ({
  gatewayUrl: getInitialValue("aegis_gateway_url", "http://127.0.0.1:8080"),
  bearerToken: getInitialValue("aegis_bearer_token", "tenant_123"),
  activeTenant: getInitialValue("aegis_active_tenant", "tenant_123"),
  timeRange: "24h",
  theme: getInitialTheme(),
  density: getInitialDensity(),
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
  setTheme: (theme) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_theme", theme);
    applyAttribute("data-theme", theme);
    set({ theme });
  },
  setDensity: (density) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_density", density);
    applyAttribute("data-density", density);
    set({ density });
  },
}));
