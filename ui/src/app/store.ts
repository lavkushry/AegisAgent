import { create } from "zustand";
import { DEMO_MODE, loadConnectionSettings, persistBearerToken } from "./runtimeConfig";

export type Theme = "dark-soc" | "light" | "oled";
export type Density = "compact" | "cozy";
export type Role = "viewer" | "analyst" | "approver" | "admin";

interface AppState {
  gatewayUrl: string;
  bearerToken: string;
  authEpoch: number;
  activeTenant: string;
  timeRange: string; // "1h", "24h", "7d", etc.
  variables: Record<string, string>;
  liveMode: boolean;
  theme: Theme;
  density: Density;
  role: Role;
  /** Current nav view (lifted so drilldowns can navigate). */
  activeView: string;
  /** Pending Explore search seeded by a drilldown; consumed by ExploreTab. */
  exploreSeed: string | null;
  exploreQuery: string;
  activeIncidentId: string | null;
  activeReceiptId: string | null;
  setGatewayUrl: (url: string) => void;
  setBearerToken: (token: string) => void;
  setActiveTenant: (tenant: string) => void;
  setTimeRange: (range: string) => void;
  setVariables: (variables: Record<string, string>) => void;
  setLiveMode: (live: boolean) => void;
  setTheme: (theme: Theme) => void;
  setDensity: (density: Density) => void;
  setRole: (role: Role) => void;
  setActiveView: (view: string) => void;
  setExploreSeed: (seed: string) => void;
  setExploreQuery: (query: string) => void;
  consumeExploreSeed: () => void;
  setActiveIncidentId: (id: string | null) => void;
  setActiveReceiptId: (id: string | null) => void;
}

const getInitialValue = (key: string, fallback: string) => {
  if (typeof window !== "undefined") {
    return localStorage.getItem(key) || fallback;
  }
  return fallback;
};

const initialConnection = loadConnectionSettings(
  typeof window !== "undefined" ? window.localStorage : null,
);

const VALID_THEMES: ReadonlyArray<Theme> = ["dark-soc", "light", "oled"];
const VALID_DENSITIES: ReadonlyArray<Density> = ["compact", "cozy"];
const VALID_ROLES: ReadonlyArray<Role> = ["viewer", "analyst", "approver", "admin"];

const getInitialTheme = (): Theme => {
  const stored = getInitialValue("aegis_theme", "dark-soc");
  return VALID_THEMES.includes(stored as Theme) ? (stored as Theme) : "dark-soc";
};

const getInitialDensity = (): Density => {
  const stored = getInitialValue("aegis_density", "compact");
  return VALID_DENSITIES.includes(stored as Density) ? (stored as Density) : "compact";
};

const getInitialRole = (): Role => {
  if (!DEMO_MODE) {
    if (typeof window !== "undefined") localStorage.removeItem("aegis_role");
    return "viewer";
  }
  const fallback: Role = DEMO_MODE ? "admin" : "viewer";
  const stored = getInitialValue("aegis_role", fallback);
  return VALID_ROLES.includes(stored as Role) ? (stored as Role) : fallback;
};

const applyAttribute = (attr: "data-theme" | "data-density", value: string) => {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute(attr, value);
  }
};

export const useAppStore = create<AppState>((set) => ({
  gatewayUrl: initialConnection.gatewayUrl,
  bearerToken: initialConnection.bearerToken,
  authEpoch: 0,
  activeTenant: initialConnection.activeTenant,
  timeRange: "24h",
  variables: {},
  liveMode: false,
  theme: getInitialTheme(),
  density: getInitialDensity(),
  role: getInitialRole(),
  activeView: "overview",
  exploreSeed: null,
  exploreQuery: "",
  activeIncidentId: null,
  activeReceiptId: null,
  setGatewayUrl: (url) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_gateway_url", url);
    set({ gatewayUrl: url });
  },
  setBearerToken: (token) => {
    persistBearerToken(typeof window !== "undefined" ? window.localStorage : null, token, DEMO_MODE);
    set((state) => ({ bearerToken: token, authEpoch: state.authEpoch + 1 }));
  },
  setActiveTenant: (tenant) => {
    if (typeof window !== "undefined") localStorage.setItem("aegis_active_tenant", tenant);
    set({ activeTenant: tenant });
  },
  setTimeRange: (range) => set({ timeRange: range }),
  setVariables: (variables) => set({ variables }),
  setLiveMode: (liveMode) => set({ liveMode }),
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
  setRole: (role) => {
    if (typeof window !== "undefined" && DEMO_MODE) localStorage.setItem("aegis_role", role);
    set({ role });
  },
  setActiveView: (view) => set({ activeView: view }),
  setExploreSeed: (seed) => set({ exploreSeed: seed, exploreQuery: seed }),
  setExploreQuery: (exploreQuery) => set({ exploreQuery }),
  consumeExploreSeed: () => set({ exploreSeed: null }),
  setActiveIncidentId: (activeIncidentId) => set({ activeIncidentId }),
  setActiveReceiptId: (activeReceiptId) => set({ activeReceiptId }),
}));

/** Roles permitted to act on the approval queue (separation of duties). */
export function canApprove(role: Role): boolean {
  return role === "approver" || role === "admin";
}
