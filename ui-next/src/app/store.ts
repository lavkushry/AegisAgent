import { create } from "zustand";
import {
  DEMO_MODE,
  loadConnectionSettings,
  persistBearerToken,
  persistConnection,
} from "./runtimeConfig";
import type {
  StreamConnectionStatus,
  VariableValues,
} from "@/datasources/types";

export type Theme = "dark-soc" | "light" | "oled";
export type Density = "compact" | "cozy";

const VALID_THEMES: ReadonlyArray<Theme> = ["dark-soc", "light", "oled"];
const VALID_DENSITIES: ReadonlyArray<Density> = ["compact", "cozy"];

interface AppState {
  gatewayUrl: string;
  bearerToken: string;
  activeTenant: string;
  operatorId: string;
  theme: Theme;
  density: Density;
  activeView: string;
  /** Relative range token for dashboard queries (e.g. "24h"). */
  timeRange: string;
  variables: VariableValues;
  liveMode: boolean;
  streamStatus: StreamConnectionStatus;
  setGatewayUrl: (url: string) => void;
  setBearerToken: (token: string) => void;
  setActiveTenant: (tenant: string) => void;
  setOperatorId: (id: string) => void;
  setTheme: (theme: Theme) => void;
  setDensity: (density: Density) => void;
  setActiveView: (view: string) => void;
  setTimeRange: (range: string) => void;
  setVariables: (variables: VariableValues) => void;
  setLiveMode: (live: boolean) => void;
  setStreamStatus: (status: StreamConnectionStatus) => void;
  applyConnection: (input: {
    gatewayUrl: string;
    activeTenant: string;
    bearerToken?: string;
    operatorId?: string;
  }) => void;
}

function getInitialValue(key: string, fallback: string): string {
  if (typeof window === "undefined") return fallback;
  return window.localStorage.getItem(key) ?? fallback;
}

function getInitialTheme(): Theme {
  const stored = getInitialValue("aegis_theme", "dark-soc");
  return VALID_THEMES.includes(stored as Theme)
    ? (stored as Theme)
    : "dark-soc";
}

function getInitialDensity(): Density {
  const stored = getInitialValue("aegis_density", "compact");
  return VALID_DENSITIES.includes(stored as Density)
    ? (stored as Density)
    : "compact";
}

function getInitialOperatorId(): string {
  if (typeof window === "undefined") {
    return DEMO_MODE ? "platform_admin" : "";
  }
  const stored = window.localStorage.getItem("aegis_operator_id");
  if (stored) return stored;
  return DEMO_MODE ? "platform_admin" : "";
}

function applyAttribute(
  attr: "data-theme" | "data-density",
  value: string,
): void {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute(attr, value);
  }
}

const initial = loadConnectionSettings(
  typeof window !== "undefined" ? window.localStorage : null,
);

const initialTheme = getInitialTheme();
const initialDensity = getInitialDensity();
applyAttribute("data-theme", initialTheme);
applyAttribute("data-density", initialDensity);

export const useAppStore = create<AppState>((set) => ({
  gatewayUrl: initial.gatewayUrl,
  bearerToken: initial.bearerToken,
  activeTenant: initial.activeTenant,
  operatorId: getInitialOperatorId(),
  theme: initialTheme,
  density: initialDensity,
  activeView: "overview",
  timeRange: "24h",
  variables: {},
  liveMode: false,
  streamStatus: "closed",
  setGatewayUrl: (url) => set({ gatewayUrl: url }),
  setBearerToken: (token) => {
    persistBearerToken(
      typeof window !== "undefined" ? window.localStorage : null,
      token,
      DEMO_MODE,
    );
    set({ bearerToken: token });
  },
  setActiveTenant: (tenant) => set({ activeTenant: tenant }),
  setOperatorId: (id) => {
    const next = id.trim();
    if (typeof window !== "undefined") {
      if (next) window.localStorage.setItem("aegis_operator_id", next);
      else window.localStorage.removeItem("aegis_operator_id");
    }
    set({ operatorId: next });
  },
  setTheme: (theme) => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem("aegis_theme", theme);
    }
    applyAttribute("data-theme", theme);
    set({ theme });
  },
  setDensity: (density) => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem("aegis_density", density);
    }
    applyAttribute("data-density", density);
    set({ density });
  },
  setActiveView: (view) => set({ activeView: view }),
  setTimeRange: (timeRange) => set({ timeRange }),
  setVariables: (variables) => set({ variables }),
  setLiveMode: (liveMode) => set({ liveMode }),
  setStreamStatus: (streamStatus) => set({ streamStatus }),
  applyConnection: ({ gatewayUrl, activeTenant, bearerToken, operatorId }) => {
    persistConnection(
      typeof window !== "undefined" ? window.localStorage : null,
      { gatewayUrl, activeTenant },
    );
    const patch: Partial<AppState> = {
      gatewayUrl: gatewayUrl.trim(),
      activeTenant: activeTenant.trim(),
    };
    if (operatorId !== undefined) {
      const next = operatorId.trim();
      if (typeof window !== "undefined") {
        if (next) window.localStorage.setItem("aegis_operator_id", next);
        else window.localStorage.removeItem("aegis_operator_id");
      }
      patch.operatorId = next;
    }
    if (bearerToken !== undefined && bearerToken.trim()) {
      persistBearerToken(
        typeof window !== "undefined" ? window.localStorage : null,
        bearerToken.trim(),
        DEMO_MODE,
      );
      patch.bearerToken = bearerToken.trim();
    }
    set(patch);
  },
}));
