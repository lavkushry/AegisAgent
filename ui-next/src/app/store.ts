import { create } from "zustand";
import {
  DEMO_MODE,
  loadConnectionSettings,
  persistBearerToken,
  persistConnection,
} from "./runtimeConfig";

export type Theme = "dark-soc" | "light" | "oled";
export type Density = "compact" | "cozy";

const VALID_THEMES: ReadonlyArray<Theme> = ["dark-soc", "light", "oled"];
const VALID_DENSITIES: ReadonlyArray<Density> = ["compact", "cozy"];

interface AppState {
  gatewayUrl: string;
  bearerToken: string;
  activeTenant: string;
  theme: Theme;
  density: Density;
  activeView: string;
  setGatewayUrl: (url: string) => void;
  setBearerToken: (token: string) => void;
  setActiveTenant: (tenant: string) => void;
  setTheme: (theme: Theme) => void;
  setDensity: (density: Density) => void;
  setActiveView: (view: string) => void;
  applyConnection: (input: {
    gatewayUrl: string;
    activeTenant: string;
    bearerToken?: string;
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
  theme: initialTheme,
  density: initialDensity,
  activeView: "overview",
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
  applyConnection: ({ gatewayUrl, activeTenant, bearerToken }) => {
    persistConnection(
      typeof window !== "undefined" ? window.localStorage : null,
      { gatewayUrl, activeTenant },
    );
    if (bearerToken !== undefined && bearerToken.trim()) {
      persistBearerToken(
        typeof window !== "undefined" ? window.localStorage : null,
        bearerToken.trim(),
        DEMO_MODE,
      );
      set({
        gatewayUrl: gatewayUrl.trim(),
        activeTenant: activeTenant.trim(),
        bearerToken: bearerToken.trim(),
      });
      return;
    }
    set({
      gatewayUrl: gatewayUrl.trim(),
      activeTenant: activeTenant.trim(),
    });
  },
}));
