"use client";

import { useAppStore, type Theme } from "@/app/store";

export interface ChartColors {
  brand: string;
  textMuted: string;
  border: string;
  surfacePanel: string;
  decisionAllow: string;
  decisionDeny: string;
  decisionApproval: string;
}

/**
 * Concrete chart colours per theme for charting libraries (Recharts/uPlot/
 * ECharts) whose SVG props do not reliably accept `var()`. These mirror the
 * chart-relevant subset of design-system/tokens.css — keep them in sync if a
 * token value changes. Pure + SSR-safe: re-derives when the store theme
 * changes, with no effect or DOM read.
 */
const THEME_CHART_COLORS: Record<Theme, ChartColors> = {
  "dark-soc": {
    brand: "#6366f1",
    textMuted: "#64748b",
    border: "#334155",
    surfacePanel: "#111827",
    decisionAllow: "#22c55e",
    decisionDeny: "#ef4444",
    decisionApproval: "#f59e0b",
  },
  light: {
    brand: "#4f46e5",
    textMuted: "#64748b",
    border: "#e2e8f0",
    surfacePanel: "#ffffff",
    decisionAllow: "#16a34a",
    decisionDeny: "#dc2626",
    decisionApproval: "#d97706",
  },
  oled: {
    brand: "#818cf8",
    textMuted: "#71717a",
    border: "#27272a",
    surfacePanel: "#0b0b0f",
    decisionAllow: "#4ade80",
    decisionDeny: "#f87171",
    decisionApproval: "#fbbf24",
  },
};

/** Chart colours for the active theme. */
export function useChartColors(): ChartColors {
  const theme = useAppStore((s) => s.theme);
  return THEME_CHART_COLORS[theme];
}
