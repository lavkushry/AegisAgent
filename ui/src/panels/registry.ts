import type { PanelProps, PanelRegistryEntry, PanelType } from "./types";
import StatPanel from "./standard/StatPanel";
import TablePanel from "./standard/TablePanel";

/**
 * The panel registry maps a PanelType to its renderer. New panel types
 * (provable-timeline, approval-card, agent-risk-map, ...) register here as
 * they are built; dashboards reference panels only by type.
 */
const entries: PanelRegistryEntry[] = [
  {
    type: "stat",
    Component: StatPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "recharts",
  },
  {
    type: "table",
    Component: TablePanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
];

export const panelRegistry: Map<PanelType, PanelRegistryEntry> = new Map(
  entries.map((e) => [e.type, e]),
);

export function getPanelEntry(type: PanelType): PanelRegistryEntry | undefined {
  return panelRegistry.get(type);
}

export type { PanelProps };
