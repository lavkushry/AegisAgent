import type { PanelRegistryEntry, PanelType } from "./types";
import StatPanel from "./standard/StatPanel";
import TablePanel from "./standard/TablePanel";
import StatusPanel from "./standard/StatusPanel";
import FeedPanel from "./standard/FeedPanel";
import NotePanel from "./standard/NotePanel";
import HeatmapPlaceholder from "./standard/HeatmapPlaceholder";
import TimeSeriesPanel from "./standard/TimeSeriesPanel";

const entries: PanelRegistryEntry[] = [
  {
    type: "stat",
    Component: StatPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "table",
    Component: TablePanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "timeseries",
    Component: TimeSeriesPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "status",
    Component: StatusPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "feed",
    Component: FeedPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "note",
    Component: NotePanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "heatmap",
    Component: HeatmapPlaceholder as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
];

export const panelRegistry: Map<PanelType, PanelRegistryEntry> = new Map(
  entries.map((e) => [e.type, e]),
);

export function getPanelEntry(
  type: PanelType,
): PanelRegistryEntry | undefined {
  return panelRegistry.get(type);
}
