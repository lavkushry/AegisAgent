import type { PanelProps, PanelRegistryEntry, PanelType } from "./types";
import StatPanel from "./standard/StatPanel";
import TablePanel from "./standard/TablePanel";
import TimeSeriesPanel from "./standard/TimeSeriesPanel";
import StatusPanel from "./standard/StatusPanel";
import FeedPanel from "./standard/FeedPanel";
import HeatmapPlaceholder from "./standard/HeatmapPlaceholder";
import AgentTablePanel from "./standard/AgentTablePanel";
import ApprovalCard from "./differentiators/ApprovalCard";
import ProvableTimeline from "./differentiators/ProvableTimeline";
import ReceiptIntegrity from "./differentiators/ReceiptIntegrity";

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
  {
    type: "timeseries",
    Component: TimeSeriesPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "recharts",
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
    type: "heatmap",
    Component: HeatmapPlaceholder as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "echarts",
  },
  {
    type: "agent-table",
    Component: AgentTablePanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "approval-card",
    Component: ApprovalCard as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "provable-timeline",
    Component: ProvableTimeline as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "receipt-integrity",
    Component: ReceiptIntegrity as PanelRegistryEntry["Component"],
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
