import type { PanelRegistryEntry, PanelType } from "./types";
import StatPanel from "./standard/StatPanel";
import TablePanel from "./standard/TablePanel";
import StatusPanel from "./standard/StatusPanel";
import FeedPanel from "./standard/FeedPanel";
import NotePanel from "./standard/NotePanel";
import HeatmapPanel from "./standard/HeatmapPanel";
import TimeSeriesPanel from "./standard/TimeSeriesPanel";
import ApprovalCardPanel from "./differentiators/ApprovalCardPanel";
import ProvableTimelinePanel from "./differentiators/ProvableTimelinePanel";
import ReceiptIntegrityPanel from "./differentiators/ReceiptIntegrityPanel";
import AgentRiskMapPanel from "./differentiators/AgentRiskMapPanel";

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
    Component: HeatmapPanel as PanelRegistryEntry["Component"],
    defaultOptions: {},
    chartLib: "none",
  },
  {
    type: "approval-card",
    Component: ApprovalCardPanel as PanelRegistryEntry["Component"],
    defaultOptions: { maxCards: 6, interactive: true },
    chartLib: "none",
  },
  {
    type: "provable-timeline",
    Component: ProvableTimelinePanel as PanelRegistryEntry["Component"],
    defaultOptions: { maxRows: 25, showRangeVerify: true },
    chartLib: "none",
  },
  {
    type: "receipt-integrity",
    Component: ReceiptIntegrityPanel as PanelRegistryEntry["Component"],
    defaultOptions: { showExports: true, showRangeVerify: true },
    chartLib: "none",
  },
  {
    type: "agent-risk-map",
    Component: AgentRiskMapPanel as PanelRegistryEntry["Component"],
    defaultOptions: { maxRows: 10 },
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
