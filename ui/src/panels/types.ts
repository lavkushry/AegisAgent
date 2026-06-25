import type { ComponentType } from "react";
import type {
  DataFrame,
  EntityKind,
  TimeRange,
  VariableValues,
} from "@/datasources/types";

/**
 * Panel framework contracts. See
 * docs/AegisAgent_SOC_Console_HLD_LLD.md section 7.1.
 *
 * Panels never fetch. PanelRuntime fetches and passes a DataFrame; panels
 * are pure: (data, state) -> JSX.
 */

export type PanelType =
  | "stat"
  | "timeseries"
  | "table"
  | "heatmap"
  | "status"
  | "feed"
  | "provable-timeline"
  | "approval-card"
  | "receipt-integrity"
  | "agent-risk-map"
  | "decision-graph";

/** Where a click on a panel row/series navigates. */
export interface DrilldownLink {
  readonly label: string;
  readonly target:
    | { kind: "verify-receipt"; receiptIdField: string }
    | { kind: "dashboard"; uid: string; mapVars: Record<string, string> }
    | { kind: "explore"; aqlTemplate: string }
    | { kind: "incident"; incidentIdField: string };
}

/** Declarative panel config — this is what lives in DashboardSchema JSON. */
export interface PanelDefinition<TOptions = Record<string, unknown>> {
  readonly id: string;
  readonly type: PanelType;
  readonly title: string;
  readonly datasourceId: string;
  readonly entity?: EntityKind;
  readonly query?: string;
  readonly search?: string;
  readonly options?: TOptions;
  readonly drilldowns?: ReadonlyArray<DrilldownLink>;
}

/** Props every panel component receives. */
export interface PanelProps<TOptions = Record<string, unknown>> {
  readonly definition: PanelDefinition<TOptions>;
  readonly data: DataFrame;
  readonly timeRange: TimeRange;
  readonly variables: VariableValues;
  readonly onDrilldown: (link: DrilldownLink, row?: Record<string, unknown>) => void;
}

/** Registry entry: a panel type's renderer + its default options. */
export interface PanelRegistryEntry<TOptions = Record<string, unknown>> {
  readonly type: PanelType;
  readonly Component: ComponentType<PanelProps<TOptions>>;
  readonly defaultOptions: TOptions;
  readonly chartLib?: "recharts" | "uplot" | "echarts" | "tanstack-table" | "none";
}
