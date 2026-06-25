import type { TimeRange } from "@/datasources/types";
import type { PanelDefinition } from "@/panels/types";

/**
 * Dashboard model. See docs/AegisAgent_SOC_Console_HLD_LLD.md section 7.3.
 * Curated system dashboards are typed JSON in dashboards/system/*; the
 * future in-app editor writes the same shape.
 */
export interface VariableDefinition {
  readonly name: string;
  readonly kind: "constant" | "query" | "interval";
  readonly query?: string;
  readonly multi?: boolean;
  readonly includeAll?: boolean;
}

export interface LayoutItem {
  readonly panel: PanelDefinition;
  readonly w: number; // 1-12 grid columns
  readonly h: number; // row-height units
}

export interface Row {
  readonly id: string;
  readonly tab?: string;
  readonly title?: string;
  readonly panels: ReadonlyArray<LayoutItem>;
}

export interface DashboardSchema {
  readonly uid: string;
  readonly title: string;
  readonly schemaVersion: 1;
  readonly variables: ReadonlyArray<VariableDefinition>;
  readonly time: { readonly defaultRange: TimeRange; readonly refreshSec?: number };
  readonly layout: ReadonlyArray<Row>;
}
