import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import type { DashboardSchema } from "../schema";

const SOC_QUERY_DATASOURCE_ID = "soc-query";

/**
 * Runtime timeline dashboard (Phase 9.2 partial) — durable Agent Security
 * Events as the console surface for sensor/cage/egress/SDK runtime telemetry.
 */
export const runtimeDashboard: DashboardSchema = {
  uid: "runtime",
  title: "Runtime Timeline",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 10 },
  layout: [
    {
      id: "runtime-note",
      panels: [
        {
          panel: {
            id: "note-runtime-scope",
            type: "note",
            title: "Scope",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body:
                "Durable ASE via POST /v1/ingest/runtime-events (hashes/ids only). " +
                "Cage execution binary and full sensor collectors are Wave A; " +
                "this page surfaces events that already land on the control plane.",
              variant: "info",
            },
          },
          w: 12,
          h: 2,
        },
      ],
    },
    {
      id: "runtime-trends",
      title: "Event volume",
      panels: [
        {
          panel: {
            id: "ts-ase-events",
            type: "timeseries",
            title: "Agent security events",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "ase",
            aggregate: "count_over_time",
            interval: "hour",
            drilldowns: [
              {
                label: "Explore ASE",
                target: { kind: "explore", aqlTemplate: "event_type:*" },
              },
            ],
          },
          w: 12,
          h: 3,
        },
      ],
    },
    {
      id: "runtime-feed",
      title: "Recent runtime events",
      panels: [
        {
          panel: {
            id: "feed-ase",
            type: "feed",
            title: "ASE feed",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "ase",
            limit: 20,
            options: {
              titleField: "event_type",
              detailField: "source_component",
              timeField: "observed_at",
              maxRows: 20,
            },
            drilldowns: [
              {
                label: "Explore ASE",
                target: { kind: "explore", aqlTemplate: "event_type:*" },
              },
            ],
          },
          w: 12,
          h: 5,
        },
      ],
    },
  ],
};
