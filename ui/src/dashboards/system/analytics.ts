import { DEFAULT_DATASOURCE_ID } from "@/datasources/registry";
import { SOC_QUERY_DATASOURCE_ID } from "@/datasources/socQuery";
import type { DashboardSchema } from "../schema";

const METRIC_DEFINITIONS =
  "Decision volume: authorizations in the selected window (server-downsampled).\n" +
  "Deny rate: denies ÷ decisions over the last 24h from GET /v1/soc/summary.\n" +
  "Trust mix: per-level decision counts — deterministic provenance, not text scoring.\n" +
  "Risk scoreboard: rolling 24h composite average — advisory only, never Cedar truth.\n" +
  "Receipt coverage: hash-chained action receipts vs total decisions (tenant stats).";

/**
 * Operational and product analytics — schema-driven panels backed by bounded
 * gateway aggregates (#1623) and honest unavailable states where REST metrics
 * are not yet exposed.
 */
export const analyticsDashboard: DashboardSchema = {
  uid: "analytics",
  title: "SOC Analytics",
  schemaVersion: 1,
  variables: [],
  time: { defaultRange: { from: "now-24h", to: "now" }, refreshSec: 30 },
  layout: [
    {
      id: "definitions",
      title: "Metric definitions (24h default window)",
      panels: [
        {
          panel: {
            id: "note-metric-definitions",
            type: "note",
            title: "How to read these panels",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: { body: METRIC_DEFINITIONS, variant: "info" },
          },
          w: 12,
          h: 2,
        },
      ],
    },
    {
      id: "vitals",
      title: "Authorization posture",
      panels: [
        {
          panel: {
            id: "stat-decisions-24h",
            type: "stat",
            title: "Decisions (24h)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "decisions_today" },
            drilldowns: [
              { label: "Explore decisions", target: { kind: "explore", aqlTemplate: "decision:*" } },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-denies-24h",
            type: "stat",
            title: "Denies (24h)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "denies_today", thresholds: [1, 5] },
            drilldowns: [
              { label: "Explore denials", target: { kind: "explore", aqlTemplate: "decision:deny" } },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-deny-rate",
            type: "stat",
            title: "Deny rate (24h)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "deny_rate_today", unit: "%", thresholds: [5, 15] },
            drilldowns: [
              { label: "Explore denials", target: { kind: "explore", aqlTemplate: "decision:deny" } },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-require-approval",
            type: "stat",
            title: "Require approval (all time)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: { valueField: "decisions_require_approval", thresholds: [1, 10] },
            drilldowns: [
              { label: "Open approvals", target: { kind: "dashboard", uid: "approvals" } },
              { label: "Explore approvals", target: { kind: "explore", aqlTemplate: "decision:require_approval" } },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "stat-pending-approvals",
            type: "stat",
            title: "Pending approvals",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "approvals_pending", thresholds: [1, 5] },
            drilldowns: [
              { label: "Approval queue", target: { kind: "dashboard", uid: "approvals" } },
            ],
          },
          w: 2,
          h: 1,
        },
        {
          panel: {
            id: "status-risk-posture",
            type: "status",
            title: "SOC risk posture (derived)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: {
              field: "risk_posture",
              healthyValues: ["healthy"],
              failedValues: ["critical", "degraded"],
            },
            drilldowns: [
              { label: "View incidents", target: { kind: "dashboard", uid: "incidents" } },
            ],
          },
          w: 2,
          h: 1,
        },
      ],
    },
    {
      id: "volume",
      title: "Decision volume trends",
      panels: [
        {
          panel: {
            id: "ts-all-decisions",
            type: "timeseries",
            title: "Authorization rate",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "decision",
            aggregate: "count_over_time",
            interval: "hour",
            drilldowns: [
              { label: "Explore window", target: { kind: "explore", aqlTemplate: "decision:*" } },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "ts-deny-decisions",
            type: "timeseries",
            title: "Denial rate",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            query: "decision:deny",
            aggregate: "count_over_time",
            interval: "hour",
            drilldowns: [
              { label: "Explore denials", target: { kind: "explore", aqlTemplate: "decision:deny" } },
            ],
          },
          w: 6,
          h: 3,
        },
      ],
    },
    {
      id: "trust",
      title: "Trust provenance mix (deterministic)",
      panels: [
        {
          panel: {
            id: "table-trust-mix",
            type: "table",
            title: "Trust level distribution",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "trust-breakdown",
            options: { columns: ["trust_level", "count"], maxRows: 8 },
            drilldowns: [
              { label: "Explore trust level", target: { kind: "explore", aqlTemplate: "source_trust:${trust_level}" } },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "table-decision-mix",
            type: "table",
            title: "Decision outcome mix",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            query: "decision:*",
            aggregate: "count_by",
            groupBy: "decision",
            limit: 6,
            options: { columns: ["decision", "count"], maxRows: 6 },
            drilldowns: [
              { label: "Explore outcome", target: { kind: "explore", aqlTemplate: "decision:${decision}" } },
            ],
          },
          w: 6,
          h: 3,
        },
      ],
    },
    {
      id: "risk",
      title: "Agent posture (advisory)",
      panels: [
        {
          panel: {
            id: "table-risky-agents",
            type: "table",
            title: "Top risky agents (advisory scoreboard)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "agent-scoreboard",
            options: {
              columns: ["agent_id", "current_avg_risk_score", "decision_count_24h", "trend"],
              maxRows: 8,
            },
            drilldowns: [
              { label: "Explore agent", target: { kind: "explore", aqlTemplate: "agent_id:${agent_id}" } },
              { label: "Agents fleet", target: { kind: "dashboard", uid: "agents" } },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "note-risk-advisory",
            type: "note",
            title: "Risk score disclaimer",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body:
                "Composite risk scores summarize recent decision context. Cedar policy and approval integrity remain the enforcement source of truth — never auto-allow from this table.",
              variant: "advisory",
            },
          },
          w: 6,
          h: 1,
        },
        {
          panel: {
            id: "table-denied-tools",
            type: "table",
            title: "Top denied tools",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            query: "decision:deny",
            aggregate: "count_by",
            groupBy: "tool",
            limit: 8,
            options: { columns: ["tool", "count"], maxRows: 8 },
            drilldowns: [
              { label: "Explore tool denials", target: { kind: "explore", aqlTemplate: "tool:${tool} decision:deny" } },
            ],
          },
          w: 6,
          h: 2,
        },
        {
          panel: {
            id: "table-denied-actions",
            type: "table",
            title: "Top denied actions",
            datasourceId: SOC_QUERY_DATASOURCE_ID,
            entity: "decision",
            query: "decision:deny",
            aggregate: "count_by",
            groupBy: "action",
            limit: 8,
            options: { columns: ["action", "count"], maxRows: 8 },
            drilldowns: [
              { label: "Explore action denials", target: { kind: "explore", aqlTemplate: "action:${action} decision:deny" } },
            ],
          },
          w: 6,
          h: 2,
        },
      ],
    },
    {
      id: "coverage",
      title: "Detection and receipt coverage",
      panels: [
        {
          panel: {
            id: "stat-total-receipts",
            type: "stat",
            title: "Hash-chained receipts",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: { valueField: "total_receipts" },
            drilldowns: [
              { label: "Receipt integrity", target: { kind: "dashboard", uid: "integrity" } },
              { label: "Receipts log", target: { kind: "dashboard", uid: "receipts" } },
            ],
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-total-decisions",
            type: "stat",
            title: "Total decisions",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "tenant-stats",
            options: { valueField: "total_decisions" },
            drilldowns: [
              { label: "Explore decisions", target: { kind: "explore", aqlTemplate: "decision:*" } },
            ],
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-open-incidents",
            type: "stat",
            title: "Open incidents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "incidents_open", thresholds: [1, 3] },
            drilldowns: [
              { label: "Incidents", target: { kind: "dashboard", uid: "incidents" } },
            ],
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "stat-active-alerts",
            type: "stat",
            title: "SOC alerts",
            datasourceId: DEFAULT_DATASOURCE_ID,
            snapshot: "soc-summary",
            options: { valueField: "alerts_total", thresholds: [1, 5] },
            drilldowns: [
              { label: "Detections", target: { kind: "dashboard", uid: "detections" } },
            ],
          },
          w: 3,
          h: 1,
        },
        {
          panel: {
            id: "table-detection-rules",
            type: "table",
            title: "Tenant detection rules",
            datasourceId: DEFAULT_DATASOURCE_ID,
            rulesCatalog: "detection",
            options: { columns: ["rule_key", "name", "severity", "enabled"], maxRows: 10 },
            drilldowns: [
              { label: "Rules editor", target: { kind: "dashboard", uid: "rules" } },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "table-soc-rules",
            type: "table",
            title: "SOC engine rules (catalog)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            rulesCatalog: "soc",
            options: { columns: ["rule_key", "name", "severity"], maxRows: 10 },
            drilldowns: [
              { label: "Rules editor", target: { kind: "dashboard", uid: "rules" } },
            ],
          },
          w: 6,
          h: 3,
        },
      ],
    },
    {
      id: "incidents",
      title: "Incident and event trends",
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
              { label: "Explore ASE", target: { kind: "explore", aqlTemplate: "event_type:*" } },
            ],
          },
          w: 6,
          h: 3,
        },
        {
          panel: {
            id: "table-recent-incidents",
            type: "table",
            title: "Recent incidents",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "incident",
            limit: 12,
            options: {
              columns: ["kind", "severity", "status", "agent_id", "opened_at"],
              maxRows: 12,
            },
            drilldowns: [
              { label: "Open incident", target: { kind: "incident", incidentIdField: "id" } },
              { label: "All incidents", target: { kind: "dashboard", uid: "incidents" } },
            ],
          },
          w: 6,
          h: 3,
        },
      ],
    },
    {
      id: "mcp",
      title: "MCP manifest posture",
      panels: [
        {
          panel: {
            id: "table-mcp-servers",
            type: "table",
            title: "Registered MCP servers",
            datasourceId: DEFAULT_DATASOURCE_ID,
            entity: "mcp_server",
            limit: 20,
            options: {
              columns: ["server_key", "name", "manifest_hash", "status"],
              maxRows: 20,
            },
            drilldowns: [
              { label: "MCP fleet", target: { kind: "dashboard", uid: "mcp" } },
            ],
          },
          w: 8,
          h: 3,
        },
        {
          panel: {
            id: "note-mcp-drift",
            type: "note",
            title: "MCP drift trend",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body:
                "Per-server manifest history is available on the MCP fleet tab. A bounded cross-tenant drift timeseries API is not exposed on REST yet — inspect manifest_hash changes per server instead of client-side aggregation.",
              variant: "unavailable",
            },
          },
          w: 4,
          h: 3,
        },
      ],
    },
    {
      id: "latency",
      title: "Response-time metrics (REST gaps)",
      panels: [
        {
          panel: {
            id: "note-mttd",
            type: "note",
            title: "MTTD (mean time to detect)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body:
                "MTTD is exported on GET /metrics as aegis_soc_mttd_seconds (Prometheus). A tenant-scoped REST aggregate for the analytics UI is not available yet — use metrics scrapers or add a bounded /v1/soc/metrics endpoint.",
              variant: "unavailable",
            },
          },
          w: 4,
          h: 2,
        },
        {
          panel: {
            id: "note-mttc",
            type: "note",
            title: "MTTC (mean time to contain)",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body:
                "MTTC is exported on GET /metrics as aegis_soc_mttr_seconds when incidents close. REST-downsampled containment latency for dashboards is pending — incident opened/closed timestamps are available via Explore and the incidents dashboard.",
              variant: "unavailable",
            },
          },
          w: 4,
          h: 2,
        },
        {
          panel: {
            id: "note-approval-latency",
            type: "note",
            title: "Approval latency",
            datasourceId: DEFAULT_DATASOURCE_ID,
            options: {
              body:
                "Human approval response time needs a bounded aggregate over approvals (created → approved). List endpoints exist but unbounded client aggregation is intentionally avoided — awaiting a gateway timing summary endpoint.",
              variant: "unavailable",
            },
          },
          w: 4,
          h: 2,
        },
      ],
    },
  ],
};