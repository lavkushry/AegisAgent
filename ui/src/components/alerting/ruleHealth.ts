import type { AlertRecord } from "@/app/api";
import type { CatalogRule } from "@/components/rules/useRulesCatalog";

export type RuleHealthStatus = "firing" | "normal" | "error" | "stale" | "unsupported";

export interface RuleHealthRow {
  rule_key: string;
  name: string;
  severity: string;
  source: string;
  enabled: boolean;
  status: RuleHealthStatus;
  alertCount24h: number;
  lastAlertAt?: string;
  throughputLabel: string;
}

const STALE_MS = 24 * 60 * 60 * 1000;

function alertMatchesRule(alert: AlertRecord, rule: CatalogRule): boolean {
  const needle = alert.rule?.toLowerCase() ?? "";
  return (
    needle === rule.rule_key.toLowerCase() ||
    needle === rule.name.toLowerCase() ||
    needle.includes(rule.rule_key.toLowerCase())
  );
}

function parseTime(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}

export function buildRuleHealthRows(
  rules: ReadonlyArray<CatalogRule>,
  alerts: ReadonlyArray<AlertRecord>,
  nowMs = Date.now(),
): RuleHealthRow[] {
  const recentAlerts = alerts.filter((alert) => {
    const ts = parseTime(alert.occurred_at ?? alert.created_at);
    return ts !== undefined && nowMs - ts <= STALE_MS;
  });

  return rules.map((rule) => {
    const matched = recentAlerts.filter((alert) => alertMatchesRule(alert, rule));
    const lastAlertAt = matched
      .map((alert) => alert.occurred_at ?? alert.created_at)
      .sort()
      .at(-1);

    let status: RuleHealthStatus;
    if (!rule.enabled) {
      status = "error";
    } else if (matched.length > 0) {
      status = "firing";
    } else if (rule.source === "default") {
      status = "unsupported";
    } else {
      status = "normal";
    }

    return {
      rule_key: rule.rule_key,
      name: rule.name,
      severity: rule.severity,
      source: rule.source,
      enabled: rule.enabled,
      status,
      alertCount24h: matched.length,
      lastAlertAt,
      throughputLabel:
        matched.length > 0
          ? `${matched.length} alert${matched.length === 1 ? "" : "s"} / 24h`
          : rule.source === "default"
            ? "Throughput metrics unavailable"
            : "0 alerts / 24h",
    };
  });
}

export function ruleHealthLabel(status: RuleHealthStatus): string {
  switch (status) {
    case "firing":
      return "Firing";
    case "normal":
      return "Normal";
    case "error":
      return "Error";
    case "stale":
      return "Stale";
    default:
      return "Unsupported";
  }
}