"use client";

import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { GatewayEntityDatasource } from "@/datasources/gatewayEntity";
import { alertRowsFromFrame } from "@/datasources/entityData";
import { errorMessage } from "@/lib/format";
import {
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  AlertCircle,
} from "lucide-react";
import JsonViewer from "@/components/primitives/JsonViewer";
import { filterAlerts } from "./alertFilters";
import { getSeverityStyle } from "./severityStyles";

const DEFAULT_TIME_RANGE = { from: "now-24h", to: "now" } as const;

export default function DetectionsPage() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const entityDatasource = useMemo(
    () => new GatewayEntityDatasource({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );

  const [alertSearch, setAlertSearch] = useState("");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("all");
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  const { data: alertsFrame, isLoading: loadingAlerts, error: alertsError } = useQuery({
    queryKey: ["alerts", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        entity: "alert",
        limit: 100,
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
    refetchInterval: 5000,
  });

  const alerts = alertRowsFromFrame(alertsFrame);
  const filteredAlerts = useMemo(
    () => filterAlerts(alerts ?? [], alertSearch, alertSeverityFilter),
    [alerts, alertSearch, alertSeverityFilter],
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-[var(--text-primary)]">
          <ShieldAlert size={16} className="text-[var(--brand)]" />
          Active Detections
        </h2>
        <p className="text-[11px] text-[var(--text-muted)]">
          Live SOC alerts fired by deterministic detection rules. Expand a row to inspect the redacted alert record.
        </p>
      </div>

      <div className="flex flex-col gap-3 rounded-lg border border-[var(--border-default)] bg-[var(--surface-panel)] p-3 md:flex-row md:items-center">
        <div className="relative w-full flex-1">
          <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={16} />
          <input
            type="text"
            value={alertSearch}
            onChange={(e) => setAlertSearch(e.target.value)}
            placeholder="Search alerts by rule, agent ID, summary..."
            className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] py-2 pl-10 pr-4 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none"
          />
        </div>
        <div className="flex w-full items-center gap-2 md:w-auto">
          <Filter className="shrink-0 text-[var(--text-muted)]" size={14} />
          <select
            value={alertSeverityFilter}
            onChange={(e) => setAlertSeverityFilter(e.target.value)}
            className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none md:w-40"
          >
            <option value="all">All Severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      <div className="panel-card space-y-3">
        <h3 className="mb-2 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          Triggered Detections Log
          {alerts && alerts.length > 0 && (
            <span className="ml-2 rounded-full bg-red-500 px-1.5 py-0.5 text-[9px] font-bold text-white">
              {alerts.length}
            </span>
          )}
        </h3>

        {loadingAlerts ? (
          <p className="py-10 text-center text-xs text-[var(--text-muted)]">Fetching active alerts...</p>
        ) : alertsError ? (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-950/20 p-4 text-xs text-red-400">
            <AlertCircle size={16} />
            <span>Error fetching alerts: {errorMessage(alertsError)}</span>
          </div>
        ) : filteredAlerts.length === 0 ? (
          <p className="py-12 text-center text-xs text-[var(--text-muted)]">
            No active alerts matched the filter conditions.
          </p>
        ) : (
          <div className="space-y-2">
            {filteredAlerts.map((alert) => {
              const isExpanded = expandedAlertId === alert.alert_id;
              const severityStyle = getSeverityStyle(alert.severity);

              return (
                <div
                  key={alert.alert_id}
                  className={`overflow-hidden rounded-lg border border-[var(--border-default)] transition-all ${severityStyle.card}`}
                >
                  <div
                    onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}
                    className="flex cursor-pointer select-none flex-wrap items-center justify-between gap-4 p-4 md:flex-nowrap"
                  >
                    <div className="flex items-center gap-3">
                      <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${severityStyle.badge}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <div className="flex flex-col">
                        <span className="font-mono text-xs font-bold text-[var(--brand)]">{alert.rule}</span>
                        <span className="mt-0.5 font-mono text-[10px] text-[var(--text-muted)]">
                          Agent: {alert.agent_id} &middot; Occurred:{" "}
                          {new Date(alert.occurred_at).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 text-xs font-medium text-[var(--text-primary)]">
                      <span className="max-w-[280px] truncate italic text-[var(--text-secondary)] md:max-w-md">
                        {alert.summary}
                      </span>
                      {isExpanded ? (
                        <ChevronUp size={16} className="text-[var(--text-muted)]" />
                      ) : (
                        <ChevronDown size={16} className="text-[var(--text-muted)]" />
                      )}
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="space-y-3 border-t border-[var(--border-default)] bg-[var(--surface-app)] p-4 font-mono text-xs">
                      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                        <div>
                          <span className="block font-sans text-[10px] font-bold uppercase text-[var(--text-muted)]">
                            Alert ID
                          </span>
                          <span className="select-all text-[var(--text-primary)]">{alert.alert_id}</span>
                        </div>
                        <div>
                          <span className="block font-sans text-[10px] font-bold uppercase text-[var(--text-muted)]">
                            Source Event ID
                          </span>
                          <span className="select-all text-[var(--text-primary)]">
                            {alert.source_event_id ?? "—"}
                          </span>
                        </div>
                      </div>
                      <div>
                        <span className="mb-1 block font-sans text-[10px] font-bold uppercase text-[var(--text-muted)]">
                          Full Summary
                        </span>
                        <p className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2.5 font-sans leading-relaxed text-[var(--text-primary)]">
                          {alert.summary}
                        </p>
                      </div>
                      <div>
                        <span className="mb-1 block font-sans text-[10px] font-bold uppercase text-[var(--text-muted)]">
                          Redacted Alert Record
                        </span>
                        <JsonViewer value={alert} />
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}