import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  filterAlerts,
  listAlerts,
  severityColorVar,
} from "@/domains/detections";
import { errorMessage, formatTime } from "@/lib/format";

export function DetectionsPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };

  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["alerts", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listAlerts(apiOpts, 100),
    enabled: tenantReady,
    refetchInterval: 10_000,
    retry: false,
  });

  const rows = useMemo(
    () => filterAlerts(data ?? [], query, severity),
    [data, query, severity],
  );

  if (!tenantReady) return <TenantGate title="Select a tenant for Detections" />;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Detections
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Triggered alerts from deterministic rules
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      <div className="panel-card flex flex-col gap-2 sm:flex-row">
        <input
          className="input-field flex-1"
          placeholder="Filter summary, rule, agent…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter detections"
        />
        <select
          className="input-field sm:w-40"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          aria-label="Severity filter"
        >
          <option value="">All severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="info">info</option>
        </select>
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading alerts…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      <div className="overflow-hidden rounded-[var(--radius-panel)] border border-[var(--border-default)]">
        <table className="w-full border-collapse text-left text-[11px]">
          <thead className="bg-[var(--surface-elevated)] text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            <tr>
              <th className="px-3 py-2 font-medium">When</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">Rule</th>
              <th className="px-3 py-2 font-medium">Summary</th>
              <th className="px-3 py-2 font-medium">Agent</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr
                key={a.id || a.alert_id}
                className="border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
              >
                <td className="px-3 py-2 whitespace-nowrap text-[var(--text-secondary)]">
                  {formatTime(a.occurred_at ?? a.created_at) || "—"}
                </td>
                <td className="px-3 py-2">
                  <span
                    className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(severityColorVar(a.severity))}
                  >
                    {a.severity || "info"}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                  {a.rule || "—"}
                </td>
                <td className="px-3 py-2 text-[var(--text-primary)]">
                  {a.summary || "—"}
                </td>
                <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                  {a.agent_id || "—"}
                </td>
              </tr>
            ))}
            {!isLoading && rows.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="px-3 py-6 text-center text-[var(--text-muted)]"
                >
                  No detections matched.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
