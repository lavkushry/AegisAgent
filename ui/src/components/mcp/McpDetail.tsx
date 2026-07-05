"use client";

import React from "react";
import {
  History,
  Clock,
  Lock,
  Unlock,
  Wrench,
  AlertTriangle,
  ExternalLink,
} from "lucide-react";
import type { AlertRecord, IncidentRecord, McpServerRecord, McpToolRecord } from "@/app/api";
import HashText from "@/components/primitives/HashText";
import StatusBadge from "@/components/security/StatusBadge";
import { getSeverityStyle } from "@/components/detections/severityStyles";
import { buildManifestTimeline } from "./manifestHistory";
import type { McpManifestSnapshot } from "@/app/api";
import { integrityStatusLabel, resolveMcpIntegrityStatus } from "./driftState";
import { integrityBadgeClass } from "./integrityStyles";
import type { McpControlKind } from "./mcpControls";

type McpDetailProps = {
  server: McpServerRecord;
  tools: McpToolRecord[];
  history: McpManifestSnapshot[];
  linkedAlerts: AlertRecord[];
  linkedIncidents: IncidentRecord[];
  isToolsLoading: boolean;
  isHistoryLoading: boolean;
  roleDisabledReason: string | null;
  onQuarantine: () => void;
  onRestore: () => void;
  onViewDetections: () => void;
  onViewIncidents: () => void;
  mutationsPending: boolean;
};

export default function McpDetail({
  server,
  tools,
  history,
  linkedAlerts,
  linkedIncidents,
  isToolsLoading,
  isHistoryLoading,
  roleDisabledReason,
  onQuarantine,
  onRestore,
  onViewDetections,
  onViewIncidents,
  mutationsPending,
}: McpDetailProps) {
  const integrity = resolveMcpIntegrityStatus(server, history);
  const timeline = buildManifestTimeline(history);
  const isQuarantined = String(server.status).toLowerCase() === "quarantined";
  const controlKind: McpControlKind = isQuarantined ? "restore" : "quarantine";

  return (
    <div className="panel-card space-y-5 lg:col-span-2">
      <div className="flex flex-col gap-3 border-b border-[var(--border-default)] pb-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <History size={14} className="text-[var(--brand)]" /> Server Detail ·{" "}
            <code className="font-bold text-[var(--brand)]">{server.server_key}</code>
          </h3>
          <p className="mt-1 text-[11px] text-[var(--text-muted)]">{server.name}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`rounded border px-2 py-0.5 text-[9px] font-bold uppercase ${integrityBadgeClass(integrity)}`}
          >
            {integrityStatusLabel(integrity)}
          </span>
          <StatusBadge status={server.status} size="sm" />
          <button
            type="button"
            disabled={Boolean(roleDisabledReason) || mutationsPending}
            title={roleDisabledReason ?? undefined}
            onClick={controlKind === "restore" ? onRestore : onQuarantine}
            className={`inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] font-semibold disabled:cursor-not-allowed disabled:opacity-50 ${
              controlKind === "restore"
                ? "border-green-500/30 bg-green-950/20 text-green-400"
                : "border-rose-500/30 bg-rose-950/20 text-rose-400"
            }`}
          >
            {controlKind === "restore" ? (
              <>
                <Unlock size={12} /> Restore
              </>
            ) : (
              <>
                <Lock size={12} /> Quarantine
              </>
            )}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-2">
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Transport</span>
          <p className="mt-1 font-mono text-[var(--text-primary)]">{server.transport || "stdio"}</p>
        </div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">Trust level</span>
          <p className="mt-1 font-mono text-[var(--text-primary)]">{server.trust_level || "unknown"}</p>
        </div>
        <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3 md:col-span-2">
          <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
            Pinned manifest hash
          </span>
          <p className="mt-1">
            <HashText value={server.manifest_hash} />
          </p>
        </div>
        {timeline[0]?.manifest_hash && timeline[0].manifest_hash !== server.manifest_hash ? (
          <div className="rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 md:col-span-2">
            <span className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider text-amber-300">
              <AlertTriangle size={12} /> Observed hash (latest snapshot)
            </span>
            <p className="mt-1">
              <HashText value={timeline[0].manifest_hash} />
            </p>
          </div>
        ) : null}
      </div>

      <section className="space-y-2">
        <h4 className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Wrench size={12} className="text-[var(--brand)]" /> Tools ({tools.length})
        </h4>
        {isToolsLoading ? (
          <p className="text-xs text-[var(--text-muted)]">Loading tools...</p>
        ) : tools.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">No tools discovered for this server.</p>
        ) : (
          <div className="max-h-48 space-y-2 overflow-y-auto custom-scrollbar">
            {tools.map((tool) => (
              <div
                key={tool.tool_key}
                className="flex items-center justify-between gap-2 rounded border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-2 text-[11px]"
              >
                <div className="min-w-0">
                  <span className="block font-mono font-bold text-[var(--brand)]">{tool.tool_key}</span>
                  <span className="text-[var(--text-muted)]">{tool.name || tool.tool_key}</span>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span
                    className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${
                      getSeverityStyle(tool.risk ?? "info").badge
                    }`}
                  >
                    {tool.risk || "info"}
                  </span>
                  <StatusBadge status={tool.status || "pending"} size="sm" />
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-2">
        <h4 className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <History size={12} className="text-[var(--brand)]" /> Manifest drift timeline
        </h4>
        {isHistoryLoading ? (
          <p className="text-xs text-[var(--text-muted)]">Loading manifest history...</p>
        ) : timeline.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">No manifest snapshots recorded.</p>
        ) : (
          <div className="max-h-56 space-y-2 overflow-y-auto custom-scrollbar">
            {timeline.map((entry, idx) => (
              <div
                key={`${entry.manifest_hash}-${entry.created_at}-${idx}`}
                className="flex items-start justify-between gap-4 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/40 p-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded px-1.5 py-0.5 text-[8px] font-extrabold uppercase ${
                        entry.event_type === "drift"
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-green-500/20 text-green-400"
                      }`}
                    >
                      {entry.event_type}
                    </span>
                    <HashText value={entry.manifest_hash} head={10} tail={6} />
                  </div>
                  <p className="text-[11px] text-[var(--text-secondary)]">{entry.description}</p>
                </div>
                <span className="flex shrink-0 items-center gap-1 whitespace-nowrap font-mono text-[10px] text-[var(--text-muted)]">
                  <Clock size={10} />
                  {entry.created_at ? new Date(entry.created_at).toLocaleString() : "—"}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-2">
        <h4 className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          Linked SOC evidence
        </h4>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[var(--text-primary)]">Detections</span>
              <button
                type="button"
                onClick={onViewDetections}
                className="inline-flex items-center gap-1 text-[10px] font-bold text-[var(--brand)]"
              >
                View <ExternalLink size={10} />
              </button>
            </div>
            <p className="mt-1 text-[var(--text-muted)]">
              {linkedAlerts.length} MCP-related alert{linkedAlerts.length === 1 ? "" : "s"} in the last 24h
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[var(--text-primary)]">Incidents</span>
              <button
                type="button"
                onClick={onViewIncidents}
                className="inline-flex items-center gap-1 text-[10px] font-bold text-[var(--brand)]"
              >
                View <ExternalLink size={10} />
              </button>
            </div>
            <p className="mt-1 text-[var(--text-muted)]">
              {linkedIncidents.length} linked incident{linkedIncidents.length === 1 ? "" : "s"}
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}