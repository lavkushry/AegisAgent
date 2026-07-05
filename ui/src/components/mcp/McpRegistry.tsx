"use client";

import React from "react";
import { Server } from "lucide-react";
import type { McpServerRecord } from "@/app/api";
import HashText from "@/components/primitives/HashText";
import StatusBadge from "@/components/security/StatusBadge";
import { integrityStatusLabel, resolveMcpIntegrityStatus } from "./driftState";
import { integrityBadgeClass } from "./integrityStyles";

export type McpRegistryEntry = McpServerRecord & {
  toolCount?: number;
  integrity: ReturnType<typeof resolveMcpIntegrityStatus>;
};

type McpRegistryProps = {
  servers: McpRegistryEntry[];
  selectedServerKey: string | null;
  onSelect: (serverKey: string) => void;
  isLoading: boolean;
  error: string | null;
};

export default function McpRegistry({
  servers,
  selectedServerKey,
  onSelect,
  isLoading,
  error,
}: McpRegistryProps) {
  return (
    <div className="panel-card space-y-4 lg:col-span-1">
      <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
        <Server size={14} className="text-[var(--brand)]" /> MCP Servers Registry
      </h3>

      {isLoading ? (
        <p className="py-8 text-center text-xs text-[var(--text-muted)]">Loading MCP servers...</p>
      ) : error ? (
        <p className="py-8 text-center text-xs text-red-400">Error: {error}</p>
      ) : servers.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center text-[var(--text-muted)]">
          <Server size={36} className="mb-4" />
          <h4 className="text-xs font-semibold">No Registered Servers</h4>
          <p className="mt-1 max-w-xs text-[10px]">
            MCP servers appear here once registered with the gateway daemon.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {servers.map((srv) => (
            <div
              key={srv.server_key}
              role="button"
              tabIndex={0}
              aria-label={`Select MCP server ${srv.server_key}`}
              onClick={() => onSelect(srv.server_key)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(srv.server_key);
                }
              }}
              className={`cursor-pointer rounded-lg border p-3 text-xs transition-colors ${
                selectedServerKey === srv.server_key
                  ? "border-[var(--border-active)] bg-[var(--brand)]/10"
                  : "border-[var(--border-default)] bg-[var(--surface-app)]/40 hover:border-[var(--border-default)]"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <span className="max-w-[140px] truncate font-mono text-xs font-bold text-[var(--brand)]">
                  {srv.server_key}
                </span>
                <StatusBadge status={srv.status || "unknown"} size="sm" />
              </div>
              <p className="mt-1 line-clamp-1 text-[11px] text-[var(--text-secondary)]">{srv.name || srv.server_key}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <span
                  className={`rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase ${integrityBadgeClass(srv.integrity)}`}
                >
                  {integrityStatusLabel(srv.integrity)}
                </span>
                <span className="font-mono text-[10px] text-[var(--text-muted)]">
                  {srv.transport || "stdio"} · trust {srv.trust_level || "unknown"}
                </span>
              </div>
              <div className="mt-2 space-y-1 font-mono text-[10px] text-[var(--text-secondary)]">
                <div className="flex flex-wrap items-center gap-1">
                  <span className="text-[var(--text-muted)]">Pinned:</span>
                  <HashText value={srv.manifest_hash} head={10} tail={6} />
                </div>
                <span>
                  Tools: {srv.toolCount ?? "—"} · Last discovery:{" "}
                  {srv.last_discovery_at ? new Date(srv.last_discovery_at).toLocaleString() : "—"}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}