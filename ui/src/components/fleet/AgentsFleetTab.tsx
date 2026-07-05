"use client";

import React, { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search, Users, Server, ChevronRight } from "lucide-react";
import { useAppStore } from "@/app/store";
import { getAgents, getAgentScoreboard, getMcpServers } from "@/app/api";
import { errorMessage } from "@/lib/format";
import StatusBadge from "@/components/security/StatusBadge";
import AgentDetailPage from "./AgentDetailPage";
import { mergeFleetRows, type FleetRow } from "./agentFleetData";

export default function AgentsFleetTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch, activeAgentId, setActiveAgentId } =
    useAppStore();
  const apiOpts = useMemo(
    () => ({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );

  const [search, setSearch] = useState("");

  const { data: agents = [], isLoading, error } = useQuery({
    queryKey: ["agents", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getAgents(apiOpts),
    refetchInterval: 5000,
  });

  const { data: scoreboard = [] } = useQuery({
    queryKey: ["agentScoreboard", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getAgentScoreboard(apiOpts),
    refetchInterval: 10000,
  });

  const { data: mcpServers = [] } = useQuery({
    queryKey: ["mcpServers", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getMcpServers(apiOpts),
    refetchInterval: 10000,
  });

  const fleetRows = useMemo(() => mergeFleetRows(agents, scoreboard), [agents, scoreboard]);

  const filteredRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return fleetRows;
    return fleetRows.filter((row) =>
      [row.agent_key, row.name, row.owner, row.environment, row.frameworkModel, row.status]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [fleetRows, search]);

  if (activeAgentId) {
    return (
      <AgentDetailPage
        agentId={activeAgentId}
        onBack={() => setActiveAgentId(null)}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-[var(--text-primary)]">
          <Users size={16} className="text-[var(--brand)]" />
          Agents Fleet
        </h2>
        <p className="text-[11px] text-[var(--text-muted)]">
          Digital workforce inventory with advisory risk trends and routeable per-agent investigation.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <VitalCard label="Registered agents" value={String(agents.length)} />
        <VitalCard label="MCP servers" value={String(mcpServers.length)} icon={<Server size={14} />} />
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={16} />
        <input
          type="text"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search agents by key, owner, environment, status..."
          className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-panel)] py-2 pl-10 pr-4 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none"
        />
      </div>

      <div className="panel-card overflow-auto">
        <table className="w-full min-w-[980px] text-left text-xs">
          <thead>
            <tr className="border-b border-[var(--border-default)] text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
              <th className="py-2">Agent</th>
              <th className="py-2">Owner</th>
              <th className="py-2">Environment</th>
              <th className="py-2">Framework / model</th>
              <th className="py-2">Risk tier</th>
              <th className="py-2">Status</th>
              <th className="py-2">Advisory risk (24h)</th>
              <th className="py-2">Trend</th>
              <th className="py-2">Last seen</th>
              <th className="py-2 text-right">Detail</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={10} className="py-10 text-center text-[var(--text-muted)]">
                  Loading fleet inventory...
                </td>
              </tr>
            ) : error ? (
              <tr>
                <td colSpan={10} className="py-10 text-center text-red-400">
                  Failed to load agents: {errorMessage(error)}
                </td>
              </tr>
            ) : filteredRows.length === 0 ? (
              <tr>
                <td colSpan={10} className="py-10 text-center text-[var(--text-muted)]">
                  No agents matched the current filter.
                </td>
              </tr>
            ) : (
              filteredRows.map((row) => (
                <FleetRowItem key={row.id} row={row} onOpen={() => setActiveAgentId(row.id)} />
              ))
            )}
          </tbody>
        </table>
        <p className="mt-3 text-[10px] text-[var(--text-muted)]">
          Connected tools/MCP bindings and incident/approval counts are shown on the agent detail page.
          Risk score and trend are advisory only — Cedar authorization remains authoritative.
        </p>
      </div>
    </div>
  );
}

function VitalCard({
  label,
  value,
  icon,
}: {
  label: string;
  value: string;
  icon?: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-panel)] px-4 py-3">
      <span className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
        {icon}
        {label}
      </span>
      <span className="mt-1 block font-mono text-lg font-bold text-[var(--text-primary)]">{value}</span>
    </div>
  );
}

function FleetRowItem({ row, onOpen }: { row: FleetRow; onOpen: () => void }) {
  return (
    <tr
      className="cursor-pointer border-b border-[var(--border-default)] hover:bg-[var(--surface-elevated)]"
      onClick={onOpen}
    >
      <td className="py-2">
        <div className="font-mono text-[11px] font-bold text-[var(--brand)]">{row.agent_key}</div>
        <div className="text-[10px] text-[var(--text-secondary)]">{row.name}</div>
      </td>
      <td className="py-2 text-[var(--text-secondary)]">{row.owner}</td>
      <td className="py-2 font-mono text-[var(--text-secondary)]">{row.environment}</td>
      <td className="py-2 text-[var(--text-secondary)]">{row.frameworkModel}</td>
      <td className="py-2 font-semibold text-[var(--sev-high)]">{row.risk_tier}</td>
      <td className="py-2">
        <StatusBadge status={row.status} size="sm" />
      </td>
      <td className="py-2 font-mono text-[var(--text-primary)]">
        {row.advisoryRiskScore}
        <span className="ml-1 text-[9px] uppercase text-[var(--text-muted)]">advisory</span>
      </td>
      <td className="py-2 text-[var(--text-secondary)]">{row.advisoryTrend}</td>
      <td className="py-2 text-[var(--text-secondary)]">{row.lastSeen}</td>
      <td className="py-2 text-right text-[var(--brand)]">
        <ChevronRight size={14} className="inline" />
      </td>
    </tr>
  );
}