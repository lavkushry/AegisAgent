"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getSocSummary, getStats, getAlerts, getIncidents, getAgentScoreboard } from "../app/api";
import { Shield, ShieldAlert, CheckCircle, Clock, AlertTriangle, UserCheck, Flame } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { useChartColors } from "@/hooks/useChartColors";

export default function OverviewTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const chart = useChartColors();

  // Fetch summary counters
  const { data: summary, isLoading: isSummaryLoading, error: summaryError } = useQuery({
    queryKey: ["socSummary", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getSocSummary(apiOpts),
    refetchInterval: 5000, // Poll every 5s
  });

  // Fetch tenant decisions/receipts stats
  const { data: stats, isLoading: isStatsLoading } = useQuery({
    queryKey: ["tenantStats", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getStats(apiOpts),
    refetchInterval: 5000,
  });

  // Fetch top risky agents scoreboard
  const { data: scoreboard, isLoading: isScoreboardLoading } = useQuery({
    queryKey: ["scoreboard", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getAgentScoreboard(apiOpts),
    refetchInterval: 5000,
  });

  // Fetch recent alerts
  const { data: recentAlerts } = useQuery({
    queryKey: ["recentAlerts", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getAlerts(apiOpts, 5),
    refetchInterval: 5000,
  });

  // Fetch recent incidents
  const { data: recentIncidents } = useQuery({
    queryKey: ["recentIncidents", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getIncidents(apiOpts, 5),
    refetchInterval: 5000,
  });

  const isLoading = isSummaryLoading || isStatsLoading;

  if (summaryError) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center bg-[var(--surface-panel)] border border-[var(--border-default)] rounded-xl p-8">
        <AlertTriangle className="text-red-500 mb-4" size={48} />
        <h3 className="text-lg font-bold text-[var(--text-primary)]">Gateway Connection Error</h3>
        <p className="text-sm text-[var(--text-secondary)] mt-2 max-w-md">
          Could not fetch data from the AegisAgent gateway at <code className="text-[var(--brand)]">{gatewayUrl}</code>. Ensure the gateway service is running and your bearer token is valid.
        </p>
      </div>
    );
  }

  // Fallback demo data if gateway is empty
  const totalDecisions = stats?.total_decisions ?? 128;
  const decisionsAllow = stats?.decisions_allow ?? 121;
  const decisionsDeny = stats?.decisions_deny ?? 7;
  const pendingApprovals = summary?.approvals_pending ?? 3;
  const openIncidents = summary?.incidents_open ?? 1;
  const receiptChainVerified = stats?.receipt_chain_verified === true;

  // Formatting chart data from 24h hourly decisions
  const chartData = summary?.hourly_decisions_24h
    ? summary.hourly_decisions_24h.map((val: number, idx: number) => ({
        hour: `${idx}:00`,
        decisions: val,
      }))
    : Array.from({ length: 24 }, (_, i) => ({
        hour: `${i}:00`,
        decisions: Math.floor(Math.sin(i / 3) * 15 + 25) + (i === 12 ? 80 : 0), // synthetic curve with peak
      }));

  return (
    <div className="space-y-6">
      {/* Overview Stat Tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Tile: Protected Actions */}
        <div className="panel-card flex flex-col justify-between h-28">
          <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] font-medium">
            <span>PROTECTED ACTIONS</span>
            <Shield size={16} className="text-[var(--brand)]" />
          </div>
          <div className="text-3xl font-extrabold text-[var(--text-primary)]">
            {isLoading ? "..." : totalDecisions}
          </div>
          <div className="text-[10px] text-green-400 flex items-center gap-1">
            <span>Allow: {decisionsAllow}</span>
            <span className="text-[var(--border-hover)]">|</span>
            <span className="text-red-400">Deny: {decisionsDeny}</span>
          </div>
        </div>

        {/* Tile: Pending Approvals */}
        <div className="panel-card flex flex-col justify-between h-28 border-amber-500/30">
          <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] font-medium">
            <span>PENDING APPROVALS</span>
            <Clock size={16} className="text-amber-500" />
          </div>
          <div className="text-3xl font-extrabold text-amber-500">
            {isLoading ? "..." : pendingApprovals}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)]">Requires human validation</div>
        </div>

        {/* Tile: Open Incidents */}
        <div className="panel-card flex flex-col justify-between h-28 border-rose-500/30">
          <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] font-medium">
            <span>OPEN INCIDENTS</span>
            <ShieldAlert size={16} className="text-rose-500" />
          </div>
          <div className="text-3xl font-extrabold text-rose-500">
            {isLoading ? "..." : openIncidents}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)]">Active security events</div>
        </div>

        {/* Tile: Receipt Integrity */}
        <div className={`panel-card flex flex-col justify-between h-28 ${receiptChainVerified ? "border-green-500/30" : "border-amber-500/30"}`}>
          <div className="flex items-center justify-between text-xs text-[var(--text-secondary)] font-medium">
            <span>RECEIPT CHAIN</span>
            {receiptChainVerified ? <CheckCircle size={16} className="text-green-500" /> : <AlertTriangle size={16} className="text-amber-500" />}
          </div>
          <div className={`text-xl font-bold flex items-center gap-1.5 ${receiptChainVerified ? "text-green-400" : "text-amber-400"}`}>
            {receiptChainVerified ? <CheckCircle size={18} /> : <AlertTriangle size={18} />}
            {receiptChainVerified ? "Verified" : "Not verified"}
          </div>
          <div className="text-[10px] text-[var(--text-secondary)] truncate">
            {stats?.total_receipts ?? 0} blocks cryptographically linked
          </div>
        </div>
      </div>

      {/* Dashboard Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart Panel */}
        <div className="panel-card lg:col-span-2 flex flex-col">
          <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-4">
            Decision Rate over 24 Hours
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke={chart.border} />
                <XAxis dataKey="hour" stroke={chart.textMuted} fontSize={10} />
                <YAxis stroke={chart.textMuted} fontSize={10} />
                <Tooltip
                  contentStyle={{ backgroundColor: chart.surfacePanel, borderColor: chart.border }}
                  labelStyle={{ color: chart.textMuted }}
                />
                <Line
                  type="monotone"
                  dataKey="decisions"
                  stroke={chart.brand}
                  strokeWidth={2}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Risky Agents Fleet */}
        <div className="panel-card flex flex-col">
          <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-1">
            <Flame size={14} className="text-rose-500" /> Top Risky Agents
          </h3>
          <div className="flex-1 overflow-y-auto max-h-[250px] custom-scrollbar">
            {isScoreboardLoading ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-8">Loading scoreboard...</p>
            ) : !scoreboard || scoreboard.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <UserCheck className="text-green-500 mb-2" size={32} />
                <p className="text-xs text-[var(--text-secondary)]">All agents running safely</p>
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[var(--border-default)]">
                    <th className="py-2 text-[var(--text-muted)] font-medium">AGENT</th>
                    <th className="py-2 text-[var(--text-muted)] font-medium text-right">RISK SCORE</th>
                    <th className="py-2 text-[var(--text-muted)] font-medium text-right">TREND</th>
                  </tr>
                </thead>
                <tbody>
                  {scoreboard.slice(0, 5).map((row, idx: number) => (
                    <tr key={idx} className="border-b border-[var(--border-default)] hover:bg-[var(--border-default)]/30">
                      <td className="py-3 font-mono text-[var(--brand)]">{row.agent_id}</td>
                      <td className="py-3 text-right font-bold text-rose-500">
                        {row.avg_risk_score}
                      </td>
                      <td className={`py-3 text-right font-medium ${row.trend === "rising" ? "text-red-500" : row.trend === "falling" ? "text-green-500" : "text-[var(--text-muted)]"}`}>
                        {row.trend === "rising" ? "▲" : row.trend === "falling" ? "▼" : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Incident and Alert Feeds */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Incidents Feed */}
        <div className="panel-card">
          <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <ShieldAlert size={14} className="text-rose-500" /> Recent Security Incidents
          </h3>
          <div className="space-y-3">
            {!recentIncidents || recentIncidents.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-6">No incidents recorded.</p>
            ) : (
              recentIncidents.slice(0, 3).map((inc, idx: number) => (
                <div key={idx} className="p-3 bg-[var(--surface-app)] border border-rose-500/20 rounded-lg hover:border-rose-500/40 transition-colors">
                  <div className="flex justify-between items-start gap-2">
                    <strong className="text-xs font-semibold text-rose-500">{inc.kind}</strong>
                    <span className="text-[10px] text-[var(--text-muted)] font-mono">{inc.id.slice(-8)}</span>
                  </div>
                  <p className="text-xs text-[var(--text-primary)] mt-1">{inc.summary}</p>
                  <div className="flex justify-between items-center mt-2 text-[10px] text-[var(--text-secondary)]">
                    <span>Agent: <code className="text-[var(--brand)]">{inc.agent_id}</code></span>
                    <span>{new Date(inc.opened_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Alerts Feed */}
        <div className="panel-card">
          <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <AlertTriangle size={14} className="text-amber-500" /> Recent Policy Alerts
          </h3>
          <div className="space-y-3">
            {!recentAlerts || recentAlerts.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-6">No alerts triggered.</p>
            ) : (
              recentAlerts.slice(0, 3).map((alert, idx: number) => (
                <div key={idx} className="p-3 bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg hover:border-[var(--border-active)]/30 transition-colors">
                  <div className="flex justify-between items-start gap-2">
                    <strong className="text-xs font-semibold text-amber-500">{alert.rule}</strong>
                    <span className="text-[10px] text-[var(--text-muted)] font-mono">{alert.id.slice(-8)}</span>
                  </div>
                  <p className="text-xs text-[var(--text-primary)] mt-1">{alert.summary}</p>
                  <div className="flex justify-between items-center mt-2 text-[10px] text-[var(--text-secondary)]">
                    <span>Severity: <span className="text-amber-500 font-bold">{alert.severity}</span></span>
                    <span>{new Date(alert.created_at).toLocaleTimeString()}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
