"use client";

import React, { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  Volume2,
  Database,
  Server,
  Sliders,
  KeyRound,
  Users,
  AlertCircle,
} from "lucide-react";
import { useAppStore, type Density, type Role, type Theme, canRevokeAgent } from "@/app/store";
import { DEMO_MODE } from "@/app/runtimeConfig";
import {
  getTenant,
  getTenantRiskWeights,
  listWebhookSubscriptions,
  probeGatewayHealth,
} from "@/app/api";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { contactChannelStatuses } from "@/components/alerting/supportStates";
import { redactSecret } from "@/components/alerting/redactSecret";
import { ConfirmDialog } from "@/components/primitives";
import { SettingScopeBadge } from "@/components/settings/scope";
import { discoverSettingsCapabilities } from "@/components/settings/capabilities";
import { RBAC_MATRIX, roleCapabilitySummary, roleOverrideDisabledReason } from "@/components/settings/rbacMatrix";
import {
  bearerTokenDisplayLabel,
  bearerTokenPlaceholder,
  connectionChangeImpact,
} from "@/components/settings/connectionForm";

const INPUT_CLASS =
  "w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none";

export default function SettingsTab() {
  const {
    gatewayUrl,
    bearerToken,
    activeTenant,
    authEpoch,
    theme,
    density,
    role,
    liveMode,
    redactByDefault,
    defaultLiveMode,
    setGatewayUrl,
    setBearerToken,
    setActiveTenant,
    setTheme,
    setDensity,
    setRole,
    setLiveMode,
    setRedactByDefault,
    setDefaultLiveMode,
    setActiveView,
  } = useAppStore();

  const { role: effectiveRole, operatorId, source: roleSource } = useEffectiveRole();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };

  const [localUrl, setLocalUrl] = useState(gatewayUrl);
  const [localTenant, setLocalTenant] = useState(activeTenant);
  const [localToken, setLocalToken] = useState("");
  const [connectionConfirmOpen, setConnectionConfirmOpen] = useState(false);

  const { data: health } = useQuery({
    queryKey: ["gatewayHealth", gatewayUrl],
    queryFn: ({ signal }) => probeGatewayHealth(gatewayUrl, signal),
    refetchInterval: 15000,
  });

  const { data: capabilities } = useQuery({
    queryKey: ["settingsCapabilities", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => discoverSettingsCapabilities(apiOpts),
    enabled: Boolean(activeTenant),
  });

  const caps = capabilities ?? {
    session: false,
    tenantDetail: false,
    riskWeights: false,
    webhooks: false,
    silences: false,
    retentionConfig: false,
  };

  const { data: tenant } = useQuery({
    queryKey: ["tenantDetail", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getTenant(apiOpts, activeTenant),
    enabled: caps.tenantDetail && Boolean(activeTenant),
  });

  const { data: riskWeights } = useQuery({
    queryKey: ["tenantRiskWeights", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getTenantRiskWeights(apiOpts),
    enabled: caps.riskWeights && Boolean(activeTenant),
  });

  const { data: webhooksResult } = useQuery({
    queryKey: ["settingsWebhooks", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => listWebhookSubscriptions(apiOpts, 10),
    enabled: caps.webhooks,
  });
  const webhookChannels = contactChannelStatuses(
    { webhooks: caps.webhooks, playbooks: false, silences: caps.silences },
    webhooksResult?.data ?? [],
  );

  const roleOverrideReason = roleOverrideDisabledReason(DEMO_MODE);
  const canEditRiskWeights = canRevokeAgent(effectiveRole);

  const applyConnection = () => {
    setGatewayUrl(localUrl.trim());
    setActiveTenant(localTenant.trim());
    if (localToken.trim()) setBearerToken(localToken.trim());
    setLocalToken("");
    setConnectionConfirmOpen(false);
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--text-primary)]">Settings</h2>
        <p className="text-[11px] text-[var(--text-muted)]">
          Capability-aware configuration. Gateway-backed settings reconcile with server state; local
          preferences never store bearer tokens in production.
        </p>
      </div>

      {/* Gateway connection */}
      <div className="panel-card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <Server size={14} className="text-[var(--brand)]" /> Gateway Connection
          </h3>
          <SettingScopeBadge scope="gateway" />
        </div>
        <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-3">
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
            <span className="text-[10px] font-bold uppercase text-[var(--text-muted)]">Liveness</span>
            <p className={`mt-1 font-mono ${health?.live ? "text-green-400" : "text-red-400"}`}>
              {health?.live ? "/livez OK" : "/livez unreachable"}
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
            <span className="text-[10px] font-bold uppercase text-[var(--text-muted)]">Readiness</span>
            <p className={`mt-1 font-mono ${health?.ready ? "text-green-400" : "text-amber-400"}`}>
              {health?.ready ? "/readyz OK" : "/readyz degraded"}
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
            <span className="text-[10px] font-bold uppercase text-[var(--text-muted)]">Session API</span>
            <p className="mt-1 font-mono text-[var(--text-primary)]">
              {caps.session ? "GET /v1/session" : "Not exposed"}
            </p>
          </div>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Gateway URL
            <input
              type="url"
              value={localUrl}
              onChange={(e) => setLocalUrl(e.target.value)}
              className={INPUT_CLASS}
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Tenant ID
            <input
              type="text"
              value={localTenant}
              onChange={(e) => setLocalTenant(e.target.value)}
              className={INPUT_CLASS}
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)] md:col-span-2">
            <span className="flex items-center gap-1">
              <KeyRound size={12} /> Bearer token ({bearerTokenDisplayLabel(Boolean(bearerToken))})
            </span>
            <input
              type="password"
              value={localToken}
              onChange={(e) => setLocalToken(e.target.value)}
              placeholder={bearerTokenPlaceholder()}
              className={INPUT_CLASS}
              autoComplete="off"
            />
            <span className="font-sans normal-case text-[var(--text-muted)]">
              Stored value: {redactSecret(bearerToken ? "set" : "")} ·{" "}
              {DEMO_MODE ? "Demo mode may persist tokens locally." : "Production keeps tokens in memory only."}
            </span>
          </label>
        </div>
        <button
          type="button"
          onClick={() => setConnectionConfirmOpen(true)}
          className="rounded bg-[var(--brand)] px-4 py-2 text-[10px] font-bold uppercase text-white hover:bg-[var(--brand-emphasis)]"
        >
          Apply connection changes
        </button>
      </div>

      {/* Tenant & session */}
      <div className="panel-card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <Users size={14} className="text-[var(--brand)]" /> Tenant & Session
          </h3>
          <SettingScopeBadge scope={caps.tenantDetail ? "gateway" : "unsupported"} />
        </div>
        <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-2">
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
            <span className="text-[10px] font-bold uppercase text-[var(--text-muted)]">Active tenant</span>
            <p className="mt-1 font-mono text-[var(--text-primary)]">{activeTenant || "—"}</p>
          </div>
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3">
            <span className="text-[10px] font-bold uppercase text-[var(--text-muted)]">Effective role</span>
            <p className="mt-1 font-mono capitalize text-[var(--text-primary)]">
              {effectiveRole} ({roleSource})
            </p>
            <p className="mt-1 text-[10px] text-[var(--text-muted)]">{roleCapabilitySummary(effectiveRole)}</p>
          </div>
        </div>
        {tenant ? (
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-xs">
            <p>
              <strong className="text-[var(--text-primary)]">{tenant.name}</strong> · plan {tenant.plan}
            </p>
            <p className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">
              Auto-respond: {tenant.auto_respond_enabled ? "enabled" : "disabled"} · Token auto-rotate on
              leak: {tenant.auto_rotate_token_on_leak_enabled ? "enabled" : "disabled"}
            </p>
          </div>
        ) : (
          <p className="text-xs text-[var(--text-muted)]">
            {caps.tenantDetail
              ? "Tenant metadata unavailable for the current context."
              : "Tenant detail API not available — enter tenant ID manually in connection settings."}
          </p>
        )}
        {operatorId ? (
          <p className="font-mono text-[10px] text-[var(--text-muted)]">Operator: {operatorId}</p>
        ) : null}
      </div>

      {/* RBAC */}
      <div className="panel-card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <Shield size={14} className="text-[var(--brand)]" /> RBAC Matrix
          </h3>
          <SettingScopeBadge scope="read-only" />
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[520px] text-left text-[11px]">
            <thead>
              <tr className="border-b border-[var(--border-default)] text-[10px] uppercase text-[var(--text-muted)]">
                <th className="px-2 py-2">Capability</th>
                <th className="px-2 py-2">Viewer</th>
                <th className="px-2 py-2">Analyst</th>
                <th className="px-2 py-2">Approver</th>
                <th className="px-2 py-2">Admin</th>
              </tr>
            </thead>
            <tbody>
              {RBAC_MATRIX.map((row) => (
                <tr key={row.capability} className="border-b border-[var(--border-default)]/50">
                  <td className="px-2 py-2 text-[var(--text-secondary)]">{row.capability}</td>
                  {[row.viewer, row.analyst, row.approver, row.admin].map((allowed, idx) => (
                    <td key={idx} className="px-2 py-2 font-mono text-[10px]">
                      {allowed ? "✓" : "—"}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <label className="flex max-w-xs flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          Demo role override
          <select
            value={role}
            disabled={Boolean(roleOverrideReason)}
            title={roleOverrideReason ?? undefined}
            onChange={(e) => setRole(e.target.value as Role)}
            className={INPUT_CLASS}
          >
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="approver">Approver</option>
            <option value="admin">Admin</option>
          </select>
          {roleOverrideReason ? (
            <span className="flex items-start gap-1 font-sans normal-case text-amber-300">
              <AlertCircle size={12} className="mt-0.5 shrink-0" />
              {roleOverrideReason}
            </span>
          ) : null}
        </label>
      </div>

      {/* Alerting */}
      <div className="panel-card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <Volume2 size={14} className="text-[var(--brand)]" /> Notification & Alerting
          </h3>
          <SettingScopeBadge scope={caps.webhooks ? "gateway" : "unsupported"} />
        </div>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {webhookChannels.map((ch) => (
            <div
              key={ch.channel}
              className="flex items-center justify-between rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3 text-xs"
            >
              <span className="capitalize text-[var(--text-primary)]">{ch.channel}</span>
              <span className="font-mono text-[10px] uppercase text-[var(--text-muted)]">{ch.support}</span>
            </div>
          ))}
        </div>
        <p className="text-xs text-[var(--text-muted)]">
          Silences API: {caps.silences ? "detected (UI in Alerting)" : "unsupported (#1627)"}. Manage contact
          points in{" "}
          <button
            type="button"
            onClick={() => setActiveView("alerting")}
            className="font-bold text-[var(--brand)] underline-offset-2 hover:underline"
          >
            Alerting
          </button>
          .
        </p>
      </div>

      {/* Retention */}
      <div className="panel-card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <Database size={14} className="text-[var(--brand)]" /> Retention & Advisory Tuning
          </h3>
          <SettingScopeBadge scope={caps.retentionConfig ? "gateway" : "unsupported"} />
        </div>
        {caps.retentionConfig ? (
          <p className="text-xs text-[var(--text-muted)]">Retention API detected — operator UI wiring pending.</p>
        ) : (
          <p className="text-xs text-[var(--text-muted)]">
            Audit and approval retention are gateway operator env vars (
            <code className="text-[var(--brand)]">AEGIS_AUDIT_RETENTION_DAYS</code>,{" "}
            <code className="text-[var(--brand)]">AEGIS_APPROVAL_RETENTION_DAYS</code>). No tenant-facing
            retention API is exposed yet.
          </p>
        )}
        {riskWeights ? (
          <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-xs">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[var(--text-primary)]">Composite risk weights (advisory)</span>
              <SettingScopeBadge scope="read-only" />
            </div>
            {!canEditRiskWeights ? (
              <p className="mt-1 text-[10px] text-amber-300">Requires admin role to modify via API.</p>
            ) : null}
            <p className="mt-2 font-mono text-[10px] text-[var(--text-muted)]">
              MCP penalty {riskWeights.mcp_trust_penalty} · Anomaly weight {riskWeights.anomaly_weight_pct}% ·
              Approval credit {riskWeights.approval_credit}
            </p>
          </div>
        ) : null}
      </div>

      {/* Console preferences */}
      <div className="panel-card space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
          <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            <Sliders size={14} className="text-[var(--brand)]" /> Console Preferences
          </h3>
          <SettingScopeBadge scope="local" />
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Theme
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)} className={INPUT_CLASS}>
              <option value="dark-soc">Dark SOC</option>
              <option value="light">Light</option>
              <option value="oled">OLED</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Density
            <select
              value={density}
              onChange={(e) => setDensity(e.target.value as Density)}
              className={INPUT_CLASS}
            >
              <option value="compact">Compact</option>
              <option value="cozy">Cozy</option>
            </select>
          </label>
        </div>
        <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={defaultLiveMode}
            onChange={(e) => {
              setDefaultLiveMode(e.target.checked);
              setLiveMode(e.target.checked);
            }}
          />
          Default to live refresh on console load
        </label>
        <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
          <input type="checkbox" checked={liveMode} onChange={(e) => setLiveMode(e.target.checked)} />
          Live refresh enabled for this session
        </label>
        <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
          <input
            type="checkbox"
            checked={redactByDefault}
            onChange={(e) => setRedactByDefault(e.target.checked)}
          />
          Redact secret-shaped JSON fields by default
        </label>
      </div>

      <ConfirmDialog
        open={connectionConfirmOpen}
        title="Apply gateway connection changes?"
        impact={connectionChangeImpact()}
        target={`${localUrl.trim()} · tenant ${localTenant.trim() || "—"}`}
        confirmLabel="Apply connection"
        onConfirm={applyConnection}
        onCancel={() => setConnectionConfirmOpen(false)}
      />
    </div>
  );
}