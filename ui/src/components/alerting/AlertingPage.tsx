"use client";

import React, { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Bell,
  Plus,
  Trash2,
  RefreshCw,
  AlertCircle,
  Info,
  Volume2,
  Shield,
  Ban,
  Zap,
} from "lucide-react";
import { useAppStore } from "@/app/store";
import {
  createSilence,
  createWebhookSubscription,
  deleteSilence,
  deleteWebhookSubscription,
  listPlaybooks,
  listSilences,
  listWebhookSubscriptions,
  probeGatewayEndpoint,
  reactivateWebhookSubscription,
  type AlertSilenceRecord,
  type WebhookSubscriptionRecord,
} from "@/app/api";
import { GatewayEntityDatasource } from "@/datasources/gatewayEntity";
import { alertRowsFromFrame, socRuleRowsFromFrame } from "@/datasources/entityData";
import { errorMessage } from "@/lib/format";
import { ConfirmDialog } from "@/components/primitives";
import { useRulesCatalog } from "@/components/rules/useRulesCatalog";
import { getSeverityStyle } from "@/components/detections/severityStyles";
import { buildRuleHealthRows, ruleHealthLabel } from "./ruleHealth";
import { ruleHealthBadgeClass } from "./ruleHealthStyles";
import { contactChannelStatuses } from "./supportStates";
import { channelSupportBadgeClass, channelSupportLabel } from "./supportStyles";
import { buildNotificationPolicies } from "./notificationPolicies";
import { hashPreview, redactSecret } from "./redactSecret";

const DEFAULT_TIME_RANGE = { from: "now-24h", to: "now" } as const;

function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    return url.length > 48 ? `${url.slice(0, 24)}…${url.slice(-12)}` : url;
  }
}

export default function AlertingPage() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();
  const entityDatasource = useMemo(
    () => new GatewayEntityDatasource({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );

  const [newWebhookUrl, setNewWebhookUrl] = useState("");
  const [newWebhookSecret, setNewWebhookSecret] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<WebhookSubscriptionRecord | null>(null);
  const [silenceRuleKey, setSilenceRuleKey] = useState("");
  const [silenceAgentId, setSilenceAgentId] = useState("");
  const [silenceHours, setSilenceHours] = useState("4");
  const [silenceComment, setSilenceComment] = useState("");
  const [deleteSilenceTarget, setDeleteSilenceTarget] = useState<AlertSilenceRecord | null>(null);

  const { data: backendSupport } = useQuery({
    queryKey: ["alertingSupport", gatewayUrl, activeTenant, authEpoch],
    queryFn: async ({ signal }) => {
      const [webhooks, playbooks, silences] = await Promise.all([
        probeGatewayEndpoint({ ...apiOpts, signal }, "/v1/webhook_subscriptions?limit=1"),
        probeGatewayEndpoint({ ...apiOpts, signal }, "/v1/playbooks?limit=1"),
        probeGatewayEndpoint({ ...apiOpts, signal }, "/v1/soc/silences?limit=1"),
      ]);
      return { webhooks, playbooks, silences };
    },
  });

  const support = backendSupport ?? { webhooks: true, playbooks: true, silences: false };

  const { data: webhooksResult, isLoading: loadingWebhooks, error: webhooksError } = useQuery({
    queryKey: ["webhookSubscriptions", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) => listWebhookSubscriptions({ ...apiOpts, signal }),
    enabled: support.webhooks,
  });
  const webhooks = webhooksResult?.data ?? [];

  const { data: silencesResult, isLoading: loadingSilences, error: silencesError } = useQuery({
    queryKey: ["alertSilences", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) => listSilences({ ...apiOpts, signal }),
    enabled: support.silences,
  });
  const silences = silencesResult?.data ?? [];

  const createSilenceMutation = useMutation({
    mutationFn: () => {
      const hours = Number(silenceHours);
      if (!Number.isFinite(hours) || hours <= 0) {
        throw new Error("Duration must be a positive number of hours");
      }
      if (!silenceRuleKey.trim() && !silenceAgentId.trim()) {
        throw new Error("Provide a rule key and/or agent id");
      }
      const endsAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
      return createSilence(
        { ...apiOpts },
        {
          rule_key: silenceRuleKey.trim() || undefined,
          agent_id: silenceAgentId.trim() || undefined,
          comment: silenceComment.trim() || undefined,
          ends_at: endsAt,
          created_by: "console",
        },
      );
    },
    onSuccess: () => {
      setSilenceRuleKey("");
      setSilenceAgentId("");
      setSilenceComment("");
      queryClient.invalidateQueries({ queryKey: ["alertSilences"] });
    },
    onError: (err: unknown) => setFormError(errorMessage(err)),
  });

  const deleteSilenceMutation = useMutation({
    mutationFn: (id: string) => deleteSilence({ ...apiOpts }, id),
    onSuccess: () => {
      setDeleteSilenceTarget(null);
      queryClient.invalidateQueries({ queryKey: ["alertSilences"] });
    },
    onError: (err: unknown) => setFormError(errorMessage(err)),
  });

  const { data: playbooksResult, isLoading: loadingPlaybooks, error: playbooksError } = useQuery({
    queryKey: ["playbooks", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) => listPlaybooks({ ...apiOpts, signal }),
    enabled: support.playbooks,
  });
  const playbooks = playbooksResult?.data ?? [];

  const { data: effectiveRulesFrame, isLoading: loadingEffective } = useQuery({
    queryKey: ["socRules", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        rulesCatalog: "soc",
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
  });
  const effectiveRules = socRuleRowsFromFrame(effectiveRulesFrame);

  const { data: customRulesFrame, isLoading: loadingCustom } = useQuery({
    queryKey: ["customRules", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        rulesCatalog: "detection",
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
  });
  const customRules = socRuleRowsFromFrame(customRulesFrame);

  const { data: alertsFrame, isLoading: loadingAlerts } = useQuery({
    queryKey: ["alerts", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        entity: "alert",
        limit: 100,
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
    refetchInterval: 10000,
  });

  const catalog = useRulesCatalog(effectiveRules, customRules);
  const alerts = alertRowsFromFrame(alertsFrame);
  const healthRows = useMemo(
    () => buildRuleHealthRows(catalog, alerts ?? []),
    [catalog, alerts],
  );
  const channelStatuses = contactChannelStatuses(support, webhooks);
  const policies = buildNotificationPolicies(webhooks);

  const createMutation = useMutation({
    mutationFn: () =>
      createWebhookSubscription(apiOpts, {
        url: newWebhookUrl.trim(),
        secret: newWebhookSecret.trim() || undefined,
      }),
    onSuccess: (record) => {
      setCreatedSecret(record.delivery_secret ?? null);
      setNewWebhookUrl("");
      setNewWebhookSecret("");
      setFormError(null);
      queryClient.invalidateQueries({ queryKey: ["webhookSubscriptions"] });
    },
    onError: (err: unknown) => setFormError(errorMessage(err) || "Failed to create webhook subscription."),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteWebhookSubscription(apiOpts, id),
    onSuccess: () => {
      setDeleteTarget(null);
      queryClient.invalidateQueries({ queryKey: ["webhookSubscriptions"] });
    },
    onError: (err: unknown) => setFormError(errorMessage(err) || "Failed to delete webhook subscription."),
  });

  const reactivateMutation = useMutation({
    mutationFn: (id: string) => reactivateWebhookSubscription(apiOpts, id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["webhookSubscriptions"] }),
    onError: (err: unknown) => setFormError(errorMessage(err) || "Failed to reactivate subscription."),
  });

  const loadingHealth = loadingEffective || loadingCustom || loadingAlerts;

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-[var(--text-primary)]">
          <Bell size={16} className="text-[var(--brand)]" />
          Alerting
        </h2>
        <p className="text-[11px] text-[var(--text-muted)]">
          Deterministic rule health, tenant-scoped contact points, notification policies, and active-response
          playbooks. Secrets are redacted after creation.
        </p>
      </div>

      {formError ? (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-950/20 p-3 text-[11px] text-red-300">
          <AlertCircle size={14} className="mt-0.5 shrink-0" />
          {formError}
        </div>
      ) : null}

      {createdSecret ? (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-950/20 p-3 text-[11px] text-amber-200">
          <Info size={14} className="mt-0.5 shrink-0" />
          <div>
            <strong className="block text-[var(--text-primary)]">Delivery secret (shown once)</strong>
            <code className="mt-1 block break-all font-mono text-[10px]">{createdSecret}</code>
            <button
              type="button"
              onClick={() => setCreatedSecret(null)}
              className="mt-2 text-[10px] font-bold uppercase text-[var(--brand)]"
            >
              Dismiss
            </button>
          </div>
        </div>
      ) : null}

      {/* Rule health */}
      <div className="panel-card space-y-4">
        <h3 className="flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Shield size={14} className="text-[var(--brand)]" /> Rule Health
        </h3>
        {loadingHealth ? (
          <p className="py-6 text-center text-xs text-[var(--text-muted)]">Loading rule health…</p>
        ) : healthRows.length === 0 ? (
          <p className="py-6 text-center text-xs text-[var(--text-muted)]">No rules in catalogue.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-[11px]">
              <thead>
                <tr className="border-b border-[var(--border-default)] text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                  <th className="px-2 py-2 font-semibold">Rule</th>
                  <th className="px-2 py-2 font-semibold">Severity</th>
                  <th className="px-2 py-2 font-semibold">Health</th>
                  <th className="px-2 py-2 font-semibold">Throughput</th>
                  <th className="px-2 py-2 font-semibold">Last alert</th>
                </tr>
              </thead>
              <tbody>
                {healthRows.map((row) => {
                  const sev = getSeverityStyle(row.severity);
                  return (
                    <tr key={row.rule_key} className="border-b border-[var(--border-default)]/50">
                      <td className="px-2 py-2">
                        <span className="block font-mono text-[10px] font-bold text-[var(--brand)]">
                          {row.rule_key}
                        </span>
                        <span className="text-[var(--text-muted)]">{row.name}</span>
                      </td>
                      <td className="px-2 py-2">
                        <span className={`rounded px-1.5 py-0.5 text-[9px] font-bold uppercase ${sev.badge}`}>
                          {row.severity}
                        </span>
                      </td>
                      <td className="px-2 py-2">
                        <span
                          className={`inline-block rounded border px-2 py-0.5 text-[9px] font-bold uppercase ${ruleHealthBadgeClass(row.status)}`}
                        >
                          {ruleHealthLabel(row.status)}
                        </span>
                      </td>
                      <td className="px-2 py-2 font-mono text-[var(--text-secondary)]">{row.throughputLabel}</td>
                      <td className="px-2 py-2 font-mono text-[var(--text-muted)]">
                        {row.lastAlertAt ? new Date(row.lastAlertAt).toLocaleString() : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Contact points */}
      <div className="panel-card space-y-4">
        <h3 className="flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Volume2 size={14} className="text-[var(--brand)]" /> Contact Points
        </h3>
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {channelStatuses.map((ch) => (
            <div
              key={ch.channel}
              className="flex items-start justify-between gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/30 p-3"
            >
              <div className="min-w-0 text-xs">
                <span className="font-semibold capitalize text-[var(--text-primary)]">{ch.channel}</span>
                <p className="mt-0.5 text-[var(--text-muted)]">{ch.detail}</p>
              </div>
              <span
                className={`shrink-0 rounded border px-2 py-0.5 font-mono text-[9px] font-bold uppercase ${channelSupportBadgeClass(ch.support)}`}
              >
                {channelSupportLabel(ch.support)}
              </span>
            </div>
          ))}
        </div>

        {!support.webhooks ? (
          <p className="text-xs text-[var(--text-muted)]">
            Webhook subscriptions API is unavailable on this gateway build.
          </p>
        ) : (
          <>
            <form
              className="flex flex-col gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 md:flex-row md:items-end"
              onSubmit={(e) => {
                e.preventDefault();
                if (!newWebhookUrl.trim()) {
                  setFormError("Webhook URL is required.");
                  return;
                }
                createMutation.mutate();
              }}
            >
              <label className="flex flex-1 flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                HTTPS webhook URL
                <input
                  type="url"
                  value={newWebhookUrl}
                  onChange={(e) => setNewWebhookUrl(e.target.value)}
                  placeholder="https://hooks.slack.com/services/…"
                  className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 font-mono text-xs text-[var(--text-primary)]"
                />
              </label>
              <label className="flex flex-1 flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                Delivery secret (optional)
                <input
                  type="password"
                  value={newWebhookSecret}
                  onChange={(e) => setNewWebhookSecret(e.target.value)}
                  placeholder="Auto-generated if empty"
                  className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 font-mono text-xs text-[var(--text-primary)]"
                />
              </label>
              <button
                type="submit"
                disabled={createMutation.isPending}
                className="flex items-center justify-center gap-1 rounded bg-[var(--brand)] px-4 py-2 text-[10px] font-bold uppercase text-white hover:bg-[var(--brand-emphasis)] disabled:opacity-50"
              >
                <Plus size={12} /> Add webhook
              </button>
            </form>

            {loadingWebhooks ? (
              <p className="text-xs text-[var(--text-muted)]">Loading subscriptions…</p>
            ) : webhooksError ? (
              <p className="text-xs text-red-400">{errorMessage(webhooksError)}</p>
            ) : webhooks.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">No webhook subscriptions registered.</p>
            ) : (
              <div className="space-y-2">
                {webhooks.map((sub) => (
                  <div
                    key={sub.id}
                    className="flex flex-col gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 md:flex-row md:items-center md:justify-between"
                  >
                    <div className="min-w-0 text-xs">
                      <span className="block truncate font-mono text-[10px] text-[var(--text-primary)]">
                        {redactUrl(sub.url)}
                      </span>
                      <span className="mt-1 block text-[var(--text-muted)]">
                        Delivery secret: {redactSecret("stored")} · fingerprint {hashPreview(sub.secret_hash)}
                      </span>
                      <span className="mt-0.5 block font-mono text-[10px] text-[var(--text-muted)]">
                        {sub.delivery_status} · {sub.consecutive_failures} failures
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      {sub.delivery_status === "dead" ? (
                        <button
                          type="button"
                          onClick={() => reactivateMutation.mutate(sub.id)}
                          disabled={reactivateMutation.isPending}
                          className="flex items-center gap-1 rounded border border-amber-500/40 bg-amber-950/20 px-2 py-1 text-[10px] font-bold text-amber-300"
                        >
                          <RefreshCw size={12} /> Reactivate
                        </button>
                      ) : null}
                      <button
                        type="button"
                        onClick={() => setDeleteTarget(sub)}
                        className="flex items-center gap-1 rounded border border-red-500/30 bg-red-950/20 px-2 py-1 text-[10px] font-bold text-red-300"
                      >
                        <Trash2 size={12} /> Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {/* Notification policies */}
      <div className="panel-card space-y-4">
        <h3 className="flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Bell size={14} className="text-[var(--brand)]" /> Notification Policies
        </h3>
        <p className="text-[11px] text-[var(--text-muted)]">
          Policies are derived from tenant webhook subscriptions (event filters and minimum severity).
        </p>
        {!support.webhooks || policies.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">No notification policies configured.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[480px] text-left text-[11px]">
              <thead>
                <tr className="border-b border-[var(--border-default)] text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                  <th className="px-2 py-2 font-semibold">Policy</th>
                  <th className="px-2 py-2 font-semibold">Events</th>
                  <th className="px-2 py-2 font-semibold">Min severity</th>
                  <th className="px-2 py-2 font-semibold">Delivery</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id} className="border-b border-[var(--border-default)]/50">
                    <td className="px-2 py-2 capitalize text-[var(--text-primary)]">{policy.label}</td>
                    <td className="px-2 py-2 font-mono text-[var(--text-secondary)]">{policy.eventTypes}</td>
                    <td className="px-2 py-2 font-mono text-[var(--text-secondary)]">{policy.minSeverity}</td>
                    <td className="px-2 py-2">
                      <span
                        className={`rounded border px-2 py-0.5 text-[9px] font-bold uppercase ${
                          policy.deliveryStatus === "healthy"
                            ? "border-green-500/40 bg-green-500/20 text-green-400"
                            : policy.deliveryStatus === "dead"
                              ? "border-red-500/40 bg-red-500/20 text-red-400"
                              : "border-[var(--border-default)] bg-[var(--border-default)]/30 text-[var(--text-muted)]"
                        }`}
                      >
                        {policy.deliveryStatus}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Silences */}
      <div className="panel-card space-y-4">
        <h3 className="flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Ban size={14} className="text-[var(--brand)]" /> Silences
        </h3>
        {support.silences ? (
          <div className="space-y-3">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <input
                className="input-field text-xs"
                placeholder="Rule key (optional)"
                value={silenceRuleKey}
                onChange={(e) => setSilenceRuleKey(e.target.value)}
              />
              <input
                className="input-field text-xs"
                placeholder="Agent id (optional)"
                value={silenceAgentId}
                onChange={(e) => setSilenceAgentId(e.target.value)}
              />
              <input
                className="input-field text-xs"
                placeholder="Hours"
                value={silenceHours}
                onChange={(e) => setSilenceHours(e.target.value)}
              />
              <input
                className="input-field text-xs sm:col-span-2 lg:col-span-1"
                placeholder="Comment"
                value={silenceComment}
                onChange={(e) => setSilenceComment(e.target.value)}
              />
            </div>
            <button
              type="button"
              onClick={() => createSilenceMutation.mutate()}
              disabled={createSilenceMutation.isPending}
              className="btn-primary text-xs"
            >
              Create silence
            </button>
            {loadingSilences ? (
              <p className="text-xs text-[var(--text-muted)]">Loading silences…</p>
            ) : silencesError ? (
              <p className="text-xs text-red-400">{errorMessage(silencesError)}</p>
            ) : silences.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">No active silences for this tenant.</p>
            ) : (
              <div className="space-y-2">
                {silences.map((s) => (
                  <div
                    key={s.id}
                    className="flex items-center justify-between gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-xs"
                  >
                    <div className="min-w-0">
                      <p className="font-mono text-[10px] text-[var(--text-primary)]">
                        {s.rule_key ? `rule:${s.rule_key}` : "rule:*"}
                        {" · "}
                        {s.agent_id ? `agent:${s.agent_id}` : "agent:*"}
                      </p>
                      <p className="text-[10px] text-[var(--text-muted)]">
                        until {new Date(s.ends_at).toLocaleString()}
                        {s.comment ? ` — ${s.comment}` : ""}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setDeleteSilenceTarget(s)}
                      className="text-[10px] uppercase text-red-400 underline"
                    >
                      Delete
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-start gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-[11px] text-[var(--text-secondary)]">
            <Info size={14} className="mt-0.5 shrink-0 text-[var(--brand)]" />
            <p>
              Alert silences require a gateway <code className="text-[var(--brand)]">/v1/soc/silences</code> API
              (tracked in #1627). Until then, mute noisy rules by disabling them in the Rules catalogue.
            </p>
          </div>
        )}
      </div>

      {/* Active response playbooks */}
      <div className="panel-card space-y-4">
        <h3 className="flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Zap size={14} className="text-[var(--brand)]" /> Active Response
        </h3>
        <p className="text-[11px] text-[var(--text-muted)]">Read-only playbook catalogue mapped to SOC triggers.</p>
        {!support.playbooks ? (
          <p className="text-xs text-[var(--text-muted)]">Playbooks API unavailable on this gateway.</p>
        ) : loadingPlaybooks ? (
          <p className="text-xs text-[var(--text-muted)]">Loading playbooks…</p>
        ) : playbooksError ? (
          <p className="text-xs text-red-400">{errorMessage(playbooksError)}</p>
        ) : playbooks.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">No playbooks registered for this tenant.</p>
        ) : (
          <div className="space-y-2">
            {playbooks.map((pb) => (
              <div
                key={pb.id}
                className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/20 p-3 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-bold text-[var(--text-primary)]">{pb.name}</span>
                  <span
                    className={`rounded px-2 py-0.5 text-[9px] font-bold uppercase ${
                      pb.enabled
                        ? "bg-green-500/20 text-green-400"
                        : "bg-[var(--border-default)]/40 text-[var(--text-muted)]"
                    }`}
                  >
                    {pb.enabled ? "Enabled" : "Disabled"}
                  </span>
                </div>
                <p className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">
                  trigger: {pb.trigger_kind} · severity ≥ {pb.trigger_severity}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={deleteSilenceTarget !== null}
        title="Delete silence?"
        impact="Matching alerts will resume notification routing after deletion."
        target={
          deleteSilenceTarget
            ? `${deleteSilenceTarget.rule_key ?? "*"} / ${deleteSilenceTarget.agent_id ?? "*"}`
            : "—"
        }
        confirmLabel="Delete"
        onConfirm={() => deleteSilenceTarget && deleteSilenceMutation.mutate(deleteSilenceTarget.id)}
        onCancel={() => setDeleteSilenceTarget(null)}
      />

      <ConfirmDialog
        open={deleteTarget !== null}
        title="Delete webhook subscription?"
        impact="Alerts will stop routing to this contact point. This cannot be undone."
        target={deleteTarget ? redactUrl(deleteTarget.url) : "—"}
        confirmLabel="Delete"
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
        onCancel={() => setDeleteTarget(null)}
      />
    </div>
  );
}