"use client";

import React, { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import {
  createSocRule,
  deleteDetectionRule,
  backtestSocRule,
  UpsertRulePayload,
  type BacktestResult,
} from "@/app/api";
import { GatewayEntityDatasource } from "@/datasources/gatewayEntity";
import { socRuleRowsFromFrame } from "@/datasources/entityData";
import { errorMessage } from "@/lib/format";
import {
  ShieldAlert,
  Plus,
  Play,
  Check,
  AlertCircle,
  Terminal,
  Activity,
  Trash2,
  AlertTriangle,
  Info,
} from "lucide-react";
import { ConfirmDialog } from "@/components/primitives";
import { jsonToYaml } from "@/components/detections/ruleFormatting";
import { getSeverityStyle } from "@/components/detections/severityStyles";
import { useRulesCatalog, type CatalogRule } from "./useRulesCatalog";

const DEFAULT_TIME_RANGE = { from: "now-24h", to: "now" } as const;

export default function RulesPage() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const entityDatasource = useMemo(
    () => new GatewayEntityDatasource({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );
  const queryClient = useQueryClient();

  const [selectedRuleKey, setSelectedRuleKey] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [isCreatingNew, setIsCreatingNew] = useState(false);

  const [formRuleKey, setFormRuleKey] = useState("");
  const [formName, setFormName] = useState("");
  const [formSeverity, setFormSeverity] = useState("medium");
  const [formCondition, setFormCondition] = useState("");
  const [formSummaryTemplate, setFormSummaryTemplate] = useState("");
  const [formEnabled, setFormEnabled] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [deleteReason, setDeleteReason] = useState("");

  const [backtestFrom, setBacktestFrom] = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 7);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  });
  const [backtestTo, setBacktestTo] = useState(() => {
    const d = new Date();
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  });
  const [backtestResult, setBacktestResult] = useState<BacktestResult | null>(null);
  const [isBacktesting, setIsBacktesting] = useState(false);
  const [backtestError, setBacktestError] = useState<string | null>(null);

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

  const catalog = useRulesCatalog(effectiveRules, customRules);

  const selectedRule = useMemo(() => {
    if (!selectedRuleKey) return null;
    return catalog.find((rule) => rule.rule_key === selectedRuleKey) ?? null;
  }, [catalog, selectedRuleKey]);

  const selectRule = (rule: CatalogRule) => {
    setSelectedRuleKey(rule.rule_key);
    setIsCreatingNew(false);
    setIsEditing(false);
    setFormRuleKey(rule.rule_key);
    setFormName(rule.name);
    setFormSeverity(rule.severity);
    setFormCondition(jsonToYaml(rule.condition));
    setFormSummaryTemplate(rule.summary_template);
    setFormEnabled(rule.enabled);
    setFormError(null);
    setFormSuccess(null);
    setBacktestResult(null);
    setBacktestError(null);
  };

  const saveRuleMutation = useMutation({
    mutationFn: (payload: UpsertRulePayload) => createSocRule(apiOpts, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["socRules"] });
      queryClient.invalidateQueries({ queryKey: ["customRules"] });
      setFormSuccess("Rule successfully registered and applied.");
      setFormError(null);
      setIsEditing(false);
      setIsCreatingNew(false);
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err) || "Failed to save rule.");
      setFormSuccess(null);
    },
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (ruleId: string) => deleteDetectionRule(apiOpts, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["socRules"] });
      queryClient.invalidateQueries({ queryKey: ["customRules"] });
      setDeleteConfirmOpen(false);
      setDeleteReason("");
      setSelectedRuleKey(null);
      setIsEditing(false);
      setIsCreatingNew(false);
      setFormSuccess("Custom rule deleted successfully.");
      setFormError(null);
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err) || "Failed to delete rule.");
      setFormSuccess(null);
    },
  });

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formRuleKey.trim() || !formName.trim() || !formSummaryTemplate.trim()) {
      setFormError("Rule Key, Name, and Summary Template are required.");
      return;
    }
    saveRuleMutation.mutate({
      rule_key: formRuleKey.trim(),
      name: formName.trim(),
      severity: formSeverity,
      condition: formCondition,
      summary_template: formSummaryTemplate.trim(),
      enabled: formEnabled,
    });
  };

  const handleDelete = () => {
    if (!selectedRule?.dbId) return;
    setDeleteConfirmOpen(true);
    setDeleteReason("");
  };

  const confirmDelete = () => {
    if (!selectedRule?.dbId || !deleteReason.trim()) return;
    deleteRuleMutation.mutate(selectedRule.dbId);
  };

  const handleCreateNew = () => {
    setIsCreatingNew(true);
    setSelectedRuleKey(null);
    setFormRuleKey("");
    setFormName("");
    setFormSeverity("medium");
    setFormCondition("decision: deny\nmutating: true\ncontext_trust: [untrusted_external, malicious_suspected]");
    setFormSummaryTemplate("Action {tool}.{action} triggered custom rule: {reason}");
    setFormEnabled(true);
    setFormError(null);
    setFormSuccess(null);
    setBacktestResult(null);
    setBacktestError(null);
    setIsEditing(true);
  };

  const handleRunBacktest = async () => {
    if (!selectedRuleKey) return;
    setIsBacktesting(true);
    setBacktestError(null);
    setBacktestResult(null);
    try {
      const fromISO = new Date(backtestFrom).toISOString();
      const toISO = new Date(backtestTo).toISOString();
      const res = await backtestSocRule(apiOpts, selectedRuleKey, fromISO, toISO);
      setBacktestResult(res);
    } catch (err: unknown) {
      setBacktestError(errorMessage(err) || "Failed to complete historical backtest.");
    } finally {
      setIsBacktesting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h2 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-[var(--text-primary)]">
          <Terminal size={16} className="text-[var(--brand)]" />
          Detection Rules
        </h2>
        <p className="text-[11px] text-[var(--text-muted)]">
          Deterministic rule catalogue with tenant custom rules, YAML conditions, and historical backtesting.
        </p>
      </div>

      <div className="flex items-start gap-2 rounded-lg border border-[var(--border-default)] bg-[var(--surface-panel)] p-3 text-[11px] text-[var(--text-secondary)]">
        <Info size={14} className="mt-0.5 shrink-0 text-[var(--brand)]" />
        <p>
          Rules evaluate <strong className="text-[var(--text-primary)]">deterministically</strong> against
          authorization decision records.{" "}
          <code className="text-[var(--brand)]">min_risk_score</code> and{" "}
          <code className="text-[var(--brand)]">max_risk_score</code> are{" "}
          <strong className="text-[var(--text-primary)]">advisory-only</strong> filters — they never gate
          Cedar authorization.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="panel-card flex flex-col space-y-4 lg:col-span-4">
          <div className="flex items-center justify-between border-b border-[var(--border-default)] pb-3">
            <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
              <Terminal size={14} className="text-[var(--brand)]" /> Rules Catalogue
            </h3>
            <button
              onClick={handleCreateNew}
              className="flex cursor-pointer items-center gap-1 rounded bg-[var(--brand)] px-2.5 py-1 text-[10px] font-bold text-white transition-colors hover:bg-[var(--brand-emphasis)]"
            >
              <Plus size={12} /> Add Rule
            </button>
          </div>

          {loadingEffective || loadingCustom ? (
            <p className="py-10 text-center text-xs text-[var(--text-muted)]">Loading catalog...</p>
          ) : catalog.length === 0 ? (
            <p className="py-10 text-center text-xs text-[var(--text-muted)]">No rules registered.</p>
          ) : (
            <div className="custom-scrollbar max-h-[600px] space-y-2 overflow-y-auto pr-1">
              {catalog.map((rule) => {
                const isSelected = selectedRuleKey === rule.rule_key;
                const sevStyle = getSeverityStyle(rule.severity);
                return (
                  <div
                    key={rule.rule_key}
                    onClick={() => selectRule(rule)}
                    className={`flex cursor-pointer select-none flex-col gap-1.5 rounded-lg border p-3 transition-all ${
                      isSelected
                        ? "border-[var(--border-active)] bg-[var(--border-default)]/80 ring-1 ring-[var(--border-focus)]"
                        : "border-[var(--border-default)] bg-[var(--surface-app)]/40 hover:border-[var(--border-default)]"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="max-w-[170px] truncate font-mono text-xs font-bold text-[var(--brand)]">
                        {rule.rule_key}
                      </span>
                      <span
                        className={`rounded px-1.5 py-0.2 font-sans text-[9px] font-bold uppercase ${sevStyle.badge}`}
                      >
                        {rule.severity}
                      </span>
                    </div>
                    <span className="line-clamp-1 text-[11px] italic text-[var(--text-secondary)]">
                      {rule.name}
                    </span>
                    <div className="mt-1 flex items-center justify-between border-t border-[var(--border-default)]/50 pt-1.5 font-mono text-[10px] text-[var(--text-muted)]">
                      <span
                        className={`font-sans font-bold uppercase ${
                          rule.source === "default" ? "text-[var(--brand)]" : "text-amber-500"
                        }`}
                      >
                        {rule.source}
                      </span>
                      <span
                        className={`flex items-center gap-1 font-bold ${
                          rule.enabled ? "text-green-500" : "text-red-400"
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            rule.enabled ? "animate-pulse bg-green-500" : "bg-red-400"
                          }`}
                        />
                        {rule.enabled ? "ACTIVE" : "DISABLED"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="space-y-6 lg:col-span-8">
          {formSuccess && (
            <div className="animate-fadeIn flex items-center gap-2 rounded-lg border border-green-500/20 bg-green-950/20 p-3 text-xs text-green-400">
              <Check size={16} />
              <span>{formSuccess}</span>
            </div>
          )}
          {formError && (
            <div className="animate-fadeIn flex items-start gap-2 rounded-lg border border-red-500/20 bg-red-950/20 p-3 text-xs text-red-400">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              <div className="flex-1 space-y-1">
                <span className="font-bold">Rule Validation Refused:</span>
                <p className="whitespace-pre-wrap font-mono">{formError}</p>
              </div>
            </div>
          )}

          {selectedRule || isCreatingNew ? (
            <div className="panel-card space-y-6">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border-default)] pb-3">
                <div className="flex items-center gap-2">
                  <h3 className="font-mono text-sm font-bold text-[var(--text-primary)]">
                    {isCreatingNew ? "New Custom Detection Rule" : selectedRule?.rule_key}
                  </h3>
                  {!isCreatingNew && (
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                        selectedRule?.source === "default"
                          ? "border border-[var(--border-active)]/20 bg-[var(--brand)]/10 text-[var(--brand)]"
                          : "border border-amber-500/20 bg-amber-500/10 text-amber-400"
                      }`}
                    >
                      {selectedRule?.source}
                    </span>
                  )}
                </div>
                <div className="flex gap-2">
                  {!isEditing && selectedRule?.source === "custom" && (
                    <button
                      onClick={() => setIsEditing(true)}
                      className="cursor-pointer rounded bg-[var(--brand)] px-4 py-1.5 text-xs font-bold text-white transition-colors hover:bg-[var(--brand-emphasis)]"
                    >
                      Edit Rule
                    </button>
                  )}
                  {isEditing && (
                    <>
                      <button
                        type="button"
                        onClick={() => {
                          setIsEditing(false);
                          setIsCreatingNew(false);
                          setFormError(null);
                        }}
                        className="cursor-pointer rounded bg-[var(--border-default)] px-4 py-1.5 text-xs font-bold text-[var(--text-primary)] transition-colors hover:bg-[var(--border-default)]"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={handleSave}
                        disabled={saveRuleMutation.isPending}
                        className="cursor-pointer rounded bg-green-600 px-4 py-1.5 text-xs font-bold text-white transition-colors hover:bg-green-700 disabled:opacity-50"
                      >
                        {saveRuleMutation.isPending ? "Validating & Saving..." : "Save Rule"}
                      </button>
                    </>
                  )}
                  {!isEditing && selectedRule?.source === "custom" && selectedRule?.dbId && (
                    <button
                      onClick={handleDelete}
                      disabled={deleteRuleMutation.isPending}
                      className="flex cursor-pointer items-center gap-1 rounded border border-red-500/30 bg-red-950/40 px-3 py-1.5 text-xs font-bold text-red-400 transition-colors hover:border-red-500/60 hover:bg-red-900/60 disabled:opacity-50"
                    >
                      <Trash2 size={13} /> Delete
                    </button>
                  )}
                </div>
              </div>

              <form onSubmit={handleSave} className="space-y-4 text-xs">
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div>
                    <label className="mb-1 block font-bold text-[var(--text-muted)]">Rule Key</label>
                    <input
                      type="text"
                      value={formRuleKey}
                      onChange={(e) =>
                        setFormRuleKey(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ""))
                      }
                      disabled={!isCreatingNew}
                      placeholder="e.g. mutating_critical_action"
                      className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 font-mono text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    />
                    <span className="mt-0.5 block text-[10px] text-[var(--text-muted)]">
                      Unique identifier. Lowercase, numbers, underscores only.
                    </span>
                  </div>
                  <div>
                    <label className="mb-1 block font-bold text-[var(--text-muted)]">
                      Rule Name (Fired Alert Rule Value)
                    </label>
                    <input
                      type="text"
                      value={formName}
                      onChange={(e) => setFormName(e.target.value)}
                      disabled={!isEditing}
                      placeholder="e.g. confused_deputy_block"
                      className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div>
                    <label className="mb-1 block font-bold text-[var(--text-muted)]">Severity</label>
                    <select
                      value={formSeverity}
                      onChange={(e) => setFormSeverity(e.target.value)}
                      disabled={!isEditing}
                      className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50"
                    >
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <div className="flex items-center pt-5">
                    <label className="flex cursor-pointer select-none items-center gap-2 font-bold text-[var(--text-primary)]">
                      <input
                        type="checkbox"
                        checked={formEnabled}
                        onChange={(e) => setFormEnabled(e.target.checked)}
                        disabled={!isEditing}
                        className="h-4 w-4 rounded border-[var(--border-default)] bg-[var(--surface-app)] text-[var(--brand)] focus:ring-[var(--border-focus)] disabled:opacity-50"
                      />
                      <span>Enabled / Evaluate Rule Live</span>
                    </label>
                  </div>
                </div>

                <div>
                  <label className="mb-1 block font-bold text-[var(--text-muted)]">Summary Template</label>
                  <input
                    type="text"
                    value={formSummaryTemplate}
                    onChange={(e) => setFormSummaryTemplate(e.target.value)}
                    disabled={!isEditing}
                    placeholder="Action {tool}.{action} denied: triggered by untrusted provenance"
                    className="w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50"
                  />
                  <span className="mt-0.5 block text-[10px] text-[var(--text-muted)]">
                    Supported placeholders: {"{tool}"}, {"{action}"}, {"{decision}"}, {"{reason}"},{" "}
                    {"{agent_id}"}, {"{tenant_id}"}.
                  </span>
                </div>

                <div>
                  <label className="mb-1 block font-bold text-[var(--text-muted)]">
                    Rule Condition (YAML Specification)
                  </label>
                  {selectedRule?.source === "default" ? (
                    <pre className="overflow-x-auto rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-3 font-mono text-[11px] text-[var(--text-secondary)]">
                      {formCondition}
                    </pre>
                  ) : (
                    <textarea
                      rows={6}
                      value={formCondition}
                      onChange={(e) => setFormCondition(e.target.value)}
                      disabled={!isEditing}
                      placeholder={
                        "event_type: authorize_decision\ndecision: deny\nmutating: true\ncontext_trust: [untrusted_external, malicious_suspected]"
                      }
                      className="custom-scrollbar w-full rounded-md border border-[var(--border-default)] bg-[var(--surface-app)] p-3 font-mono text-[11px] leading-relaxed text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                    />
                  )}
                  {isEditing && (
                    <span className="mt-0.5 block text-[10px] text-[var(--text-muted)]">
                      Specify filters (event_type, decision, tool, action, context_trust: [...], mutating:
                      true/false, min_risk_score, max_risk_score, matched_policy_contains: [...]) using
                      standard YAML block format. Risk score bounds are advisory-only.
                    </span>
                  )}
                </div>
              </form>

              {!isCreatingNew && (
                <div className="space-y-4 border-t border-[var(--border-default)] pt-5">
                  <div className="flex flex-col justify-between gap-3 md:flex-row md:items-center">
                    <div>
                      <h4 className="flex items-center gap-1.5 text-xs font-bold text-[var(--text-primary)]">
                        <Activity size={14} className="text-[var(--brand)]" /> Historical Decision Backtesting
                      </h4>
                      <p className="mt-0.5 text-[11px] text-[var(--text-muted)]">
                        Evaluate rule matches over historical decisions in memory without affecting live
                        pipelines.
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <div className="flex items-center gap-1">
                        <span className="font-mono text-[10px] text-[var(--text-muted)]">From:</span>
                        <input
                          type="datetime-local"
                          value={backtestFrom}
                          onChange={(e) => setBacktestFrom(e.target.value)}
                          className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1 text-[10px] text-[var(--text-primary)] focus:outline-none"
                        />
                      </div>
                      <div className="flex items-center gap-1">
                        <span className="font-mono text-[10px] text-[var(--text-muted)]">To:</span>
                        <input
                          type="datetime-local"
                          value={backtestTo}
                          onChange={(e) => setBacktestTo(e.target.value)}
                          className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1 text-[10px] text-[var(--text-primary)] focus:outline-none"
                        />
                      </div>
                      <button
                        type="button"
                        onClick={handleRunBacktest}
                        disabled={isBacktesting}
                        className="flex cursor-pointer items-center gap-1 rounded bg-[var(--brand)] px-3.5 py-1.5 text-[10px] font-bold text-white transition-colors hover:bg-[var(--brand-emphasis)] disabled:opacity-50"
                      >
                        <Play size={10} /> {isBacktesting ? "Simulating..." : "Run Simulator"}
                      </button>
                    </div>
                  </div>

                  {backtestError && (
                    <div className="animate-fadeIn flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-950/20 p-3 font-mono text-[11px] text-red-400">
                      <AlertCircle size={14} className="shrink-0" />
                      <span>{backtestError}</span>
                    </div>
                  )}

                  {backtestResult && (
                    <div className="animate-fadeIn space-y-4 rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/70 p-4">
                      <div className="grid grid-cols-1 gap-3 text-center sm:grid-cols-3">
                        <div className="rounded border border-[var(--border-default)]/75 bg-[var(--surface-panel)]/80 p-3">
                          <span className="block text-[9px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
                            Decisions Scanned
                          </span>
                          <span className="text-lg font-extrabold text-[var(--text-primary)]">
                            {backtestResult.decisions_scanned}
                          </span>
                        </div>
                        <div className="rounded border border-[var(--border-default)]/75 bg-[var(--surface-panel)]/80 p-3">
                          <span className="block text-[9px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
                            Match Count
                          </span>
                          <span
                            className={`text-lg font-extrabold ${
                              backtestResult.match_count > 0 ? "text-amber-400" : "text-green-400"
                            }`}
                          >
                            {backtestResult.match_count}
                          </span>
                        </div>
                        <div className="rounded border border-[var(--border-default)]/75 bg-[var(--surface-panel)]/80 p-3">
                          <span className="block text-[9px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
                            Est. Daily Volume
                          </span>
                          <span className="text-lg font-extrabold text-[var(--brand)]">
                            {Number(backtestResult.estimated_daily_alert_volume).toFixed(3)} / day
                          </span>
                        </div>
                      </div>

                      {backtestResult.matched_decision_ids &&
                      backtestResult.matched_decision_ids.length > 0 ? (
                        <div className="space-y-1.5">
                          <span className="block text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
                            Matched Decision IDs
                          </span>
                          <div className="custom-scrollbar flex max-h-32 flex-wrap gap-1.5 overflow-y-auto rounded border border-[var(--border-default)] bg-[var(--surface-panel)]/50 p-2.5">
                            {backtestResult.matched_decision_ids.map((id: string) => (
                              <span
                                key={id}
                                className="cursor-default select-all rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-0.5 font-mono text-[10px] text-[var(--brand)] hover:border-[var(--border-active)]"
                              >
                                {id}
                              </span>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <p className="py-2 text-center text-[11px] italic text-[var(--text-muted)]">
                          Simulator scanned decisions cleanly. No matches detected.
                        </p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="panel-card flex flex-col items-center justify-center py-20 text-center text-[var(--text-muted)]">
              <ShieldAlert size={36} className="mb-2 text-[var(--border-default)]" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
                Select a Rule
              </h4>
              <p className="mt-1 max-w-sm text-[11px]">
                Select a default built-in or tenant custom rule from the catalog to view conditions, modify
                parameters, or run a historical backtest simulation.
              </p>
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={deleteConfirmOpen}
        title="Delete this custom detection rule?"
        impact="This removes the custom deterministic rule from the gateway catalogue. Existing alerts and receipts remain as evidence, but the rule will no longer fire."
        target={selectedRule ? `${selectedRule.rule_key} · ${selectedRule.name}` : ""}
        reason={deleteReason}
        onReasonChange={setDeleteReason}
        confirmLabel="Delete custom rule"
        confirmDisabled={!deleteReason.trim() || deleteRuleMutation.isPending}
        onConfirm={confirmDelete}
        onCancel={() => {
          setDeleteConfirmOpen(false);
          setDeleteReason("");
        }}
      />
    </div>
  );
}