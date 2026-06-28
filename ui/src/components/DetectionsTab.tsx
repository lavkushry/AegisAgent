"use client";

import React, { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import {
  getAlerts,
  getSocRules,
  getDetectionRules,
  createSocRule,
  deleteDetectionRule,
  backtestSocRule,
  UpsertRulePayload,
  type BacktestResult,
  type SocRuleRecord,
} from "../app/api";
import { errorMessage } from "@/lib/format";
import {
  ShieldAlert,
  Plus,
  Play,
  Check,
  ChevronDown,
  ChevronUp,
  Search,
  Filter,
  AlertCircle,
  Terminal,
  Activity,
  Trash2,
  AlertTriangle
} from "lucide-react";

// Local helper to format RuleCondition JSON object to a YAML-like string for display
function jsonToYaml(obj: unknown): string {
  if (!obj) return "";
  if (typeof obj === "string") return obj;
  if (typeof obj !== "object") return String(obj);

  const formatValue = (val: unknown): string => {
    if (typeof val === "string") {
      if (/[\s:#[\]{}]/.test(val)) {
        return JSON.stringify(val);
      }
      return val;
    }
    return String(val);
  };

  const lines: string[] = [];
  for (const [key, val] of Object.entries(obj)) {
    if (val === undefined || val === null) continue;
    if (Array.isArray(val)) {
      if (val.length === 0) {
        lines.push(`${key}: []`);
      } else {
        lines.push(`${key}:`);
        for (const item of val) {
          lines.push(`  - ${formatValue(item)}`);
        }
      }
    } else if (typeof val === "object") {
      lines.push(`${key}:`);
      const sub = jsonToYaml(val);
      for (const subline of sub.split("\n")) {
        if (subline) lines.push(`  ${subline}`);
      }
    } else {
      lines.push(`${key}: ${formatValue(val)}`);
    }
  }
  return lines.join("\n");
}

export default function DetectionsTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [subTab, setSubTab] = useState<"alerts" | "rules">("alerts");
  
  // Alerts filters
  const [alertSearch, setAlertSearch] = useState("");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("all");
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  // Selected rule state
  const [selectedRuleKey, setSelectedRuleKey] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [isCreatingNew, setIsCreatingNew] = useState(false);

  // Custom rule form inputs
  const [formRuleKey, setFormRuleKey] = useState("");
  const [formName, setFormName] = useState("");
  const [formSeverity, setFormSeverity] = useState("medium");
  const [formCondition, setFormCondition] = useState("");
  const [formSummaryTemplate, setFormSummaryTemplate] = useState("");
  const [formEnabled, setFormEnabled] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);

  // Backtest parameters
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

  // Fetch Alerts (Active Detections)
  const { data: alerts, isLoading: loadingAlerts, error: alertsError } = useQuery({
    queryKey: ["alerts", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getAlerts(apiOpts, 100),
    refetchInterval: 5000, // Poll every 5s for live alerts feed
  });

  // Fetch Effective Rules (what's active on the gateway)
  const { data: effectiveRules, isLoading: loadingEffective } = useQuery({
    queryKey: ["socRules", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getSocRules(apiOpts),
  });

  // Fetch Custom Rules (to retrieve DB record ID and status including disabled rules)
  const { data: customRules, isLoading: loadingCustom } = useQuery({
    queryKey: ["customRules", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getDetectionRules(apiOpts),
  });

  // Consolidate the catalogue of default and custom rules
  const catalog = useMemo(() => {
    if (!effectiveRules) return [];
    
    // Map effective rules (defaults + enabled custom rules)
    const list = effectiveRules.map(r => ({
      rule_key: r.rule_key,
      name: r.name,
      severity: r.severity,
      condition: r.condition,
      summary_template: r.summary_template,
      source: r.source || "default",
      enabled: true,
      dbId: undefined as string | undefined
    }));

    // Find and attach database IDs, and identify disabled custom rules
    if (customRules) {
      for (const cr of customRules) {
        const match = list.find(r => r.rule_key === cr.rule_key);
        if (match) {
          match.dbId = cr.id;
          match.enabled = cr.enabled;
        } else if (!cr.enabled) {
          // Rule is custom and disabled
          list.push({
            rule_key: cr.rule_key,
            name: cr.name,
            severity: cr.severity,
            condition: cr.condition, // Already a string format in CustomRules
            summary_template: cr.summary_template,
            source: "custom",
            enabled: false,
            dbId: cr.id
          });
        }
      }
    }
    return list;
  }, [effectiveRules, customRules]);

  // Find currently selected rule from catalog
  const selectedRule = useMemo(() => {
    if (!selectedRuleKey) return null;
    return catalog.find(r => r.rule_key === selectedRuleKey) || null;
  }, [catalog, selectedRuleKey]);

  const selectRule = (rule: SocRuleRecord & { dbId?: string }) => {
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

  // Filter alerts client-side for immediate responsiveness
  const filteredAlerts = useMemo(() => {
    if (!alerts) return [];
    return alerts.filter(a => {
      const severityMatch = alertSeverityFilter === "all" || a.severity.toLowerCase() === alertSeverityFilter.toLowerCase();
      const q = alertSearch.toLowerCase();
      const searchMatch = !alertSearch ||
        a.rule.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.agent_id.toLowerCase().includes(q) ||
        a.alert_id.toLowerCase().includes(q);
      return severityMatch && searchMatch;
    });
  }, [alerts, alertSearch, alertSeverityFilter]);

  // Save (Create/Update) Custom Rule Mutation
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
    }
  });

  // Delete Custom Rule Mutation
  const deleteRuleMutation = useMutation({
    mutationFn: (ruleId: string) => deleteDetectionRule(apiOpts, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["socRules"] });
      queryClient.invalidateQueries({ queryKey: ["customRules"] });
      setSelectedRuleKey(null);
      setIsEditing(false);
      setIsCreatingNew(false);
      setFormSuccess("Custom rule deleted successfully.");
      setFormError(null);
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err) || "Failed to delete rule.");
      setFormSuccess(null);
    }
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
      enabled: formEnabled
    });
  };

  const handleDelete = () => {
    if (!selectedRule || !selectedRule.dbId) return;
    if (confirm(`Are you sure you want to permanently delete custom rule '${selectedRule.rule_key}'?`)) {
      deleteRuleMutation.mutate(selectedRule.dbId);
    }
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

  const getSeverityStyle = (severity: string) => {
    switch (String(severity).toLowerCase()) {
      case "high":
        return {
          badge: "bg-red-500/20 border border-red-500/40 text-red-400",
          card: "border-l-4 border-l-red-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]"
        };
      case "medium":
        return {
          badge: "bg-amber-500/20 border border-amber-500/40 text-amber-400",
          card: "border-l-4 border-l-amber-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]"
        };
      case "low":
        return {
          badge: "bg-yellow-500/20 border border-yellow-500/40 text-yellow-400",
          card: "border-l-4 border-l-yellow-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]"
        };
      case "info":
        return {
          badge: "bg-blue-500/20 border border-blue-500/40 text-blue-400",
          card: "border-l-4 border-l-blue-500 bg-[var(--surface-panel)] hover:bg-[var(--surface-elevated)] border-r border-y border-[var(--border-default)]"
        };
      default:
        return {
          badge: "bg-slate-500/20 border border-slate-500/40 text-slate-400",
          card: "border-l-4 border-l-slate-500 bg-[var(--surface-panel)]/40 hover:bg-[var(--border-default)]/50 border-r border-y border-[var(--border-default)]"
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub-tab Pill navigation */}
      <div className="flex gap-2 bg-[var(--surface-app)] p-1 rounded-lg w-fit border border-[var(--border-default)]">
        <button
          onClick={() => { setSubTab("alerts"); setFormError(null); setFormSuccess(null); }}
          className={`px-4 py-1.5 rounded-md text-xs font-semibold tracking-wide transition-all cursor-pointer flex items-center gap-2 ${
            subTab === "alerts"
              ? "bg-[var(--brand)] text-white font-bold"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          <ShieldAlert size={14} />
          Active Alerts
          {alerts && alerts.length > 0 && (
            <span className="bg-red-500 text-white text-[9px] px-1.5 py-0.5 rounded-full font-bold ml-1">
              {alerts.length}
            </span>
          )}
        </button>
        <button
          onClick={() => { setSubTab("rules"); setFormError(null); setFormSuccess(null); }}
          className={`px-4 py-1.5 rounded-md text-xs font-semibold tracking-wide transition-all cursor-pointer flex items-center gap-2 ${
            subTab === "rules"
              ? "bg-[var(--brand)] text-white font-bold"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          <Terminal size={14} />
          Detection Rules & Backtesting
        </button>
      </div>

      {/* Tab Content: Active Alerts */}
      {subTab === "alerts" && (
        <div className="space-y-4 animate-fadeIn">
          {/* Filters Bar */}
          <div className="flex flex-col md:flex-row gap-3 items-center bg-[var(--surface-panel)] p-3 rounded-lg border border-[var(--border-default)]">
            <div className="relative flex-1 w-full">
              <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={16} />
              <input
                type="text"
                value={alertSearch}
                onChange={(e) => setAlertSearch(e.target.value)}
                placeholder="Search alerts by rule, agent ID, summary..."
                className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md pl-10 pr-4 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none"
              />
            </div>
            <div className="flex items-center gap-2 w-full md:w-auto">
              <Filter className="text-[var(--text-muted)] shrink-0" size={14} />
              <select
                value={alertSeverityFilter}
                onChange={(e) => setAlertSeverityFilter(e.target.value)}
                className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none w-full md:w-40"
              >
                <option value="all">All Severities</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>

          {/* Alerts List */}
          <div className="panel-card space-y-3">
            <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Triggered Detections Log
            </h3>

            {loadingAlerts ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-10">Fetching active alerts...</p>
            ) : alertsError ? (
              <div className="flex items-center gap-2 text-red-400 bg-red-950/20 border border-red-500/20 p-4 rounded-lg text-xs">
                <AlertCircle size={16} />
                <span>Error fetching alerts: {errorMessage(alertsError)}</span>
              </div>
            ) : filteredAlerts.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-12">No active alerts matched the filter conditions.</p>
            ) : (
              <div className="space-y-2">
                {filteredAlerts.map((alert) => {
                  const isExpanded = expandedAlertId === alert.alert_id;
                  const severityStyle = getSeverityStyle(alert.severity);

                  return (
                    <div
                      key={alert.alert_id}
                      className={`rounded-lg overflow-hidden border border-[var(--border-default)] transition-all ${severityStyle.card}`}
                    >
                      <div
                        onClick={() => setExpandedAlertId(isExpanded ? null : alert.alert_id)}
                        className="flex flex-wrap md:flex-nowrap items-center justify-between gap-4 p-4 cursor-pointer select-none"
                      >
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${severityStyle.badge}`}>
                            {alert.severity.toUpperCase()}
                          </span>
                          <div className="flex flex-col">
                            <span className="text-xs font-mono font-bold text-[var(--brand)]">
                              {alert.rule}
                            </span>
                            <span className="text-[10px] text-[var(--text-muted)] mt-0.5 font-mono">
                              Agent: {alert.agent_id} &middot; Occurred: {new Date(alert.occurred_at).toLocaleString()}
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 text-xs font-medium text-[var(--text-primary)]">
                          <span className="truncate max-w-[280px] md:max-w-md text-[var(--text-secondary)] italic">
                            {alert.summary}
                          </span>
                          {isExpanded ? <ChevronUp size={16} className="text-[var(--text-muted)]" /> : <ChevronDown size={16} className="text-[var(--text-muted)]" />}
                        </div>
                      </div>

                      {/* Expanded alert details */}
                      {isExpanded && (
                        <div className="border-t border-[var(--border-default)] bg-[var(--surface-app)] p-4 text-xs font-mono space-y-3">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                              <span className="text-[var(--text-muted)] block text-[10px] uppercase font-sans font-bold">Alert ID</span>
                              <span className="text-[var(--text-primary)] select-all">{alert.alert_id}</span>
                            </div>
                            <div>
                              <span className="text-[var(--text-muted)] block text-[10px] uppercase font-sans font-bold">Source Event ID</span>
                              <span className="text-[var(--text-primary)] select-all">{alert.source_event_id}</span>
                            </div>
                          </div>
                          <div>
                            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-sans font-bold mb-1">Full Summary</span>
                            <p className="text-[var(--text-primary)] font-sans leading-relaxed bg-[var(--surface-app)] p-2.5 rounded border border-[var(--border-default)]">
                              {alert.summary}
                            </p>
                          </div>
                          <div>
                            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-sans font-bold mb-1">Raw Alert Record</span>
                            <pre className="bg-[var(--surface-app)] text-[var(--brand)] p-3 rounded overflow-x-auto text-[11px] border border-[var(--border-default)] max-h-60 custom-scrollbar">
                              {JSON.stringify(alert, null, 2)}
                            </pre>
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
      )}

      {/* Tab Content: Detection Rules & Backtester */}
      {subTab === "rules" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 animate-fadeIn">
          {/* Left Column: Catalogue */}
          <div className="lg:col-span-4 panel-card flex flex-col space-y-4">
            <div className="flex justify-between items-center border-b border-[var(--border-default)] pb-3">
              <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                <Terminal size={14} className="text-[var(--brand)]" /> Rules Catalogue
              </h3>
              <button
                onClick={handleCreateNew}
                className="bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-white font-bold text-[10px] px-2.5 py-1 rounded transition-colors flex items-center gap-1 cursor-pointer"
              >
                <Plus size={12} /> Add Rule
              </button>
            </div>

            {loadingEffective || loadingCustom ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-10">Loading catalog...</p>
            ) : catalog.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-10">No rules registered.</p>
            ) : (
              <div className="space-y-2 overflow-y-auto max-h-[600px] pr-1 custom-scrollbar">
                {catalog.map((rule) => {
                  const isSelected = selectedRuleKey === rule.rule_key;
                  const sevStyle = getSeverityStyle(rule.severity);
                  return (
                    <div
                      key={rule.rule_key}
                      onClick={() => selectRule(rule)}
                      className={`p-3 rounded-lg border cursor-pointer select-none transition-all flex flex-col gap-1.5 ${
                        isSelected
                          ? "bg-[var(--border-default)]/80 border-[var(--border-active)] ring-1 ring-[var(--border-focus)]"
                          : "bg-[var(--surface-app)]/40 border-[var(--border-default)] hover:border-[var(--border-default)]"
                      }`}
                    >
                      <div className="flex justify-between items-center">
                        <span className="text-xs font-mono font-bold text-[var(--brand)] truncate max-w-[170px]">
                          {rule.rule_key}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <span className={`px-1.5 py-0.2 text-[9px] rounded font-bold uppercase font-sans ${sevStyle.badge}`}>
                            {rule.severity}
                          </span>
                        </div>
                      </div>

                      <span className="text-[11px] text-[var(--text-secondary)] line-clamp-1 italic">
                        {rule.name}
                      </span>

                      <div className="flex justify-between items-center text-[10px] text-[var(--text-muted)] font-mono mt-1 border-t border-[var(--border-default)]/50 pt-1.5">
                        <span className={`uppercase font-sans font-bold ${
                          rule.source === "default" ? "text-[var(--brand)]" : "text-amber-500"
                        }`}>
                          {rule.source}
                        </span>
                        <span className={`flex items-center gap-1 font-bold ${
                          rule.enabled ? "text-green-500" : "text-red-400"
                        }`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${
                            rule.enabled ? "bg-green-500 animate-pulse" : "bg-red-400"
                          }`} />
                          {rule.enabled ? "ACTIVE" : "DISABLED"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Rule Details, Editor, and Backtester */}
          <div className="lg:col-span-8 space-y-6">
            {/* Form Success/Error notifications */}
            {formSuccess && (
              <div className="flex items-center gap-2 text-green-400 bg-green-950/20 border border-green-500/20 p-3 rounded-lg text-xs animate-fadeIn">
                <Check size={16} />
                <span>{formSuccess}</span>
              </div>
            )}
            {formError && (
              <div className="flex items-start gap-2 text-red-400 bg-red-950/20 border border-red-500/20 p-3 rounded-lg text-xs animate-fadeIn">
                <AlertTriangle size={16} className="shrink-0 mt-0.5" />
                <div className="flex-1 space-y-1">
                  <span className="font-bold">Rule Validation Refused:</span>
                  <p className="font-mono whitespace-pre-wrap">{formError}</p>
                </div>
              </div>
            )}

            {/* Selected Rule Panel */}
            {selectedRule || isCreatingNew ? (
              <div className="panel-card space-y-6">
                <div className="flex justify-between items-center border-b border-[var(--border-default)] pb-3 flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-[var(--text-primary)] font-mono">
                      {isCreatingNew ? "New Custom Detection Rule" : selectedRule?.rule_key}
                    </h3>
                    {!isCreatingNew && (
                      <span className={`px-2 py-0.5 text-[10px] rounded uppercase font-bold ${
                        selectedRule?.source === "default"
                          ? "bg-[var(--brand)]/10 border border-[var(--border-active)]/20 text-[var(--brand)]"
                          : "bg-amber-500/10 border border-amber-500/20 text-amber-400"
                      }`}>
                        {selectedRule?.source}
                      </span>
                    )}
                  </div>
                  <div className="flex gap-2">
                    {!isEditing && selectedRule?.source === "custom" && (
                      <button
                        onClick={() => setIsEditing(true)}
                        className="bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-white font-bold text-xs px-4 py-1.5 rounded transition-colors cursor-pointer"
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
                          className="bg-[var(--border-default)] hover:bg-[var(--border-default)] text-[var(--text-primary)] font-bold text-xs px-4 py-1.5 rounded transition-colors cursor-pointer"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={handleSave}
                          disabled={saveRuleMutation.isPending}
                          className="bg-green-600 hover:bg-green-700 text-white font-bold text-xs px-4 py-1.5 rounded transition-colors disabled:opacity-50 cursor-pointer"
                        >
                          {saveRuleMutation.isPending ? "Validating & Saving..." : "Save Rule"}
                        </button>
                      </>
                    )}
                    {!isEditing && selectedRule?.source === "custom" && selectedRule?.dbId && (
                      <button
                        onClick={handleDelete}
                        disabled={deleteRuleMutation.isPending}
                        className="bg-red-950/40 hover:bg-red-900/60 border border-red-500/30 hover:border-red-500/60 text-red-400 font-bold text-xs px-3 py-1.5 rounded transition-colors flex items-center gap-1 disabled:opacity-50 cursor-pointer"
                      >
                        <Trash2 size={13} /> Delete
                      </button>
                    )}
                  </div>
                </div>

                {/* Rule Form */}
                <form onSubmit={handleSave} className="space-y-4 text-xs">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-[var(--text-muted)] font-bold block mb-1">Rule Key</label>
                      <input
                        type="text"
                        value={formRuleKey}
                        onChange={(e) => setFormRuleKey(e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, ""))}
                        disabled={!isCreatingNew}
                        placeholder="e.g. mutating_critical_action"
                        className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed font-mono"
                      />
                      <span className="text-[10px] text-[var(--text-muted)] mt-0.5 block">Unique identifier. Lowercase, numbers, underscores only.</span>
                    </div>
                    <div>
                      <label className="text-[var(--text-muted)] font-bold block mb-1">Rule Name (Fired Alert Rule Value)</label>
                      <input
                        type="text"
                        value={formName}
                        onChange={(e) => setFormName(e.target.value)}
                        disabled={!isEditing}
                        placeholder="e.g. confused_deputy_block"
                        className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-[var(--text-muted)] font-bold block mb-1">Severity</label>
                      <select
                        value={formSeverity}
                        onChange={(e) => setFormSeverity(e.target.value)}
                        disabled={!isEditing}
                        className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50"
                      >
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                      </select>
                    </div>
                    <div className="flex items-center pt-5">
                      <label className="flex items-center gap-2 font-bold text-[var(--text-primary)] cursor-pointer select-none">
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
                    <label className="text-[var(--text-muted)] font-bold block mb-1">Summary Template</label>
                    <input
                      type="text"
                      value={formSummaryTemplate}
                      onChange={(e) => setFormSummaryTemplate(e.target.value)}
                      disabled={!isEditing}
                      placeholder="Action {tool}.{action} denied: triggered by untrusted provenance"
                      className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md px-3 py-2 text-xs text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50"
                    />
                    <span className="text-[10px] text-[var(--text-muted)] mt-0.5 block">Supported placeholders: {"{tool}"}, {"{action}"}, {"{decision}"}, {"{reason}"}, {"{agent_id}"}, {"{tenant_id}"}.</span>
                  </div>

                  <div>
                    <label className="text-[var(--text-muted)] font-bold block mb-1">Rule Condition (YAML Specification)</label>
                    {selectedRule?.source === "default" ? (
                      <pre className="bg-[var(--surface-app)] text-[var(--text-secondary)] p-3 rounded border border-[var(--border-default)] font-mono text-[11px] overflow-x-auto">
                        {formCondition}
                      </pre>
                    ) : (
                      <div className="relative">
                        <textarea
                          rows={6}
                          value={formCondition}
                          onChange={(e) => setFormCondition(e.target.value)}
                          disabled={!isEditing}
                          placeholder="event_type: authorize_decision&#10;decision: deny&#10;mutating: true&#10;context_trust: [untrusted_external, malicious_suspected]"
                          className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-md p-3 font-mono text-[11px] text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed leading-relaxed custom-scrollbar"
                        />
                      </div>
                    )}
                    {isEditing && (
                      <span className="text-[10px] text-[var(--text-muted)] mt-0.5 block">
                        Specify filters (event_type, decision, tool, action, context_trust: [...], mutating: true/false, min_risk_score, max_risk_score, matched_policy_contains: [...]) using standard YAML block format.
                      </span>
                    )}
                  </div>
                </form>

                {/* Backtesting Sub-panel */}
                {!isCreatingNew && (
                  <div className="border-t border-[var(--border-default)] pt-5 space-y-4">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                      <div>
                        <h4 className="text-xs font-bold text-[var(--text-primary)] flex items-center gap-1.5">
                          <Activity size={14} className="text-[var(--brand)]" /> Historical Decision Backtesting
                        </h4>
                        <p className="text-[11px] text-[var(--text-muted)] mt-0.5">Evaluate rule matches over historical decisions in memory without affecting live pipelines.</p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="flex items-center gap-1">
                          <span className="text-[10px] text-[var(--text-muted)] font-mono">From:</span>
                          <input
                            type="datetime-local"
                            value={backtestFrom}
                            onChange={(e) => setBacktestFrom(e.target.value)}
                            className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded px-2 py-1 text-[10px] text-[var(--text-primary)] focus:outline-none"
                          />
                        </div>
                        <div className="flex items-center gap-1">
                          <span className="text-[10px] text-[var(--text-muted)] font-mono">To:</span>
                          <input
                            type="datetime-local"
                            value={backtestTo}
                            onChange={(e) => setBacktestTo(e.target.value)}
                            className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded px-2 py-1 text-[10px] text-[var(--text-primary)] focus:outline-none"
                          />
                        </div>
                        <button
                          type="button"
                          onClick={handleRunBacktest}
                          disabled={isBacktesting}
                          className="bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-white text-[10px] px-3.5 py-1.5 rounded transition-colors flex items-center gap-1 font-bold disabled:opacity-50 cursor-pointer"
                        >
                          <Play size={10} /> {isBacktesting ? "Simulating..." : "Run Simulator"}
                        </button>
                      </div>
                    </div>

                    {backtestError && (
                      <div className="flex items-center gap-2 text-red-400 bg-red-950/20 border border-red-500/20 p-3 rounded-lg text-[11px] font-mono animate-fadeIn">
                        <AlertCircle size={14} className="shrink-0" />
                        <span>{backtestError}</span>
                      </div>
                    )}

                    {/* Backtest Result Output */}
                    {backtestResult && (
                      <div className="bg-[var(--surface-app)]/70 rounded-lg p-4 border border-[var(--border-default)] space-y-4 animate-fadeIn">
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-center">
                          <div className="bg-[var(--surface-panel)]/80 rounded p-3 border border-[var(--border-default)]/75">
                            <span className="text-[9px] uppercase font-bold text-[var(--text-muted)] tracking-wider block">Decisions Scanned</span>
                            <span className="text-lg font-extrabold text-[var(--text-primary)]">{backtestResult.decisions_scanned}</span>
                          </div>
                          <div className="bg-[var(--surface-panel)]/80 rounded p-3 border border-[var(--border-default)]/75">
                            <span className="text-[9px] uppercase font-bold text-[var(--text-muted)] tracking-wider block">Match Count</span>
                            <span className={`text-lg font-extrabold ${
                              backtestResult.match_count > 0 ? "text-amber-400" : "text-green-400"
                            }`}>{backtestResult.match_count}</span>
                          </div>
                          <div className="bg-[var(--surface-panel)]/80 rounded p-3 border border-[var(--border-default)]/75">
                            <span className="text-[9px] uppercase font-bold text-[var(--text-muted)] tracking-wider block">Est. Daily Volume</span>
                            <span className="text-lg font-extrabold text-[var(--brand)]">
                              {Number(backtestResult.estimated_daily_alert_volume).toFixed(3)} / day
                            </span>
                          </div>
                        </div>

                        {backtestResult.matched_decision_ids && backtestResult.matched_decision_ids.length > 0 ? (
                          <div className="space-y-1.5">
                            <span className="text-[10px] uppercase font-bold text-[var(--text-muted)] tracking-wider block">Matched Decision IDs</span>
                            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto custom-scrollbar bg-[var(--surface-panel)]/50 p-2.5 rounded border border-[var(--border-default)]">
                              {backtestResult.matched_decision_ids.map((id: string) => (
                                <span
                                  key={id}
                                  className="px-2 py-0.5 bg-[var(--surface-app)] text-[var(--brand)] rounded font-mono text-[10px] border border-[var(--border-default)] hover:border-[var(--border-active)] cursor-default select-all"
                                >
                                  {id}
                                </span>
                              ))}
                            </div>
                          </div>
                        ) : (
                          <p className="text-[11px] text-[var(--text-muted)] italic text-center py-2">
                            Simulator scanned decisions cleanly. No matches detected.
                          </p>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="panel-card flex flex-col items-center justify-center text-center py-20 text-[var(--text-muted)]">
                <ShieldAlert size={36} className="text-[var(--border-default)] mb-2" />
                <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">Select a Rule</h4>
                <p className="text-[11px] max-w-sm mt-1">Select a default built-in or tenant custom rule from the catalog to view conditions, modify parameters, or run a historical backtest simulation.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
