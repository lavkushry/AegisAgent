"use client";

import React from "react";
import { Settings, Shield, Sliders, Volume2, Database, Info } from "lucide-react";

export default function SettingsTab() {
  return (
    <div className="space-y-6">
      {/* Access Control & RBAC Role Information */}
      <div className="panel-card space-y-4">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3">
          <Shield size={14} className="text-[var(--brand)]" /> Role-Based Access Control (RBAC)
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
          <div className="bg-[var(--surface-app)]/30 p-3 rounded-lg border border-[var(--border-default)]">
            <span className="font-bold text-[var(--text-primary)]">Viewer</span>
            <p className="text-[var(--text-muted)] mt-1">Read-only access to decision records, incidents, and receipts logs.</p>
          </div>
          <div className="bg-[var(--surface-app)]/30 p-3 rounded-lg border border-[var(--border-default)]">
            <span className="font-bold text-blue-400">Analyst</span>
            <p className="text-[var(--text-muted)] mt-1">Inspects incidents, triggers agent containment actions, and silences alerts.</p>
          </div>
          <div className="bg-[var(--surface-app)]/30 p-3 rounded-lg border border-[var(--border-default)]">
            <span className="font-bold text-amber-400">Approver</span>
            <p className="text-[var(--text-muted)] mt-1">Authorizes pending actions inside the human-in-the-loop approvals queue.</p>
          </div>
          <div className="bg-[var(--surface-app)]/30 p-3 rounded-lg border border-[var(--border-default)]">
            <span className="font-bold text-[var(--brand)]">Admin</span>
            <p className="text-[var(--text-muted)] mt-1">Full control over settings, tenant configurations, and custom detection rules.</p>
          </div>
        </div>
      </div>

      {/* Notification Sinks & Contact Points */}
      <div className="panel-card space-y-4">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3">
          <Volume2 size={14} className="text-[var(--brand)]" /> Notification Contact Points
        </h3>
        
        <div className="space-y-3 text-xs">
          <div className="flex justify-between items-center p-3 bg-[var(--surface-app)]/20 border border-[var(--border-default)] rounded-lg">
            <div>
              <span className="font-semibold text-[var(--text-primary)]">Slack Integrations</span>
              <p className="text-[var(--text-muted)] mt-0.5">Route alerts to Slack channels via incoming webhooks.</p>
            </div>
            <span className="text-[10px] text-green-400 bg-green-950/20 border border-green-500/20 px-2 py-0.5 rounded font-mono">ENABLED</span>
          </div>

          <div className="flex justify-between items-center p-3 bg-[var(--surface-app)]/20 border border-[var(--border-default)] rounded-lg">
            <div>
              <span className="font-semibold text-[var(--text-primary)]">PagerDuty Incident Desk</span>
              <p className="text-[var(--text-muted)] mt-0.5">Auto-create service incidents on critical policy violations.</p>
            </div>
            <span className="text-[10px] text-[var(--text-muted)] bg-[var(--border-default)]/20 border border-[var(--border-default)]/20 px-2 py-0.5 rounded font-mono">STANDBY</span>
          </div>
        </div>
      </div>

      {/* System info & Tuning parameters */}
      <div className="panel-card space-y-4">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5 border-b border-[var(--border-default)] pb-3">
          <Database size={14} className="text-[var(--brand)]" /> System Tuning Pragmas
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono text-[var(--text-secondary)]">
          <div className="bg-[var(--surface-app)]/20 border border-[var(--border-default)] rounded-lg p-3 space-y-1">
            <span className="text-[var(--text-muted)] font-sans font-bold uppercase text-[9px] block">Database Engine</span>
            <span className="text-[var(--text-primary)]">SQLite v3.x (with WAL journal checkpointing)</span>
          </div>
          <div className="bg-[var(--surface-app)]/20 border border-[var(--border-default)] rounded-lg p-3 space-y-1">
            <span className="text-[var(--text-muted)] font-sans font-bold uppercase text-[9px] block">OpenTelemetry Tracing</span>
            <span className="text-[var(--text-primary)]">OTLP Span Exporter: INERT</span>
          </div>
        </div>
      </div>
    </div>
  );
}
