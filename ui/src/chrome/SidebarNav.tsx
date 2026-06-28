"use client";

import { AlertOctagon, Clock, FileCheck2, Fingerprint, LayoutDashboard, LayoutGrid, Search, Server, Settings, Shield, ShieldAlert, Users } from "lucide-react";
import { useAppStore } from "@/app/store";
import type { ConsoleView } from "@/state/consoleUrl";

const NAV_ITEMS = [
  ["overview", "Overview", LayoutDashboard], ["dashboards", "Dashboards", LayoutGrid],
  ["integrity", "Integrity Console", Fingerprint], ["explore", "Explore", Search],
  ["incidents", "Incidents", AlertOctagon], ["detections", "Detections & Rules", ShieldAlert],
  ["approvals", "Approvals", Clock], ["agents", "Agents Fleet", Users],
  ["mcp", "MCP Servers", Server], ["receipts", "Receipts Log", FileCheck2],
  ["settings", "Settings", Settings],
] as const;

export default function SidebarNav() {
  const activeView = useAppStore((state) => state.activeView);
  const setActiveView = useAppStore((state) => state.setActiveView);
  const activeTenant = useAppStore((state) => state.activeTenant);
  return (
    <aside className="flex w-full shrink-0 flex-col border-b border-[var(--border-default)] bg-[var(--surface-app)] p-4 md:min-h-screen md:w-64 md:border-b-0 md:border-r md:p-5">
      <div className="mb-4 flex items-center gap-2 px-2 md:mb-8"><Shield className="text-[var(--brand)]" size={24} /><div><h1 className="text-sm font-extrabold uppercase tracking-wider">AegisAgent</h1><span className="font-mono text-[10px] font-semibold tracking-wider text-[var(--text-muted)]">SOC CONSOLE</span></div></div>
      <div className="mb-3 rounded border border-[var(--border-default)] px-3 py-2 text-[10px] text-[var(--text-secondary)]"><span className="block uppercase tracking-wider text-[var(--text-muted)]">Tenant context</span><strong className="block truncate font-mono">{activeTenant || "Not selected"}</strong></div>
      <nav className="grid grid-cols-2 gap-1 md:block md:space-y-1.5" aria-label="SOC console">
        {NAV_ITEMS.map(([id, label, Icon]) => <button key={id} type="button" onClick={() => setActiveView(id as ConsoleView)} className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs font-semibold md:gap-3 md:py-2.5 ${activeView === id ? "bg-[var(--brand)] text-[var(--text-on-brand)]" : "text-[var(--text-secondary)] hover:bg-[var(--surface-panel)] hover:text-[var(--text-primary)]"}`}><Icon size={16} aria-hidden="true" />{label}</button>)}
      </nav>
      <div className="mt-auto hidden border-t border-[var(--border-default)] px-2 pt-6 font-mono text-[10px] text-[var(--text-muted)] md:block">v1.2.0-beta · 2026</div>
    </aside>
  );
}
