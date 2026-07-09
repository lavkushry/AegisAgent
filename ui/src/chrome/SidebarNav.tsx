"use client";

import { AlertOctagon, BarChart3, Beaker, Bell, Clock, FileCheck2, Fingerprint, LayoutDashboard, LayoutGrid, PencilRuler, Search, Server, Settings, Shield, ShieldAlert, Terminal, Users } from "lucide-react";
import { useAppStore } from "@/app/store";
import { DEV_HARNESS_ENABLED, DEV_HARNESS_VIEW } from "@/dev/guard";
import { useSocSummary } from "@/hooks/useSocSummary";
import type { ConsoleView } from "@/state/consoleUrl";

const NAV_ITEMS = [
  ["overview", "Overview", LayoutDashboard, null],
  ["dashboards", "Dashboards", LayoutGrid, null],
  ["integrity", "Integrity Console", Fingerprint, null],
  ["explore", "Explore", Search, null],
  ["incidents", "Incidents", AlertOctagon, "incidents_open"],
  ["detections", "Detections", ShieldAlert, "alerts_total"],
  ["rules", "Rules", Terminal, null],
  ["alerting", "Alerting", Bell, null],
  ["approvals", "Approvals", Clock, "approvals_pending"],
  ["agents", "Agents Fleet", Users, null],
  ["mcp", "MCP Servers", Server, null],
  ["receipts", "Receipts Log", FileCheck2, null],
  ["analytics", "Analytics", BarChart3, null],
  ["runtime", "Runtime Timeline", Clock, null],
  ["dashboard-editor", "Dashboard editor", PencilRuler, null],
  ["settings", "Settings", Settings, null],
] as const;

const DEV_NAV_ITEM = [DEV_HARNESS_VIEW, "Panel harness", Beaker, null] as const;

type BadgeField = "approvals_pending" | "alerts_total" | "incidents_open";

function NavBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span
      aria-hidden="true"
      className="ml-auto rounded-full bg-[var(--sev-critical)] px-1.5 py-0.5 text-[10px] font-bold tabular-nums text-white"
    >
      {count > 99 ? "99+" : count}
    </span>
  );
}

export default function SidebarNav() {
  const activeView = useAppStore((state) => state.activeView);
  const setActiveView = useAppStore((state) => state.setActiveView);
  const activeTenant = useAppStore((state) => state.activeTenant);
  const liveMode = useAppStore((state) => state.liveMode);
  const streamStatus = useAppStore((state) => state.streamStatus);
  const { data: summary } = useSocSummary();

  const badgeFor = (field: BadgeField | null) => {
    if (!field || !summary) return 0;
    return Number(summary[field] ?? 0);
  };

  const streamLabel =
    !liveMode || streamStatus === "closed"
      ? null
      : streamStatus === "live"
        ? "Live stream"
        : streamStatus === "connecting"
          ? "Connecting stream"
          : "Polling fallback";

  const streamColor =
    streamStatus === "live"
      ? "var(--state-verified)"
      : streamStatus === "connecting"
        ? "var(--state-pending)"
        : "var(--text-muted)";

  return (
    <aside className="flex w-full shrink-0 flex-col border-b border-[var(--border-default)] bg-[var(--surface-app)] p-4 md:min-h-screen md:w-64 md:border-b-0 md:border-r md:p-5">
      <div className="mb-4 flex items-center gap-2 px-2 md:mb-8">
        <Shield className="text-[var(--brand)]" size={24} />
        <div>
          <h1 className="text-sm font-extrabold uppercase tracking-wider">AegisAgent</h1>
          <span className="font-mono text-[10px] font-semibold tracking-wider text-[var(--text-muted)]">SOC CONSOLE</span>
        </div>
      </div>
      <div className="mb-3 rounded border border-[var(--border-default)] px-3 py-2 text-[10px] text-[var(--text-secondary)]">
        <span className="block uppercase tracking-wider text-[var(--text-muted)]">Tenant context</span>
        {/* activeTenant hydrates from localStorage (see app/store.ts), which
            is unavailable during SSR/static export -- the server always
            renders "Not selected" and the client corrects to the persisted
            tenant on the very first render, a one-time, intentional
            client/server text difference. */}
        <strong className="block truncate font-mono" suppressHydrationWarning>
          {activeTenant || "Not selected"}
        </strong>
        {streamLabel ? (
          <span className="mt-1 flex items-center gap-1.5 text-[var(--text-muted)]">
            <span className="inline-block h-1.5 w-1.5 rounded-full" style={{ backgroundColor: streamColor }} aria-hidden="true" />
            {streamLabel}
          </span>
        ) : null}
      </div>
      <nav className="grid grid-cols-2 gap-1 md:block md:space-y-1.5" aria-label="SOC console">
        {[...NAV_ITEMS, ...(DEV_HARNESS_ENABLED ? [DEV_NAV_ITEM] : [])].map(([id, label, Icon, badgeField]) => (
          <button
            key={id}
            type="button"
            aria-label={label}
            onClick={() => setActiveView(id as ConsoleView)}
            className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs font-semibold md:gap-3 md:py-2.5 ${
              activeView === id
                ? "bg-[var(--brand)] text-[var(--text-on-brand)]"
                : "text-[var(--text-secondary)] hover:bg-[var(--surface-panel)] hover:text-[var(--text-primary)]"
            }`}
          >
            <Icon size={16} aria-hidden="true" />
            <span className="min-w-0 flex-1 truncate">{label}</span>
            <NavBadge count={badgeFor(badgeField)} />
          </button>
        ))}
      </nav>
      <div className="mt-auto hidden border-t border-[var(--border-default)] px-2 pt-6 font-mono text-[10px] text-[var(--text-muted)] md:block">
        v1.2.0-beta · 2026
      </div>
    </aside>
  );
}