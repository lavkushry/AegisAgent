import { Link } from "react-router-dom";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { DashboardLoader } from "@/dashboards/DashboardLoader";
import { overviewDashboard } from "@/dashboards/system/overview";

/** Schema-driven Overview (Phase B PanelRuntime). */
export function OverviewPage() {
  const activeTenant = useAppStore((s) => s.activeTenant);
  const liveMode = useAppStore((s) => s.liveMode);
  const setLiveMode = useAppStore((s) => s.setLiveMode);
  const timeRange = useAppStore((s) => s.timeRange);
  const setTimeRange = useAppStore((s) => s.setTimeRange);

  if (!activeTenant.trim()) {
    return <TenantGate title="Select a tenant for Overview" />;
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-end gap-2">
        <label className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          Range
          <select
            className="input-field w-auto py-1"
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            aria-label="Time range"
          >
            <option value="1h">1h</option>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
          </select>
        </label>
        <button
          type="button"
          className={`rounded-md border px-2 py-1 text-[11px] font-medium ${
            liveMode
              ? "border-[var(--border-active)] bg-[var(--brand-subtle)] text-[var(--text-primary)]"
              : "border-[var(--border-default)] text-[var(--text-secondary)]"
          }`}
          onClick={() => setLiveMode(!liveMode)}
          aria-pressed={liveMode}
        >
          {liveMode ? "● Live" : "Live off"}
        </button>
        <Link
          className="text-[11px] text-[var(--brand)] underline"
          to="/settings"
        >
          Settings
        </Link>
      </div>
      <DashboardLoader schema={overviewDashboard} />
    </div>
  );
}
