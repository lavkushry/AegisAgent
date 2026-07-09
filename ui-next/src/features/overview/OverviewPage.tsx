import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { DashboardLoader } from "@/dashboards/DashboardLoader";
import { overviewDashboard } from "@/dashboards/system/overview";

/** Schema-driven Overview — global ControlsBar owns range/live. */
export function OverviewPage() {
  const activeTenant = useAppStore((s) => s.activeTenant);

  if (!activeTenant.trim()) {
    return <TenantGate title="Select a tenant for Overview" />;
  }

  return <DashboardLoader schema={overviewDashboard} />;
}
