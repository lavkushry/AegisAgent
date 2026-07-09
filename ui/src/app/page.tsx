"use client";

import React from "react";
import { useAppStore } from "./store";
import AppShell from "@/chrome/AppShell";
import ExploreTab from "../components/ExploreTab";
import IncidentsTab from "../components/IncidentsTab";
import McpTab from "../components/McpTab";
import SettingsTab from "../components/SettingsTab";
import DetectionsPage from "../components/detections/DetectionsPage";
import RulesPage from "../components/rules/RulesPage";
import AlertingPage from "../components/alerting/AlertingPage";
import DashboardLoader from "../dashboards/DashboardLoader";
import { overviewDashboard } from "../dashboards/system/overview";
import { integrityDashboard } from "../dashboards/system/integrity";
import AgentsFleetTab from "../components/fleet/AgentsFleetTab";
import { approvalsDashboard } from "../dashboards/system/approvals";
import { receiptsDashboard } from "../dashboards/system/receipts";
import { analyticsDashboard } from "../dashboards/system/analytics";
import { runtimeDashboard } from "../dashboards/system/runtime";
import DashboardEditorPage from "../components/dashboards/DashboardEditorPage";
import PanelHarnessPage from "../dev/PanelHarnessPage";
import { DEV_HARNESS_ENABLED, DEV_HARNESS_VIEW } from "../dev/guard";


type ActiveTab = "overview" | "dashboards" | "integrity" | "explore" | "incidents" | "detections" | "rules" | "alerting" | "approvals" | "agents" | "mcp" | "receipts" | "analytics" | "runtime" | "dashboard-editor" | "dev-harness" | "settings";

export default function Home() {
  const activeTab = useAppStore((s) => s.activeView) as ActiveTab;
  const views: Partial<Record<ActiveTab, React.ReactNode>> = {
    overview: <DashboardLoader schema={overviewDashboard} />,
    dashboards: <DashboardLoader schema={overviewDashboard} />,
    integrity: <DashboardLoader schema={integrityDashboard} />, explore: <ExploreTab />,
    incidents: <IncidentsTab />,
    detections: <DetectionsPage />,
    rules: <RulesPage />,
    alerting: <AlertingPage />,
    approvals: <DashboardLoader schema={approvalsDashboard} />,
    agents: <AgentsFleetTab />, mcp: <McpTab />, receipts: <DashboardLoader schema={receiptsDashboard} />,
    analytics: <DashboardLoader schema={analyticsDashboard} />,
    runtime: <DashboardLoader schema={runtimeDashboard} />,
    "dashboard-editor": <DashboardEditorPage />,
    [DEV_HARNESS_VIEW]: DEV_HARNESS_ENABLED ? <PanelHarnessPage /> : null,
    settings: <SettingsTab />,
  };

  return (
    <AppShell>{views[activeTab] ?? views.overview ?? null}</AppShell>
  );
}
