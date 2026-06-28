"use client";

import React from "react";
import { useAppStore } from "./store";
import AppShell from "@/chrome/AppShell";
import OverviewTab from "../components/OverviewTab";
import ExploreTab from "../components/ExploreTab";
import IncidentsTab from "../components/IncidentsTab";
import ApprovalsTab from "../components/ApprovalsTab";
import McpTab from "../components/McpTab";
import ReceiptsTab from "../components/ReceiptsTab";
import SettingsTab from "../components/SettingsTab";
import DetectionsTab from "../components/DetectionsTab";
import DashboardLoader from "../dashboards/DashboardLoader";
import { overviewDashboard } from "../dashboards/system/overview";
import { integrityDashboard } from "../dashboards/system/integrity";
import { fleetDashboard } from "../dashboards/system/fleet";

type ActiveTab = "overview" | "dashboards" | "integrity" | "explore" | "incidents" | "detections" | "approvals" | "agents" | "mcp" | "receipts" | "settings";

export default function Home() {
  const activeTab = useAppStore((s) => s.activeView) as ActiveTab;
  const views: Record<ActiveTab, React.ReactNode> = {
    overview: <OverviewTab />, dashboards: <DashboardLoader schema={overviewDashboard} />,
    integrity: <DashboardLoader schema={integrityDashboard} />, explore: <ExploreTab />,
    incidents: <IncidentsTab />, detections: <DetectionsTab />, approvals: <ApprovalsTab />,
    agents: <DashboardLoader schema={fleetDashboard} />, mcp: <McpTab />, receipts: <ReceiptsTab />,
    settings: <SettingsTab />,
  };

  return (
    <AppShell>{views[activeTab] ?? views.overview}</AppShell>
  );
}
