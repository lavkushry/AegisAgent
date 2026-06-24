"use client";

import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "./store";
import ConfigBar from "../components/ConfigBar";
import OverviewTab from "../components/OverviewTab";
import ExploreTab from "../components/ExploreTab";
import IncidentsTab from "../components/IncidentsTab";
import ApprovalsTab from "../components/ApprovalsTab";
import AgentsTab from "../components/AgentsTab";
import McpTab from "../components/McpTab";
import ReceiptsTab from "../components/ReceiptsTab";
import SettingsTab from "../components/SettingsTab";
import DetectionsTab from "../components/DetectionsTab";
import { Shield, LayoutDashboard, Search, AlertOctagon, ShieldAlert, Clock, Users, Server, FileCheck2, Settings as SettingsIcon } from "lucide-react";

type ActiveTab = "overview" | "explore" | "incidents" | "detections" | "approvals" | "agents" | "mcp" | "receipts" | "settings";

export default function Home() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("overview");
  const [isFetching, setIsFetching] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");
  const queryClient = useQueryClient();

  const handleRefresh = async () => {
    setIsFetching(true);
    setStatusMsg("Refreshing console data...");
    try {
      await queryClient.refetchQueries();
      setStatusMsg("Console data updated successfully.");
    } catch (err: any) {
      setStatusMsg(`Refresh failed: ${err.message}`);
    } finally {
      setIsFetching(false);
    }
  };

  const renderContent = () => {
    switch (activeTab) {
      case "overview":
        return <OverviewTab />;
      case "explore":
        return <ExploreTab />;
      case "incidents":
        return <IncidentsTab />;
      case "detections":
        return <DetectionsTab />;
      case "approvals":
        return <ApprovalsTab />;
      case "agents":
        return <AgentsTab />;
      case "mcp":
        return <McpTab />;
      case "receipts":
        return <ReceiptsTab />;
      case "settings":
        return <SettingsTab />;
      default:
        return <OverviewTab />;
    }
  };

  const navItems = [
    { id: "overview" as ActiveTab, label: "Overview", icon: <LayoutDashboard size={16} /> },
    { id: "explore" as ActiveTab, label: "Explore", icon: <Search size={16} /> },
    { id: "incidents" as ActiveTab, label: "Incidents", icon: <AlertOctagon size={16} /> },
    { id: "detections" as ActiveTab, label: "Detections & Rules", icon: <ShieldAlert size={16} /> },
    { id: "approvals" as ActiveTab, label: "Approvals", icon: <Clock size={16} /> },
    { id: "agents" as ActiveTab, label: "Agents Fleet", icon: <Users size={16} /> },
    { id: "mcp" as ActiveTab, label: "MCP Servers", icon: <Server size={16} /> },
    { id: "receipts" as ActiveTab, label: "Receipts Log", icon: <FileCheck2 size={16} /> },
    { id: "settings" as ActiveTab, label: "Settings", icon: <SettingsIcon size={16} /> },
  ];

  return (
    <div className="flex flex-col md:flex-row min-h-screen bg-[#0f172a] text-[#e2e8f0]">
      {/* Sidebar navigation */}
      <aside className="w-full md:w-64 bg-[#0b0f19] border-r border-[#1f2937] flex flex-col p-5 shrink-0">
        {/* Title / Logo */}
        <div className="flex items-center gap-2 mb-8 px-2">
          <Shield className="text-indigo-500" size={24} />
          <div className="flex flex-col">
            <h1 className="font-extrabold text-sm tracking-wider uppercase">AegisAgent</h1>
            <span className="text-[10px] text-[#64748b] tracking-wider font-semibold font-mono">SOC CONSOLE</span>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="flex-1 space-y-1.5">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                setActiveTab(item.id);
                setStatusMsg("");
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-semibold tracking-wide transition-colors cursor-pointer ${
                activeTab === item.id
                  ? "bg-indigo-600 text-white font-bold"
                  : "text-[#94a3b8] hover:bg-[#111827] hover:text-[#e2e8f0]"
              }`}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>

        {/* Footer */}
        <div className="pt-6 border-t border-[#1f2937] text-[10px] text-[#64748b] font-mono px-2 mt-auto">
          <span>v1.2.0-beta &middot; 2026</span>
        </div>
      </aside>

      {/* Main dashboard content */}
      <main className="flex-1 flex flex-col p-6 space-y-6 overflow-x-hidden">
        {/* Config Top Bar */}
        <ConfigBar
          onRefresh={handleRefresh}
          isFetching={isFetching}
          statusMessage={statusMsg}
        />

        {/* Render Active Tab Page */}
        <div className="flex-1">
          {renderContent()}
        </div>
      </main>
    </div>
  );
}
