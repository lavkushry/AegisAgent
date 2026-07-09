import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/chrome/AppShell";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { ApprovalsPage } from "@/features/approvals/ApprovalsPage";
import { IntegrityPage } from "@/features/integrity/IntegrityPage";
import { ExplorePage } from "@/features/explore/ExplorePage";
import { AgentsPage } from "@/features/agents/AgentsPage";
import { AgentDetailPage } from "@/features/agents/AgentDetailPage";
import { IncidentsPage } from "@/features/incidents/IncidentsPage";
import { McpPage } from "@/features/mcp/McpPage";
import { DetectionsPage } from "@/features/detections/DetectionsPage";
import { RulesPage } from "@/features/rules/RulesPage";
import { AlertingPage } from "@/features/alerting/AlertingPage";
import { DashboardEditorPage } from "@/features/dashboards/DashboardEditorPage";

export function AppRouter() {
  return (
    <BrowserRouter basename="/dashboard">
      <AppShell>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
          <Route path="/integrity" element={<IntegrityPage />} />
          <Route path="/explore" element={<ExplorePage />} />
          <Route path="/detections" element={<DetectionsPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/alerting" element={<AlertingPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/agents/:agentId" element={<AgentDetailPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/mcp" element={<McpPage />} />
          <Route path="/dashboards" element={<DashboardEditorPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}
