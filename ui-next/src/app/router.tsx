import { lazy, Suspense, type ComponentType } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/chrome/AppShell";
import { RouteErrorBoundary } from "@/app/RouteErrorBoundary";
// Eager: landing + connection config (critical path for cold start).
import { OverviewPage } from "@/features/overview/OverviewPage";
import { SettingsPage } from "@/features/settings/SettingsPage";

/**
 * Lazy-load feature routes so the initial dashboard shell stays small.
 * Named exports are adapted to default for React.lazy.
 */
function lazyPage<T extends ComponentType<unknown>>(
  loader: () => Promise<{ [key: string]: T }>,
  exportName: string,
) {
  return lazy(async () => {
    const mod = await loader();
    return { default: mod[exportName] as T };
  });
}

const ApprovalsPage = lazyPage(
  () => import("@/features/approvals/ApprovalsPage"),
  "ApprovalsPage",
);
const IntegrityPage = lazyPage(
  () => import("@/features/integrity/IntegrityPage"),
  "IntegrityPage",
);
const ExplorePage = lazyPage(
  () => import("@/features/explore/ExplorePage"),
  "ExplorePage",
);
const AgentsPage = lazyPage(
  () => import("@/features/agents/AgentsPage"),
  "AgentsPage",
);
const AgentDetailPage = lazyPage(
  () => import("@/features/agents/AgentDetailPage"),
  "AgentDetailPage",
);
const IncidentsPage = lazyPage(
  () => import("@/features/incidents/IncidentsPage"),
  "IncidentsPage",
);
const McpPage = lazyPage(
  () => import("@/features/mcp/McpPage"),
  "McpPage",
);
const DetectionsPage = lazyPage(
  () => import("@/features/detections/DetectionsPage"),
  "DetectionsPage",
);
const RulesPage = lazyPage(
  () => import("@/features/rules/RulesPage"),
  "RulesPage",
);
const AlertingPage = lazyPage(
  () => import("@/features/alerting/AlertingPage"),
  "AlertingPage",
);
const DashboardEditorPage = lazyPage(
  () => import("@/features/dashboards/DashboardEditorPage"),
  "DashboardEditorPage",
);

function RouteFallback() {
  return (
    <div
      className="flex min-h-[8rem] items-center text-xs text-[var(--text-muted)]"
      role="status"
      aria-live="polite"
    >
      Loading view…
    </div>
  );
}

export function AppRouter() {
  return (
    <BrowserRouter basename="/dashboard">
      <AppShell>
        <RouteErrorBoundary>
          <Suspense fallback={<RouteFallback />}>
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
          </Suspense>
        </RouteErrorBoundary>
      </AppShell>
    </BrowserRouter>
  );
}
