import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/chrome/AppShell";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { ApprovalsPage } from "@/features/approvals/ApprovalsPage";
import { IntegrityPage } from "@/features/integrity/IntegrityPage";
import { ExplorePage } from "@/features/explore/ExplorePage";

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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}
