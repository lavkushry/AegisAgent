import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/chrome/AppShell";
import { OverviewPage } from "@/features/overview/OverviewPage";
import { SettingsPage } from "@/features/settings/SettingsPage";
import { PlaceholderPage } from "@/features/PlaceholderPage";

export function AppRouter() {
  return (
    <BrowserRouter basename="/dashboard">
      <AppShell>
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route
            path="/approvals"
            element={
              <PlaceholderPage
                title="Approvals"
                body="Approval queue with frozen action hash will port here."
              />
            }
          />
          <Route
            path="/integrity"
            element={
              <PlaceholderPage
                title="Integrity"
                body="Receipt chain and verify panels will port here."
              />
            }
          />
          <Route
            path="/explore"
            element={
              <PlaceholderPage
                title="Explore"
                body="AQL explore surface will port here."
              />
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </BrowserRouter>
  );
}
