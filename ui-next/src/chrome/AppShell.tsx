import type { ReactNode } from "react";
import { SidebarNav } from "./SidebarNav";
import { ThemeControls } from "./ThemeControls";
import { ControlsBar } from "./ControlsBar";
import { useAppStore } from "@/app/store";
import { useSocStream } from "@/hooks/useSocStream";

export function AppShell({ children }: { children: ReactNode }) {
  const activeTenant = useAppStore((s) => s.activeTenant);
  const theme = useAppStore((s) => s.theme);

  // Advisory live stream when Live is enabled in ControlsBar
  useSocStream();

  return (
    <div className="flex h-full min-h-screen bg-[var(--surface-app)] text-[var(--text-primary)]">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <aside
        className="flex w-56 shrink-0 flex-col border-r border-[var(--border-default)] bg-[var(--surface-panel)]"
        aria-label="Console chrome"
      >
        <div className="border-b border-[var(--border-default)] px-4 py-4">
          <h1 className="text-xs font-bold tracking-wider text-[var(--brand)]">
            AegisAgent
          </h1>
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            SOC Console
          </div>
          <div className="mt-2 text-[10px] text-[var(--text-secondary)]">
            Tenant context
            <div
              className="mt-0.5 font-mono text-[11px] text-[var(--text-primary)]"
              data-testid="tenant-context"
            >
              {activeTenant.trim() ? activeTenant : "Not selected"}
            </div>
          </div>
        </div>
        <SidebarNav />
        <div className="mt-auto border-t border-[var(--border-default)]">
          <ThemeControls />
          <div className="border-t border-[var(--border-default)] px-4 py-3 text-[10px] text-[var(--text-muted)]">
            Bun SPA · Dark SOC · {theme}
          </div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <ControlsBar />
        <main id="main-content" className="flex-1 overflow-auto p-6" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}
