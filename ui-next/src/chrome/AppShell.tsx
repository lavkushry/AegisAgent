import type { ReactNode } from "react";
import { SidebarNav } from "./SidebarNav";
import { ThemeControls } from "./ThemeControls";
import { useAppStore } from "@/app/store";

export function AppShell({ children }: { children: ReactNode }) {
  const activeTenant = useAppStore((s) => s.activeTenant);
  const theme = useAppStore((s) => s.theme);

  return (
    <div className="flex h-full min-h-screen bg-[var(--surface-app)] text-[var(--text-primary)]">
      <aside className="flex w-56 shrink-0 flex-col border-r border-[var(--border-default)] bg-[var(--surface-panel)]">
        <div className="border-b border-[var(--border-default)] px-4 py-4">
          <h1 className="text-xs font-bold tracking-wider text-[var(--brand)]">
            AegisAgent
          </h1>
          <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            SOC Console
          </div>
          <div className="mt-2 text-[10px] text-[var(--text-secondary)]">
            Tenant context
            <div className="mt-0.5 font-mono text-[11px] text-[var(--text-primary)]">
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
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  );
}
