"use client";

import { useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { errorMessage } from "@/lib/format";
import { useConsoleUrlSync } from "@/hooks/useConsoleUrlSync";
import ControlsBar from "./ControlsBar";
import SidebarNav from "./SidebarNav";

export default function AppShell({ children }: { children: ReactNode }) {
  useConsoleUrlSync();
  const queryClient = useQueryClient();
  const [isFetching, setIsFetching] = useState(false);
  const [statusMessage, setStatusMessage] = useState("");
  const refresh = async () => {
    setIsFetching(true);
    setStatusMessage("Refreshing console data…");
    try {
      await queryClient.refetchQueries();
      setStatusMessage("Console data updated.");
    } catch (error: unknown) {
      setStatusMessage(`Refresh failed: ${errorMessage(error)}`);
    } finally {
      setIsFetching(false);
    }
  };
  return <div className="flex min-h-screen flex-col bg-[var(--surface-app)] text-[var(--text-primary)] md:flex-row"><SidebarNav /><main className="flex min-w-0 flex-1 flex-col space-y-6 overflow-x-hidden p-4 md:p-6"><ControlsBar onRefresh={refresh} isFetching={isFetching} statusMessage={statusMessage} /><div className="flex-1">{children}</div></main></div>;
}
