"use client";

import { useEffect, useState } from "react";
import { useAppStore } from "@/app/store";
import { parseConsoleUrl, serializeConsoleUrl, type ConsoleView } from "@/state/consoleUrl";

export function useConsoleUrlSync(): void {
  const [hydrated, setHydrated] = useState(false);
  const state = useAppStore();

  useEffect(() => {
    const applyLocation = () => {
      const parsed = parseConsoleUrl(window.location.search);
      const current = useAppStore.getState();
      if (parsed.view) current.setActiveView(parsed.view);
      if (parsed.timeRange) current.setTimeRange(parsed.timeRange);
      if (parsed.liveMode !== undefined) current.setLiveMode(parsed.liveMode);
      if (parsed.variables) current.setVariables(parsed.variables);
      if (parsed.exploreQuery) current.setExploreSeed(parsed.exploreQuery);
      if (parsed.incidentId) current.setActiveIncidentId(parsed.incidentId);
      if (parsed.receiptId) current.setActiveReceiptId(parsed.receiptId);
    };
    applyLocation();
    const hydrationTimer = window.setTimeout(() => setHydrated(true), 0);
    window.addEventListener("popstate", applyLocation);
    return () => {
      window.clearTimeout(hydrationTimer);
      window.removeEventListener("popstate", applyLocation);
    };
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    const search = serializeConsoleUrl({
      view: state.activeView as ConsoleView,
      timeRange: state.timeRange,
      liveMode: state.liveMode,
      exploreQuery: state.exploreQuery || undefined,
      incidentId: state.activeIncidentId || undefined,
      receiptId: state.activeReceiptId || undefined,
      variables: state.variables,
    });
    window.history.replaceState(null, "", `${window.location.pathname}${search}${window.location.hash}`);
  }, [
    hydrated,
    state.activeIncidentId,
    state.activeReceiptId,
    state.activeView,
    state.exploreQuery,
    state.liveMode,
    state.timeRange,
    state.variables,
  ]);
}
