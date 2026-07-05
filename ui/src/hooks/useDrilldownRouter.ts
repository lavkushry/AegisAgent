"use client";

import { useCallback } from "react";
import { useAppStore } from "@/app/store";
import { applyDrilldownLink } from "@/dashboards/drilldown";
import type { DrilldownLink } from "@/panels/types";

/**
 * Turns a panel DrilldownLink into navigation. Until the console moves to
 * real routes, navigation is store-driven view switching plus a seeded
 * Explore query.
 */
export function useDrilldownRouter(): (
  link: DrilldownLink,
  row?: Record<string, unknown>,
) => void {
  const setActiveView = useAppStore((s) => s.setActiveView);
  const setExploreSeed = useAppStore((s) => s.setExploreSeed);
  const setActiveIncidentId = useAppStore((s) => s.setActiveIncidentId);
  const setActiveReceiptId = useAppStore((s) => s.setActiveReceiptId);
  const setActiveAgentId = useAppStore((s) => s.setActiveAgentId);
  const setVariables = useAppStore((s) => s.setVariables);

  return useCallback(
    (link: DrilldownLink, row?: Record<string, unknown>) => {
      applyDrilldownLink(
        {
          setActiveView,
          setExploreSeed,
          setActiveIncidentId,
          setActiveReceiptId,
          setActiveAgentId,
          setVariables,
          getVariables: () => useAppStore.getState().variables,
        },
        link,
        row,
      );
    },
    [
      setActiveAgentId,
      setActiveIncidentId,
      setActiveReceiptId,
      setActiveView,
      setExploreSeed,
      setVariables,
    ],
  );
}