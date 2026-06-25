"use client";

import { useCallback } from "react";
import { useAppStore } from "@/app/store";
import type { DrilldownLink } from "@/panels/types";

/** Replace ${field} tokens in a template with values from a clicked row. */
function fillTemplate(template: string, row?: Record<string, unknown>): string {
  if (!row) return template;
  return template.replace(/\$\{(\w+)\}/g, (_, key: string) => {
    const value = row[key];
    return value === null || value === undefined ? "" : String(value);
  });
}

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

  return useCallback(
    (link: DrilldownLink, row?: Record<string, unknown>) => {
      switch (link.target.kind) {
        case "explore":
          setExploreSeed(fillTemplate(link.target.aqlTemplate, row));
          setActiveView("explore");
          break;
        case "verify-receipt":
          setActiveView("integrity");
          break;
        case "incident":
          setActiveView("incidents");
          break;
        case "dashboard":
          setActiveView(link.target.uid);
          break;
      }
    },
    [setActiveView, setExploreSeed],
  );
}
