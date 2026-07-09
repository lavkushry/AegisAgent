import { useNavigate } from "react-router-dom";
import { useCallback } from "react";
import type { DrilldownLink } from "@/panels/types";
import { resolveDrilldownPath } from "./drilldownPath";

/**
 * Panel drilldown → SPA navigation.
 * Path resolution lives in drilldownPath.ts (unit-tested).
 */
export function useDrilldownRouter(): (
  link: DrilldownLink,
  row?: Record<string, unknown>,
) => void {
  const navigate = useNavigate();

  return useCallback(
    (link: DrilldownLink, row?: Record<string, unknown>) => {
      const path = resolveDrilldownPath(link, row);
      if (path) navigate(path);
    },
    [navigate],
  );
}
