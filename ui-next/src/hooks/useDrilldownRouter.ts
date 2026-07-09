import { useNavigate } from "react-router-dom";
import { useCallback } from "react";
import type { DrilldownLink } from "@/panels/types";

/**
 * Minimal drilldown router — maps panel drilldowns to SPA routes.
 * Full template substitution for AQL lands with ControlsBar (Phase C).
 */
export function useDrilldownRouter(): (
  link: DrilldownLink,
  row?: Record<string, unknown>,
) => void {
  const navigate = useNavigate();

  return useCallback(
    (link: DrilldownLink, row?: Record<string, unknown>) => {
      const target = link.target;
      switch (target.kind) {
        case "explore": {
          const aql = interpolate(target.aqlTemplate, row);
          navigate(`/explore?q=${encodeURIComponent(aql)}`);
          break;
        }
        case "incident": {
          const id = row?.[target.incidentIdField];
          if (id) navigate(`/incidents`);
          else navigate("/incidents");
          break;
        }
        case "dashboard": {
          const uid = target.uid;
          if (uid === "approvals") navigate("/approvals");
          else if (uid === "integrity") navigate("/integrity");
          else if (uid === "incidents") navigate("/incidents");
          else if (uid === "detections") navigate("/detections");
          else if (uid === "agents") navigate("/agents");
          else navigate("/");
          break;
        }
        case "agent": {
          navigate("/agents");
          break;
        }
        case "receipt":
        case "verify-receipt": {
          navigate("/integrity");
          break;
        }
        default:
          break;
      }
    },
    [navigate],
  );
}

function interpolate(
  template: string,
  row?: Record<string, unknown>,
): string {
  if (!row) return template;
  return template.replace(/\$\{(\w+)\}/g, (_, key: string) =>
    String(row[key] ?? ""),
  );
}
