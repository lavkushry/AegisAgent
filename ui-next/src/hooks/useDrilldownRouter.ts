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
          else if (uid === "integrity" || uid === "receipts")
            navigate("/integrity");
          else if (uid === "incidents") navigate("/incidents");
          else if (uid === "detections") navigate("/detections");
          else if (uid === "agents" || uid === "fleet") navigate("/agents");
          else if (uid === "mcp") navigate("/mcp");
          else if (uid === "rules") navigate("/rules");
          else if (uid === "alerting") navigate("/alerting");
          else if (uid === "explore") navigate("/explore");
          else if (uid === "dashboards") navigate("/dashboards");
          else navigate("/");
          break;
        }
        case "agent": {
          const id = row?.[target.agentIdField];
          if (id != null && String(id).length > 0) {
            navigate(`/agents/${encodeURIComponent(String(id))}`);
          } else {
            navigate("/agents");
          }
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
