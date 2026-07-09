import { frameRows } from "@/datasources/frame";
import type { PanelProps } from "../types";
import {
  riskIntensity,
  rowsToRiskMap,
  type RiskTrend,
} from "./agentRiskMapModel";

export interface AgentRiskMapOptions {
  /** Max ranked agents (default: 10). */
  maxRows?: number;
}

function trendLabel(trend: RiskTrend): string {
  if (trend === "rising") return "↑";
  if (trend === "falling") return "↓";
  return "→";
}

function barColor(score: number): string {
  if (score >= 70) return "var(--sev-critical)";
  if (score >= 40) return "var(--sev-medium)";
  if (score >= 20) return "var(--sev-low)";
  return "var(--brand)";
}

/**
 * ★ Fleet differentiator — ranked agent risk map from
 * `GET /v1/agents/risk-scoreboard` (snapshot: agent-scoreboard).
 *
 * Pure SVG horizontal bars + trend glyphs. Score is advisory display metadata
 * only (never used to gate authorization).
 */
export default function AgentRiskMapPanel(
  props: PanelProps<AgentRiskMapOptions>,
) {
  const maxRows = props.definition.options?.maxRows ?? 10;
  const rows = rowsToRiskMap(frameRows(props.data), maxRows);
  const drill = props.definition.drilldowns?.[0];

  if (rows.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        No risk scoreboard data
      </div>
    );
  }

  const maxScore = Math.max(...rows.map((r) => r.score), 1);
  const barMaxW = 180;
  const rowH = 22;
  const labelW = 96;
  const scoreW = 36;
  const trendW = 16;
  const padY = 4;
  const width = labelW + barMaxW + scoreW + trendW + 16;
  const height = rows.length * (rowH + padY) - padY;

  return (
    <div className="flex h-full flex-col gap-1">
      <div className="flex items-baseline justify-between text-[10px] text-[var(--text-muted)]">
        <span>
          max{" "}
          <span className="tabular-nums text-[var(--text-primary)]">
            {maxScore.toFixed(1)}
          </span>
        </span>
        <span className="tabular-nums">
          n={rows.length}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-full min-h-[6rem] w-full"
        role="img"
        aria-label={`${props.definition.title}: ${rows.length} agents by 24h risk`}
      >
        {rows.map((row, i) => {
          const y = i * (rowH + padY);
          const barW = riskIntensity(row.score, maxScore) * barMaxW;
          const color = barColor(row.score);
          const short =
            row.agentKey.length > 14
              ? `${row.agentKey.slice(0, 13)}…`
              : row.agentKey;
          return (
            <g
              key={row.agentId}
              data-testid="agent-risk-row"
              style={{ cursor: drill ? "pointer" : "default" }}
              onClick={() => {
                if (!drill) return;
                props.onDrilldown(drill, {
                  id: row.agentId,
                  agent_id: row.agentId,
                  agent_key: row.agentKey,
                });
              }}
            >
              <title>
                {row.agentKey}: score {row.score.toFixed(1)},{" "}
                {row.decisionCount24h} decisions/24h, trend {row.trend}
              </title>
              <text
                x={0}
                y={y + rowH / 2 + 3}
                fill="var(--text-secondary)"
                fontSize={9}
                fontFamily="ui-monospace, monospace"
              >
                {short}
              </text>
              <rect
                x={labelW}
                y={y + 4}
                width={barMaxW}
                height={rowH - 8}
                rx={3}
                fill="var(--surface-elevated)"
              />
              <rect
                x={labelW}
                y={y + 4}
                width={Math.max(2, barW)}
                height={rowH - 8}
                rx={3}
                fill={color}
                opacity={0.85}
              />
              <text
                x={labelW + barMaxW + 6}
                y={y + rowH / 2 + 3}
                fill="var(--text-primary)"
                fontSize={10}
                fontFamily="ui-monospace, monospace"
                fontWeight={600}
              >
                {row.score.toFixed(0)}
              </text>
              <text
                x={labelW + barMaxW + scoreW + 2}
                y={y + rowH / 2 + 3}
                fill={
                  row.trend === "rising"
                    ? "var(--sev-high)"
                    : row.trend === "falling"
                      ? "var(--state-verified)"
                      : "var(--text-muted)"
                }
                fontSize={11}
                fontWeight={700}
              >
                {trendLabel(row.trend)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
