import type { EvidenceGraph } from "@/domains/graph";
import {
  NODE_H,
  NODE_W,
  countByGroup,
  layoutEvidenceGraph,
  nodeFill,
  shortLabel,
} from "@/panels/differentiators/decisionGraphModel";

export interface EvidenceGraphSvgProps {
  graph: EvidenceGraph;
  maxNodes?: number;
  scopeLabel: string;
}

/**
 * Pure SVG layered render of an [`EvidenceGraph`] — shared by the
 * `decision-graph` dashboard panel and the standalone Evidence Graph page so
 * the two never drift.
 */
export function EvidenceGraphSvg({
  graph,
  maxNodes = 40,
  scopeLabel,
}: EvidenceGraphSvgProps) {
  if (graph.nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        Empty graph for {scopeLabel}
      </div>
    );
  }

  const layout = layoutEvidenceGraph(graph, maxNodes);
  const counts = countByGroup(graph.nodes);

  return (
    <div className="flex h-full flex-col gap-1" data-testid="evidence-graph-svg">
      <div className="flex flex-wrap items-baseline justify-between gap-2 text-[10px] text-[var(--text-muted)]">
        <span className="font-mono truncate">{scopeLabel}</span>
        <span className="tabular-nums">
          {graph.nodes.length} nodes · {graph.edges.length} edges
          {counts.decision
            ? ` · ${counts.decision} decision${counts.decision === 1 ? "" : "s"}`
            : ""}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        className="h-full min-h-[8rem] w-full"
        role="img"
        aria-label={`Evidence graph for ${scopeLabel}: ${graph.nodes.length} nodes`}
      >
        {layout.edges.map((e, i) => {
          const x1 = e.from.x + NODE_W;
          const y1 = e.from.y + NODE_H / 2;
          const x2 = e.to.x;
          const y2 = e.to.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={`e-${i}-${e.from.id}-${e.to.id}`}>
              <path
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                fill="none"
                stroke="var(--border-default)"
                strokeWidth={1.25}
              />
            </g>
          );
        })}
        {layout.nodes.map((n) => (
          <g key={n.id}>
            <title>
              {n.group}: {n.label}
            </title>
            <rect
              x={n.x}
              y={n.y}
              width={NODE_W}
              height={NODE_H}
              rx={4}
              fill={nodeFill(String(n.group))}
              fillOpacity={0.22}
              stroke={nodeFill(String(n.group))}
              strokeWidth={1}
            />
            <text
              x={n.x + NODE_W / 2}
              y={n.y + 11}
              textAnchor="middle"
              fill="var(--text-muted)"
              fontSize={7}
              fontFamily="ui-sans-serif, system-ui, sans-serif"
            >
              {String(n.group)}
            </text>
            <text
              x={n.x + NODE_W / 2}
              y={n.y + 22}
              textAnchor="middle"
              fill="var(--text-primary)"
              fontSize={9}
              fontFamily="ui-monospace, monospace"
              fontWeight={600}
            >
              {shortLabel(n.label, 11)}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
