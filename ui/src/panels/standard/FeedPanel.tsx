import { frameRows } from "@/datasources/frame";
import { formatTime } from "@/lib/format";
import type { PanelProps } from "../types";

interface FeedPanelOptions {
  timeField?: string;
  titleField?: string;
  detailField?: string;
  maxRows?: number;
}

export default function FeedPanel({ data, definition, onDrilldown }: PanelProps<FeedPanelOptions>) {
  const options = definition.options ?? {};
  const rows = frameRows(data).slice(0, options.maxRows ?? 25);

  return (
    <ol className="h-full space-y-1 overflow-auto pr-1 custom-scrollbar">
      {rows.map((row, index) => (
        <li key={String(row.id ?? index)}>
          <button
            type="button"
            onClick={() => definition.drilldowns?.[0] && onDrilldown(definition.drilldowns[0], row)}
            disabled={!definition.drilldowns?.[0]}
            className="grid w-full grid-cols-[5rem_1fr] gap-3 rounded px-2 py-1.5 text-left text-xs hover:bg-[var(--surface-elevated)] disabled:cursor-default"
          >
            <time className="font-mono text-[var(--text-muted)]">
              {formatTime(String(row[options.timeField ?? "created_at"] ?? ""))}
            </time>
            <span className="min-w-0">
              <strong className="block truncate text-[var(--text-primary)]">
                {String(row[options.titleField ?? "event_type"] ?? "Event")}
              </strong>
              <span className="block truncate text-[var(--text-secondary)]">
                {String(row[options.detailField ?? "summary"] ?? "")}
              </span>
            </span>
          </button>
        </li>
      ))}
    </ol>
  );
}
