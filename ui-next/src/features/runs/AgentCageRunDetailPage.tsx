import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  getAgentRun,
  getRunTimeline,
  listRunEvents,
  runStatusColorVar,
} from "@/domains/agentRuns";
import { errorMessage, formatTime } from "@/lib/format";

export function AgentCageRunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };

  const runQuery = useQuery({
    queryKey: ["agent-run", runId, gatewayUrl, activeTenant],
    queryFn: () => getAgentRun(apiOpts, runId!),
    enabled: tenantReady && Boolean(runId),
    retry: false,
  });

  const timelineQuery = useQuery({
    queryKey: ["run-timeline", runId, gatewayUrl, activeTenant],
    queryFn: () => getRunTimeline(apiOpts, runId!),
    enabled: tenantReady && Boolean(runId),
    retry: false,
  });

  const eventsQuery = useQuery({
    queryKey: ["run-events", runId, gatewayUrl, activeTenant],
    queryFn: () => listRunEvents(apiOpts, runId!),
    enabled: tenantReady && Boolean(runId),
    retry: false,
  });

  if (!tenantReady)
    return <TenantGate title="Select a tenant for run detail" />;
  if (!runId) return null;

  const run = runQuery.data;
  const timeline = timelineQuery.data ?? [];
  const events = eventsQuery.data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Run detail
        </h1>
        <p className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">
          {runId}
        </p>
      </div>

      {runQuery.isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading run…</p>
      )}
      {runQuery.error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(runQuery.error)}
        </div>
      )}

      {run ? (
        <div className="panel-card space-y-2">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
            <dt className="text-[var(--text-muted)]">Run key</dt>
            <dd className="font-mono text-[var(--text-secondary)]">
              {run.run_key}
            </dd>
            <dt className="text-[var(--text-muted)]">Status</dt>
            <dd>
              <span
                className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                style={pillStyle(runStatusColorVar(run.status))}
              >
                {run.status}
              </span>
            </dd>
            <dt className="text-[var(--text-muted)]">Mode</dt>
            <dd className="text-[var(--text-secondary)]">{run.mode}</dd>
            <dt className="text-[var(--text-muted)]">Source</dt>
            <dd className="text-[var(--text-secondary)]">
              {run.source_component}
            </dd>
            <dt className="text-[var(--text-muted)]">Started</dt>
            <dd className="text-[var(--text-secondary)]">
              {formatTime(run.started_at)}
            </dd>
            <dt className="text-[var(--text-muted)]">Finished</dt>
            <dd className="text-[var(--text-secondary)]">
              {formatTime(run.finished_at) || "—"}
            </dd>
            <dt className="text-[var(--text-muted)]">Trust level</dt>
            <dd className="text-[var(--text-secondary)]">
              {run.root_trust_level || "—"}
            </dd>
          </dl>
        </div>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel-card space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider">
            Decision timeline
          </h2>
          {timelineQuery.isLoading ? (
            <p className="text-xs text-[var(--text-muted)]">Loading…</p>
          ) : timelineQuery.error ? (
            <p className="text-xs text-[var(--sev-high)]">
              {errorMessage(timelineQuery.error)}
            </p>
          ) : timeline.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">
              No audit events for this run.
            </p>
          ) : (
            <ul className="space-y-2 text-[11px]">
              {timeline.map((ev) => (
                <li
                  key={ev.id}
                  className="border-t border-[var(--border-default)] pt-2 first:border-t-0 first:pt-0"
                >
                  <div className="font-mono text-[var(--text-primary)]">
                    {ev.event_type}
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)]">
                    {[ev.skill, ev.action, ev.resource]
                      .filter(Boolean)
                      .join(" · ") || "—"}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel-card space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider">
            Runtime events
          </h2>
          {eventsQuery.isLoading ? (
            <p className="text-xs text-[var(--text-muted)]">Loading…</p>
          ) : eventsQuery.error ? (
            <p className="text-xs text-[var(--sev-high)]">
              {errorMessage(eventsQuery.error)}
            </p>
          ) : events.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">
              No runtime events for this run.
            </p>
          ) : (
            <ul className="space-y-2 text-[11px]">
              {events.map((ev) => (
                <li
                  key={ev.id}
                  className="border-t border-[var(--border-default)] pt-2 first:border-t-0 first:pt-0"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[var(--text-primary)]">
                      {ev.event_type}
                    </span>
                    <span className="text-[10px] text-[var(--text-muted)]">
                      {formatTime(ev.observed_at)}
                    </span>
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)]">
                    {ev.source_component}
                    {ev.reason ? ` · ${ev.reason}` : ""}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
