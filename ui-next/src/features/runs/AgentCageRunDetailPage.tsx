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
import { listPromptEventsForRun } from "@/domains/promptEvents";
import {
  listModelCallsForRun,
  modelCallStatusColorVar,
  parseTokenCounts,
} from "@/domains/modelCalls";
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

  const promptEventsQuery = useQuery({
    queryKey: ["run-prompt-events", runId, gatewayUrl, activeTenant],
    queryFn: () => listPromptEventsForRun(apiOpts, runId!),
    enabled: tenantReady && Boolean(runId),
    retry: false,
  });

  const modelCallsQuery = useQuery({
    queryKey: ["run-model-calls", runId, gatewayUrl, activeTenant],
    queryFn: () => listModelCallsForRun(apiOpts, runId!),
    enabled: tenantReady && Boolean(runId),
    retry: false,
  });

  if (!tenantReady)
    return <TenantGate title="Select a tenant for run detail" />;
  if (!runId) return null;

  const run = runQuery.data;
  const timeline = timelineQuery.data ?? [];
  const events = eventsQuery.data ?? [];
  const promptEvents = promptEventsQuery.data ?? [];
  const modelCalls = modelCallsQuery.data ?? [];

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

        <div className="panel-card space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider">
            Prompt timeline
          </h2>
          {promptEventsQuery.isLoading ? (
            <p className="text-xs text-[var(--text-muted)]">Loading…</p>
          ) : promptEventsQuery.error ? (
            <p className="text-xs text-[var(--sev-high)]">
              {errorMessage(promptEventsQuery.error)}
            </p>
          ) : promptEvents.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">
              No prompt lineage recorded for this run.
            </p>
          ) : (
            <ul className="space-y-2 text-[11px]">
              {promptEvents.map((ev) => (
                <li
                  key={ev.id}
                  className="border-t border-[var(--border-default)] pt-2 first:border-t-0 first:pt-0"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--text-primary)] capitalize">
                      {ev.role || "prompt"}
                      {ev.model_provider ? ` · ${ev.model_provider}` : ""}
                    </span>
                    <span className="text-[10px] text-[var(--text-muted)]">
                      {formatTime(ev.created_at)}
                    </span>
                  </div>
                  {ev.redacted_prompt_preview ? (
                    <p className="mt-1 text-[10px] text-[var(--text-secondary)]">
                      {ev.redacted_prompt_preview}
                    </p>
                  ) : null}
                  <div className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">
                    {ev.prompt_hash.slice(0, 16)}… · {ev.redaction_status}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel-card space-y-2">
          <h2 className="text-xs font-bold uppercase tracking-wider">
            Model calls
          </h2>
          {modelCallsQuery.isLoading ? (
            <p className="text-xs text-[var(--text-muted)]">Loading…</p>
          ) : modelCallsQuery.error ? (
            <p className="text-xs text-[var(--sev-high)]">
              {errorMessage(modelCallsQuery.error)}
            </p>
          ) : modelCalls.length === 0 ? (
            <p className="text-xs text-[var(--text-muted)]">
              No model calls recorded for this run.
            </p>
          ) : (
            <ul className="space-y-2 text-[11px]">
              {modelCalls.map((mc) => {
                const tokens = parseTokenCounts(mc.token_counts_json);
                return (
                  <li
                    key={mc.id}
                    className="border-t border-[var(--border-default)] pt-2 first:border-t-0 first:pt-0"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[var(--text-primary)]">
                        {mc.provider}/{mc.model}
                      </span>
                      <span
                        className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                        style={pillStyle(modelCallStatusColorVar(mc.status))}
                      >
                        {mc.status}
                      </span>
                    </div>
                    <div className="mt-1 text-[10px] text-[var(--text-muted)]">
                      {formatTime(mc.started_at) || formatTime(mc.received_at)}
                      {tokens
                        ? ` · ${Object.entries(tokens)
                            .map(([k, v]) => `${k}: ${v}`)
                            .join(", ")}`
                        : ""}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
