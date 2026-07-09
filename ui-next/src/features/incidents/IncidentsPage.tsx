import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  downloadIncidentEvidencePack,
  getIncident,
  listIncidents,
  severityColorVar,
  type IncidentRecord,
} from "@/domains/incidents";
import { triggerBlobDownload } from "@/lib/http/client";
import { errorMessage, formatTime } from "@/lib/format";

export function IncidentsPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["incidents", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listIncidents(apiOpts, 50),
    enabled: tenantReady,
    refetchInterval: 10_000,
    retry: false,
  });

  const detailQuery = useQuery({
    queryKey: ["incident", selectedId, gatewayUrl, activeTenant],
    queryFn: () => getIncident(apiOpts, selectedId!),
    enabled: tenantReady && Boolean(selectedId),
    retry: false,
  });

  const exportIncident = async (incident: IncidentRecord) => {
    setExporting(true);
    setFlash(null);
    try {
      const blob = await downloadIncidentEvidencePack(apiOpts, incident.id);
      triggerBlobDownload(
        blob,
        `aegis-incident-${incident.id}-evidence.zip`,
      );
      setFlash({ ok: true, message: "Incident evidence pack downloaded." });
    } catch (err: unknown) {
      setFlash({ ok: false, message: errorMessage(err) });
    } finally {
      setExporting(false);
    }
  };

  if (!tenantReady) return <TenantGate title="Select a tenant for Incidents" />;

  const rows = data ?? [];
  const detail = detailQuery.data;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Incidents
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Correlated cases with per-incident evidence-pack export
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      {flash ? (
        <p
          role="status"
          className={`rounded border px-3 py-2 text-[11px] ${
            flash.ok
              ? "border-emerald-500/30 text-[var(--state-verified)]"
              : "border-rose-500/30 text-[var(--state-failed)]"
          }`}
        >
          {flash.message}
        </p>
      ) : null}

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading incidents…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          {rows.map((inc) => (
            <button
              key={inc.id}
              type="button"
              onClick={() => setSelectedId(inc.id)}
              className={`panel-card w-full cursor-pointer text-left transition-colors ${
                selectedId === inc.id
                  ? "ring-1 ring-[var(--border-active)]"
                  : "hover:bg-[var(--interactive-bg-hover)]"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-xs font-semibold text-[var(--text-primary)]">
                    {inc.summary || inc.kind || inc.id}
                  </div>
                  <div className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">
                    {inc.id}
                  </div>
                </div>
                <span
                  className="shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                  style={pillStyle(severityColorVar(inc.severity))}
                >
                  {inc.severity || "info"}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-[var(--text-secondary)]">
                <span className="capitalize">{inc.status || "open"}</span>
                <span>{formatTime(inc.opened_at) || "—"}</span>
                {inc.agent_id ? (
                  <span className="font-mono">{inc.agent_id}</span>
                ) : null}
              </div>
            </button>
          ))}
          {!isLoading && rows.length === 0 ? (
            <div className="panel-card text-xs text-[var(--text-secondary)]">
              No incidents for this tenant.
            </div>
          ) : null}
        </div>

        <div className="panel-card min-h-[200px] space-y-3">
          {!selectedId ? (
            <p className="text-xs text-[var(--text-muted)]">
              Select an incident to inspect and export evidence.
            </p>
          ) : detailQuery.isLoading ? (
            <p className="text-xs text-[var(--text-muted)]">Loading detail…</p>
          ) : detailQuery.error ? (
            <p className="text-xs text-[var(--sev-high)]">
              {errorMessage(detailQuery.error)}
            </p>
          ) : detail ? (
            <>
              <div>
                <h2 className="text-xs font-bold uppercase tracking-wider">
                  Incident detail
                </h2>
                <p className="mt-1 text-sm text-[var(--text-primary)]">
                  {detail.summary || detail.kind}
                </p>
              </div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
                <dt className="text-[var(--text-muted)]">ID</dt>
                <dd className="font-mono text-[var(--text-secondary)]">
                  {detail.id}
                </dd>
                <dt className="text-[var(--text-muted)]">Status</dt>
                <dd className="capitalize text-[var(--text-secondary)]">
                  {detail.status}
                </dd>
                <dt className="text-[var(--text-muted)]">Severity</dt>
                <dd>
                  <span
                    className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(severityColorVar(detail.severity))}
                  >
                    {detail.severity || "info"}
                  </span>
                </dd>
                <dt className="text-[var(--text-muted)]">Agent</dt>
                <dd className="font-mono text-[var(--text-secondary)]">
                  {detail.agent_id || "—"}
                </dd>
                <dt className="text-[var(--text-muted)]">Opened</dt>
                <dd className="text-[var(--text-secondary)]">
                  {formatTime(detail.opened_at) || "—"}
                </dd>
              </dl>
              <button
                type="button"
                className="btn-primary inline-flex items-center gap-1"
                disabled={exporting}
                onClick={() => exportIncident(detail)}
              >
                <Download size={12} />
                {exporting ? "Exporting…" : "Download evidence pack"}
              </button>
              <p className="text-[10px] text-[var(--text-muted)]">
                GET /v1/incidents/:id/evidence-pack — ZIP of correlated
                investigation evidence.
              </p>
            </>
          ) : null}
        </div>
      </div>
    </div>
  );
}
