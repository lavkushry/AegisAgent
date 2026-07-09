import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { HashChip } from "@/components/security/HashChip";
import { TrustBadge } from "@/components/security/TrustBadge";
import { pillStyle } from "@/components/security/pill";
import {
  listMcpManifestHistory,
  listMcpServers,
  listMcpTools,
  quarantineMcpServer,
  restoreMcpServer,
  type McpServerRecord,
} from "@/domains/mcp";
import { errorMessage, formatTime } from "@/lib/format";

export function McpPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [pending, setPending] = useState<{
    kind: "quarantine" | "restore";
    server: McpServerRecord;
  } | null>(null);
  const [reason, setReason] = useState("");
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["mcp-servers", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listMcpServers(apiOpts),
    enabled: tenantReady,
    refetchInterval: 15_000,
    retry: false,
  });

  const toolsQuery = useQuery({
    queryKey: ["mcp-tools", selectedKey, gatewayUrl, activeTenant],
    queryFn: () => listMcpTools(apiOpts, selectedKey!),
    enabled: tenantReady && Boolean(selectedKey),
    retry: false,
  });

  const historyQuery = useQuery({
    queryKey: ["mcp-history", selectedKey, gatewayUrl, activeTenant],
    queryFn: () => listMcpManifestHistory(apiOpts, selectedKey!),
    enabled: tenantReady && Boolean(selectedKey),
    retry: false,
  });

  const mutation = useMutation({
    mutationFn: async () => {
      if (!pending) throw new Error("No server selected");
      const key = pending.server.server_key;
      const r = reason.trim() || undefined;
      if (pending.kind === "quarantine") {
        return quarantineMcpServer(apiOpts, key, r);
      }
      return restoreMcpServer(apiOpts, key, r);
    },
    onSuccess: () => {
      setFlash({
        ok: true,
        message: `MCP server ${pending?.kind} completed.`,
      });
      setPending(null);
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["mcp-servers"] });
    },
    onError: (err: unknown) => {
      setFlash({ ok: false, message: errorMessage(err) });
    },
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for MCP" />;

  const rows = data ?? [];
  const selected = rows.find((r) => r.server_key === selectedKey);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          MCP Servers
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Registry, pinned manifest hashes, quarantine / restore
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
        <p className="text-xs text-[var(--text-muted)]">Loading MCP servers…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-2">
          {rows.map((s) => (
            <button
              key={s.server_key}
              type="button"
              onClick={() => setSelectedKey(s.server_key)}
              className={`panel-card w-full cursor-pointer text-left ${
                selectedKey === s.server_key
                  ? "ring-1 ring-[var(--border-active)]"
                  : "hover:bg-[var(--interactive-bg-hover)]"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-xs font-semibold">
                    {s.name || s.server_key}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--text-muted)]">
                    {s.server_key}
                  </div>
                </div>
                <span
                  className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                  style={pillStyle(
                    s.status === "quarantined"
                      ? "--decision-approval"
                      : s.status === "active"
                        ? "--state-verified"
                        : "--sev-info",
                  )}
                >
                  {s.status || "unknown"}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <TrustBadge trust={s.trust_level} />
                <HashChip hash={s.manifest_hash} kind="manifest" />
              </div>
            </button>
          ))}
          {!isLoading && rows.length === 0 ? (
            <div className="panel-card text-xs text-[var(--text-secondary)]">
              No MCP servers registered.
            </div>
          ) : null}
        </div>

        <div className="panel-card space-y-3">
          {!selected ? (
            <p className="text-xs text-[var(--text-muted)]">
              Select a server to view tools and controls.
            </p>
          ) : (
            <>
              <h2 className="text-xs font-bold uppercase tracking-wider">
                {selected.name || selected.server_key}
              </h2>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
                <dt className="text-[var(--text-muted)]">Transport</dt>
                <dd className="text-[var(--text-secondary)]">
                  {selected.transport || "—"}
                </dd>
                <dt className="text-[var(--text-muted)]">Endpoint</dt>
                <dd className="break-all font-mono text-[10px] text-[var(--text-secondary)]">
                  {selected.endpoint || "—"}
                </dd>
                <dt className="text-[var(--text-muted)]">Discovered</dt>
                <dd className="text-[var(--text-secondary)]">
                  {formatTime(selected.last_discovery_at) || "—"}
                </dd>
                <dt className="text-[var(--text-muted)]">Manifest</dt>
                <dd>
                  <HashChip hash={selected.manifest_hash} kind="manifest" />
                </dd>
              </dl>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="rounded-md border border-[var(--border-default)] px-2.5 py-1.5 text-[11px] font-medium disabled:opacity-40"
                  disabled={
                    selected.status === "quarantined" || mutation.isPending
                  }
                  onClick={() => {
                    setFlash(null);
                    setReason("");
                    setPending({ kind: "quarantine", server: selected });
                  }}
                >
                  Quarantine
                </button>
                <button
                  type="button"
                  className="rounded-md border border-[var(--border-default)] px-2.5 py-1.5 text-[11px] font-medium disabled:opacity-40"
                  disabled={
                    selected.status !== "quarantined" || mutation.isPending
                  }
                  onClick={() => {
                    setFlash(null);
                    setReason("");
                    setPending({ kind: "restore", server: selected });
                  }}
                >
                  Restore
                </button>
              </div>

              <div>
                <h3 className="mb-2 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                  Manifest history
                </h3>
                {historyQuery.isLoading ? (
                  <p className="text-[11px] text-[var(--text-muted)]">
                    Loading history…
                  </p>
                ) : historyQuery.error ? (
                  <p className="text-[11px] text-[var(--sev-high)]">
                    {errorMessage(historyQuery.error)}
                  </p>
                ) : (
                  <ul className="mb-4 max-h-32 space-y-1 overflow-auto text-[11px]">
                    {(historyQuery.data ?? []).map((snap, i) => (
                      <li
                        key={snap.id ?? `${snap.manifest_hash}-${i}`}
                        className="flex flex-wrap items-center gap-2 rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1"
                      >
                        <HashChip hash={snap.manifest_hash} kind="manifest" />
                        <span className="text-[var(--text-muted)]">
                          {formatTime(snap.created_at) || "—"}
                        </span>
                        {i === 0 ? (
                          <span className="text-[10px] text-[var(--state-verified)]">
                            latest
                          </span>
                        ) : null}
                      </li>
                    ))}
                    {(historyQuery.data ?? []).length === 0 ? (
                      <li className="text-[var(--text-muted)]">
                        No history snapshots.
                      </li>
                    ) : null}
                  </ul>
                )}
              </div>

              <div>
                <h3 className="mb-2 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                  Tools
                </h3>
                {toolsQuery.isLoading ? (
                  <p className="text-[11px] text-[var(--text-muted)]">
                    Loading tools…
                  </p>
                ) : toolsQuery.error ? (
                  <p className="text-[11px] text-[var(--sev-high)]">
                    {errorMessage(toolsQuery.error)}
                  </p>
                ) : (
                  <ul className="max-h-64 space-y-1 overflow-auto text-[11px]">
                    {(toolsQuery.data ?? []).map((t) => (
                      <li
                        key={t.tool_key}
                        className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1.5"
                      >
                        <span className="font-mono font-medium">
                          {t.tool_key}
                        </span>
                        {t.mutates_state ? (
                          <span className="ml-2 text-[var(--decision-approval)]">
                            mutates
                          </span>
                        ) : null}
                        {t.approval_required ? (
                          <span className="ml-2 text-[var(--decision-approval)]">
                            approval
                          </span>
                        ) : null}
                        {t.description ? (
                          <p className="mt-0.5 text-[var(--text-muted)]">
                            {t.description}
                          </p>
                        ) : null}
                      </li>
                    ))}
                    {(toolsQuery.data ?? []).length === 0 ? (
                      <li className="text-[var(--text-muted)]">No tools.</li>
                    ) : null}
                  </ul>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {pending ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface-overlay)] p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md space-y-3 rounded-[var(--radius-panel)] border border-[var(--border-default)] bg-[var(--surface-modal)] p-4 shadow-[var(--shadow-elevated)]">
            <h2 className="text-sm font-bold uppercase tracking-wider">
              Confirm {pending.kind}
            </h2>
            <p className="font-mono text-xs text-[var(--text-secondary)]">
              {pending.server.server_key}
            </p>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Reason
              <textarea
                className="input-field min-h-[64px] resize-y normal-case tracking-normal"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs"
                onClick={() => setPending(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={mutation.isPending}
                onClick={() => mutation.mutate()}
              >
                {mutation.isPending ? "Working…" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
