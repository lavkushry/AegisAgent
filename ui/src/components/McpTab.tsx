"use client";

import React, { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import {
  getMcpServers,
  getMcpManifestHistory,
  getMcpTools,
  quarantineMcpServer,
  restoreMcpServer,
} from "../app/api";
import { GatewayEntityDatasource } from "@/datasources/gatewayEntity";
import { alertRowsFromFrame, incidentRowsFromFrame } from "@/datasources/entityData";
import { errorMessage } from "@/lib/format";
import { ConfirmDialog } from "@/components/primitives";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import McpRegistry, { type McpRegistryEntry } from "@/components/mcp/McpRegistry";
import McpDetail from "@/components/mcp/McpDetail";
import { resolveMcpIntegrityStatus } from "@/components/mcp/driftState";
import { alertsForMcpServer, incidentsForMcpServer } from "@/components/mcp/linkedSoc";
import {
  mcpControlConfirmLabel,
  mcpControlDisabledReason,
  mcpControlImpact,
  mcpControlTitle,
  type McpControlKind,
} from "@/components/mcp/mcpControls";
import { History } from "lucide-react";

type PendingMcpAction = {
  kind: McpControlKind;
  serverKey: string;
};

const DEFAULT_TIME_RANGE = { from: "now-24h", to: "now" } as const;

export default function McpTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch, setActiveView } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const entityDatasource = useMemo(
    () => new GatewayEntityDatasource({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );
  const queryClient = useQueryClient();
  const { role } = useEffectiveRole();

  const [selectedServerKey, setSelectedServerKey] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingMcpAction | null>(null);
  const [auditReason, setAuditReason] = useState("");
  const [mutationError, setMutationError] = useState<string | null>(null);

  const { data: servers = [], isLoading, error } = useQuery({
    queryKey: ["mcpServers", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getMcpServers(apiOpts),
    refetchInterval: 5000,
  });

  const { data: history = [], isLoading: isHistoryLoading } = useQuery({
    queryKey: ["mcpHistory", gatewayUrl, activeTenant, authEpoch, selectedServerKey],
    queryFn: () => getMcpManifestHistory(apiOpts, selectedServerKey!),
    enabled: Boolean(selectedServerKey),
  });

  const { data: tools = [], isLoading: isToolsLoading } = useQuery({
    queryKey: ["mcpTools", gatewayUrl, activeTenant, authEpoch, selectedServerKey],
    queryFn: () => getMcpTools(apiOpts, selectedServerKey!),
    enabled: Boolean(selectedServerKey),
  });

  const { data: alertsFrame } = useQuery({
    queryKey: ["mcpLinkedAlerts", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        entity: "alert",
        limit: 100,
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
  });

  const { data: incidentsFrame } = useQuery({
    queryKey: ["mcpLinkedIncidents", gatewayUrl, activeTenant, authEpoch],
    queryFn: ({ signal }) =>
      entityDatasource.query({
        entity: "incident",
        limit: 50,
        timeRange: DEFAULT_TIME_RANGE,
        variables: {},
        signal,
      }),
  });

  const selectedServer = useMemo(
    () => servers.find((srv) => srv.server_key === selectedServerKey) ?? null,
    [servers, selectedServerKey],
  );

  const registryEntries: McpRegistryEntry[] = useMemo(
    () =>
      servers.map((srv) => ({
        ...srv,
        toolCount: srv.server_key === selectedServerKey ? tools.length : undefined,
        integrity: resolveMcpIntegrityStatus(
          srv,
          srv.server_key === selectedServerKey ? history : [],
        ),
      })),
    [servers, selectedServerKey, tools.length, history],
  );

  const linkedAlerts = useMemo(() => {
    if (!selectedServerKey) return [];
    return alertsForMcpServer(alertRowsFromFrame(alertsFrame), selectedServerKey);
  }, [alertsFrame, selectedServerKey]);

  const linkedIncidents = useMemo(() => {
    if (!selectedServerKey) return [];
    return incidentsForMcpServer(incidentRowsFromFrame(incidentsFrame), selectedServerKey);
  }, [incidentsFrame, selectedServerKey]);

  const quarantineMutation = useMutation({
    mutationFn: ({ key, reason }: { key: string; reason: string }) =>
      quarantineMcpServer(apiOpts, key, reason),
    onSuccess: () => {
      setPendingAction(null);
      setAuditReason("");
      setMutationError(null);
      queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (err: unknown) => setMutationError(errorMessage(err) || "Quarantine failed."),
  });

  const restoreMutation = useMutation({
    mutationFn: ({ key, reason }: { key: string; reason: string }) =>
      restoreMcpServer(apiOpts, key, reason),
    onSuccess: () => {
      setPendingAction(null);
      setAuditReason("");
      setMutationError(null);
      queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
    onError: (err: unknown) => setMutationError(errorMessage(err) || "Restore failed."),
  });

  const openControl = (kind: McpControlKind, serverKey: string) => {
    const server = servers.find((srv) => srv.server_key === serverKey);
    const disabled = mcpControlDisabledReason(kind, server?.status ?? "", role);
    if (disabled) {
      setMutationError(disabled);
      return;
    }
    setPendingAction({ kind, serverKey });
    setAuditReason("");
    setMutationError(null);
  };

  const confirmMcpAction = () => {
    if (!pendingAction || !auditReason.trim()) return;
    if (pendingAction.kind === "restore") {
      restoreMutation.mutate({ key: pendingAction.serverKey, reason: auditReason.trim() });
    } else {
      quarantineMutation.mutate({ key: pendingAction.serverKey, reason: auditReason.trim() });
    }
  };

  const roleDisabledReason = selectedServer
    ? mcpControlDisabledReason(
        selectedServer.status === "quarantined" ? "restore" : "quarantine",
        selectedServer.status ?? "",
        role,
      )
    : null;

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--text-primary)]">
          MCP Governance
        </h2>
        <p className="text-[11px] text-[var(--text-muted)]">
          Registry, manifest integrity, tool approval state, and tenant-scoped containment. Unknown
          verification never renders as healthy.
        </p>
      </div>

      {mutationError ? (
        <p className="rounded border border-red-500/30 bg-red-950/20 px-3 py-2 text-xs text-red-300">
          {mutationError}
        </p>
      ) : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <McpRegistry
          servers={registryEntries}
          selectedServerKey={selectedServerKey}
          onSelect={setSelectedServerKey}
          isLoading={isLoading}
          error={error ? errorMessage(error) : null}
        />

        {!selectedServer ? (
          <div className="panel-card flex flex-col items-center justify-center py-24 text-center text-[var(--text-muted)] lg:col-span-2">
            <History size={36} className="mb-4 animate-pulse" />
            <h4 className="text-xs font-semibold">Select an MCP Server</h4>
            <p className="mt-1 max-w-xs text-[10px]">
              Inspect manifest hashes, tool states, drift timeline, and linked SOC evidence.
            </p>
          </div>
        ) : (
          <McpDetail
            server={selectedServer}
            tools={tools}
            history={history}
            linkedAlerts={linkedAlerts}
            linkedIncidents={linkedIncidents}
            isToolsLoading={isToolsLoading}
            isHistoryLoading={isHistoryLoading}
            roleDisabledReason={roleDisabledReason}
            onQuarantine={() => openControl("quarantine", selectedServer.server_key)}
            onRestore={() => openControl("restore", selectedServer.server_key)}
            onViewDetections={() => setActiveView("detections")}
            onViewIncidents={() => setActiveView("incidents")}
            mutationsPending={quarantineMutation.isPending || restoreMutation.isPending}
          />
        )}
      </div>

      <ConfirmDialog
        open={pendingAction !== null}
        title={pendingAction ? mcpControlTitle(pendingAction.kind) : "Confirm MCP action"}
        impact={pendingAction ? mcpControlImpact(pendingAction.kind) : ""}
        target={pendingAction?.serverKey ?? ""}
        reason={auditReason}
        onReasonChange={setAuditReason}
        confirmLabel={pendingAction ? mcpControlConfirmLabel(pendingAction.kind) : "Confirm"}
        confirmDisabled={
          !auditReason.trim() || quarantineMutation.isPending || restoreMutation.isPending
        }
        onConfirm={confirmMcpAction}
        onCancel={() => {
          setPendingAction(null);
          setAuditReason("");
        }}
      />
    </div>
  );
}