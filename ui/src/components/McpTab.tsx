"use client";

import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getMcpServers, quarantineMcpServer, restoreMcpServer, getMcpManifestHistory } from "../app/api";
import { Server, Lock, Unlock, History, Clock } from "lucide-react";
import StatusBadge from "./security/StatusBadge";
import { errorMessage } from "@/lib/format";

export default function McpTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [selectedServerKey, setSelectedServerKey] = useState<string | null>(null);

  // Fetch MCP servers list
  const { data: servers, isLoading, error } = useQuery({
    queryKey: ["mcpServers", gatewayUrl, activeTenant, authEpoch],
    queryFn: () => getMcpServers(apiOpts),
    refetchInterval: 5000,
  });

  // Fetch manifest history for selected server
  const { data: history, isLoading: isHistoryLoading } = useQuery({
    queryKey: ["mcpHistory", gatewayUrl, activeTenant, authEpoch, selectedServerKey],
    queryFn: () => getMcpManifestHistory(apiOpts, selectedServerKey!),
    enabled: !!selectedServerKey,
  });

  const quarantineMutation = useMutation({
    mutationFn: (key: string) => quarantineMcpServer(apiOpts, key),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
  });

  const restoreMutation = useMutation({
    mutationFn: (key: string) => restoreMcpServer(apiOpts, key),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mcpServers"] });
    },
  });

  const handleToggleQuarantine = (key: string, isQuarantined: boolean) => {
    if (isQuarantined) {
      restoreMutation.mutate(key);
    } else {
      quarantineMutation.mutate(key);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* MCP Servers List */}
      <div className="panel-card lg:col-span-1 space-y-4">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
          <Server size={14} className="text-[var(--brand)]" /> MCP Servers Registry
        </h3>

        {isLoading ? (
          <p className="text-xs text-[var(--text-muted)] text-center py-8">Loading MCP servers...</p>
        ) : error ? (
          <p className="text-xs text-red-400 text-center py-8">Error: {errorMessage(error)}</p>
        ) : !servers || servers.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center text-[var(--text-muted)]">
            <Server size={36} className="mb-4" />
            <h4 className="text-xs font-semibold">No Registered Servers</h4>
            <p className="text-[10px] max-w-xs mt-1">MCP servers will appear here once registered with the gateway daemon.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {servers.map((srv) => (
              <div
                key={srv.server_key}
                onClick={() => setSelectedServerKey(srv.server_key)}
                className={`p-3 border rounded-lg cursor-pointer transition-colors text-xs ${
                  selectedServerKey === srv.server_key
                    ? "bg-[var(--brand)]/10 border-[var(--border-active)]"
                    : "bg-[var(--surface-app)]/40 border-[var(--border-default)] hover:border-[var(--border-default)]"
                }`}
              >
                <div className="flex justify-between items-start">
                  <span className="font-bold text-[var(--brand)] font-mono truncate max-w-[120px]">{srv.server_key}</span>
                  <StatusBadge status={srv.status || "healthy"} size="sm" />
                </div>
                <div className="flex flex-col gap-1 mt-2 text-[10px] text-[var(--text-secondary)] font-mono">
                  <span className="truncate">Manifest Hash: {srv.manifest_hash ? srv.manifest_hash.slice(0, 16) : "N/A"}</span>
                  <span>Transport: {srv.transport || "stdio"}</span>
                </div>
                <div className="text-right mt-3">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleToggleQuarantine(srv.server_key, srv.status === "quarantined");
                    }}
                    disabled={quarantineMutation.isPending || restoreMutation.isPending}
                    className={`inline-flex items-center gap-0.5 text-[9px] font-semibold border rounded px-2 py-0.5 cursor-pointer ${
                      srv.status === "quarantined"
                        ? "bg-green-950/20 border-green-500/30 text-green-400"
                        : "bg-rose-950/20 border-rose-500/30 text-rose-400"
                    }`}
                  >
                    {srv.status === "quarantined" ? (
                      <>
                        <Unlock size={10} /> Restore
                      </>
                    ) : (
                      <>
                        <Lock size={10} /> Quarantine
                      </>
                    )}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Manifest Drift History Details */}
      <div className="panel-card lg:col-span-2 space-y-4">
        {!selectedServerKey ? (
          <div className="flex flex-col items-center justify-center py-24 text-center text-[var(--text-muted)]">
            <History size={36} className="mb-4 animate-pulse" />
            <h4 className="text-xs font-semibold">Select an MCP Server</h4>
            <p className="text-[10px] max-w-xs mt-1">Select a server to view its manifest drift history and logs.</p>
          </div>
        ) : (
          <>
            <div className="border-b border-[var(--border-default)] pb-3 flex justify-between items-center">
              <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
                <History size={14} className="text-[var(--brand)]" /> Manifest Drift History &middot; <code className="text-[var(--brand)] font-bold">{selectedServerKey}</code>
              </h3>
            </div>

            {isHistoryLoading ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-8">Loading manifest history...</p>
            ) : !history || history.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)] text-center py-8">No drift history logs available for this server.</p>
            ) : (
              <div className="space-y-3 max-h-[350px] overflow-y-auto custom-scrollbar">
                {history.map((record, idx: number) => (
                  <div key={idx} className="p-3 bg-[var(--surface-app)]/40 border border-[var(--border-default)] rounded-lg text-xs flex justify-between items-start gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[8px] font-extrabold ${record.event_type === "drift" ? "bg-amber-500/20 text-amber-400" : "bg-green-500/20 text-green-400"}`}>
                          {record.event_type ? record.event_type.toUpperCase() : "LOG"}
                        </span>
                        <code className="text-[var(--brand)] font-mono text-[10px]">{record.manifest_hash ? record.manifest_hash.slice(0, 16) : "N/A"}</code>
                      </div>
                      <p className="text-[var(--text-secondary)] text-[11px] font-sans mt-1">
                        {record.description || record.details || "Manifest check processed successfully."}
                      </p>
                    </div>
                    <span className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap flex items-center gap-1">
                      <Clock size={10} /> {new Date(record.created_at || record.ts || 0).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
