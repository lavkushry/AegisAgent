"use client";

import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { getAgents, freezeAgent, unfreezeAgent } from "../app/api";
import { ShieldCheck, ShieldAlert, Zap, Lock, Unlock, AlertTriangle } from "lucide-react";
import StatusBadge from "./security/StatusBadge";

export default function AgentsTab() {
  const { gatewayUrl, bearerToken } = useAppStore();
  const apiOpts = { gatewayUrl, bearerToken };
  const queryClient = useQueryClient();

  // Fetch agents list
  const { data: agents, isLoading, error } = useQuery({
    queryKey: ["agents", gatewayUrl, bearerToken],
    queryFn: () => getAgents(apiOpts),
    refetchInterval: 5000,
  });

  const freezeMutation = useMutation({
    mutationFn: (id: string) => freezeAgent(apiOpts, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  const unfreezeMutation = useMutation({
    mutationFn: (id: string) => unfreezeAgent(apiOpts, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
  });

  const handleToggleFreeze = (id: string, isFrozen: boolean) => {
    if (isFrozen) {
      unfreezeMutation.mutate(id);
    } else {
      freezeMutation.mutate(id);
    }
  };

  return (
    <div className="panel-card space-y-4">
      <div className="border-b border-[var(--border-default)] pb-3">
        <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider flex items-center gap-1.5">
          <Zap size={14} className="text-[var(--brand)]" /> Agents Fleet Inventory
        </h3>
      </div>

      {isLoading ? (
        <p className="text-sm text-[var(--text-muted)] text-center py-16">Loading fleet info...</p>
      ) : error ? (
        <p className="text-sm text-red-400 text-center py-16">Error: {(error as any).message}</p>
      ) : !agents || agents.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center text-[var(--text-muted)]">
          <ShieldAlert size={48} className="mb-4" />
          <h4 className="text-sm font-semibold">No Registered Agents</h4>
          <p className="text-xs max-w-xs mt-1">Register agents using the gateway API or SDK to monitor them here.</p>
        </div>
      ) : (
        <div className="overflow-x-auto custom-scrollbar">
          <table className="w-full text-left text-xs min-w-[700px]">
            <thead>
              <tr className="border-b border-[var(--border-default)] text-[var(--text-muted)] uppercase text-[10px] tracking-wider font-semibold">
                <th className="py-2.5">Agent Key</th>
                <th className="py-2.5">Status</th>
                <th className="py-2.5">Risk Tier</th>
                <th className="py-2.5">Environment</th>
                <th className="py-2.5">Model / System</th>
                <th className="py-2.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent: any) => {
                const isFrozen = agent.status === "frozen" || agent.status === "quarantined";
                return (
                  <tr key={agent.id} className="border-b border-[var(--border-default)] hover:bg-[var(--border-default)]/20 transition-colors">
                    <td className="py-3.5 font-mono text-[var(--brand)] font-bold">{agent.id}</td>
                    <td className="py-3.5"><StatusBadge status={agent.status} /></td>
                    <td className="py-3.5 font-semibold text-rose-400">{agent.risk_tier || "low"}</td>
                    <td className="py-3.5 font-mono text-[var(--text-secondary)]">{agent.environment || "production"}</td>
                    <td className="py-3.5 text-[var(--text-primary)]">{agent.model || "N/A"}</td>
                    <td className="py-3.5 text-right">
                      {agent.status !== "revoked" ? (
                        <button
                          onClick={() => handleToggleFreeze(agent.id, agent.status === "frozen")}
                          disabled={freezeMutation.isPending || unfreezeMutation.isPending}
                          className={`inline-flex items-center gap-1 text-[11px] font-semibold border rounded-lg px-3 py-1 cursor-pointer transition-colors ${
                            agent.status === "frozen"
                              ? "bg-green-950/20 border-green-500/30 text-green-400 hover:bg-green-900/10"
                              : "bg-amber-950/20 border-amber-500/30 text-amber-400 hover:bg-amber-900/10"
                          }`}
                        >
                          {agent.status === "frozen" ? (
                            <>
                              <Unlock size={12} /> Restore Agent
                            </>
                          ) : (
                            <>
                              <Lock size={12} /> Freeze Agent
                            </>
                          )}
                        </button>
                      ) : (
                        <span className="text-[var(--text-muted)] italic">Revoked</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
