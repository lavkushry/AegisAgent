"use client";

import React, { useEffect, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { searchDecisions, verifyReceipt } from "../app/api";
import { parseAql } from "@/datasources/aql/parse";
import { Search, ChevronDown, ChevronUp, Check, AlertTriangle, Cpu, Fingerprint } from "lucide-react";
import DecisionBadge from "./security/DecisionBadge";
import TrustBadge from "./security/TrustBadge";
import HashChip from "./security/HashChip";
import FieldSidebar from "./filters/FieldSidebar";
import { formatTime, errorMessage } from "@/lib/format";

// Loosely-typed decision record from the gateway. The datasource/DataFrame
// layer (HLD/LLD section 5) will replace this with a generated type.
interface DecisionRecord {
  id: string;
  decision?: string;
  tool?: string;
  skill?: string;
  tool_call?: { name?: string; parameters?: Record<string, unknown> };
  agent_id?: string;
  root_trust_level?: string;
  source_trust?: string;
  created_at?: string;
  ts?: string;
  reason?: string;
  matched_policies?: string[];
  matched_policy_ids?: string[];
  run_id?: string;
  action_hash?: string;
  composite_risk_score?: number;
}

export default function ExploreTab() {
  const { gatewayUrl, bearerToken } = useAppStore();
  const exploreSeed = useAppStore((s) => s.exploreSeed);
  const consumeExploreSeed = useAppStore((s) => s.consumeExploreSeed);
  const apiOpts = { gatewayUrl, bearerToken };

  // Seed the query from a drilldown at mount (this tab remounts on switch).
  const [searchQuery, setSearchQuery] = useState(() => exploreSeed ?? "");
  const [debouncedQuery, setDebouncedQuery] = useState(() => exploreSeed ?? "");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<Record<string, { ok: boolean; msg: string; loading: boolean }>>({});

  // Clear the one-time seed after the initializers above have consumed it.
  useEffect(() => {
    if (exploreSeed) consumeExploreSeed();
    // Mount-only: the seed is read once via the useState initializers.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fetch decisions based on query
  const { data: decisions, isLoading, error } = useQuery({
    queryKey: ["decisions", gatewayUrl, bearerToken, debouncedQuery],
    queryFn: () => searchDecisions(apiOpts, { limit: 50, ...parseAql(debouncedQuery) }),
    refetchInterval: 10000, // Poll every 10s
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setDebouncedQuery(searchQuery);
  };

  const verifyMutation = useMutation({
    mutationFn: (receiptId: string) => verifyReceipt(apiOpts, receiptId),
    onSuccess: (data, receiptId) => {
      // Assuming response is like { verified: true, error: null } or similar
      const isVerified = data.verified || (data.status === "verified") || (!data.error);
      const message = data.error ? `Tamper detected: ${data.error}` : "Receipt cryptographic signature matches the hash chain.";
      setVerificationResult((prev) => ({
        ...prev,
        [receiptId]: { ok: isVerified, msg: message, loading: false },
      }));
    },
    onError: (err: unknown, receiptId) => {
      setVerificationResult((prev) => ({
        ...prev,
        [receiptId]: { ok: false, msg: `Verification failed: ${errorMessage(err)}`, loading: false },
      }));
    },
  });

  const triggerVerification = (receiptId: string) => {
    setVerificationResult((prev) => ({
      ...prev,
      [receiptId]: { ok: false, msg: "", loading: true },
    }));
    verifyMutation.mutate(receiptId);
  };

  return (
    <div className="space-y-4">
      {/* Query Bar */}
      <form onSubmit={handleSearch} className="flex gap-2">
        <div className="relative flex-1">
          <input
            type="text"
            placeholder="AQL: agent_id:coding-agent AND decision:deny untrusted   (field:value + keywords)"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[var(--surface-panel)] border border-[var(--border-default)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none"
          />
          <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={16} />
        </div>
        <button
          type="submit"
          className="bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-white font-medium text-sm rounded-lg px-6 py-2 transition-colors cursor-pointer"
        >
          Search
        </button>
      </form>

      <div className="grid grid-cols-1 lg:grid-cols-[210px_minmax(0,1fr)] gap-4">
        {/* Field facet sidebar (computed from loaded results) */}
        <FieldSidebar
          rows={(decisions ?? []) as Array<Record<string, unknown>>}
          onSelect={(field, value) => {
            const q = `${field}:${value}`;
            setSearchQuery(q);
            setDebouncedQuery(q);
          }}
        />

        {/* Decisions Results List */}
        <div className="panel-card min-w-0">
          <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-4">
            FTS5 Decision Index Explorer
          </h3>

        {isLoading ? (
          <p className="text-sm text-[var(--text-muted)] text-center py-12">Querying decision records...</p>
        ) : error ? (
          <p className="text-sm text-red-400 text-center py-12">Error: {errorMessage(error)}</p>
        ) : !decisions || decisions.length === 0 ? (
          <p className="text-sm text-[var(--text-muted)] text-center py-12">No decisions matched the query.</p>
        ) : (
          <div className="space-y-2">
            {decisions.map((dec: DecisionRecord) => {
              const isExpanded = expandedId === dec.id;
              const vResult = verificationResult[dec.id];
              return (
                <div
                  key={dec.id}
                  className="border border-[var(--border-default)] hover:border-[var(--border-default)] rounded-lg overflow-hidden bg-[var(--surface-app)]/50"
                >
                  {/* Row Header */}
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : dec.id)}
                    className="flex flex-wrap md:flex-nowrap justify-between items-center gap-4 p-4 cursor-pointer select-none hover:bg-[var(--surface-panel)]/40 transition-colors"
                  >
                    <div className="flex items-center gap-3">
                      <DecisionBadge decision={dec.decision} />
                      <div className="flex flex-col">
                        <span className="text-xs font-mono font-bold text-[var(--brand)]">
                          {dec.tool_call?.name || dec.skill || dec.tool || "generic_action"}
                        </span>
                        <span className="text-[10px] text-[var(--text-muted)] mt-0.5 font-mono">
                          Agent: {dec.agent_id}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <TrustBadge trust={dec.root_trust_level || dec.source_trust} />
                      <span className="text-xs text-[var(--text-muted)]">
                        {formatTime(dec.created_at || dec.ts)}
                      </span>
                      {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </div>
                  </div>

                  {/* Expanded Inspector View */}
                  {isExpanded && (
                    <div className="p-4 bg-[var(--surface-panel)]/60 border-t border-[var(--border-default)] space-y-4 text-xs">
                      {/* Grid Properties */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <div>
                            <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Reason</span>
                            <span className="text-[var(--text-primary)] font-medium">{dec.reason || "N/A"}</span>
                          </div>
                          <div>
                            <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Matched Policies</span>
                            <span className="text-[var(--text-primary)] font-mono">{dec.matched_policies?.join(", ") || dec.matched_policy_ids?.join(", ") || "none"}</span>
                          </div>
                          <div>
                            <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Run ID</span>
                            <span className="text-[var(--text-primary)] font-mono">{dec.run_id || "N/A"}</span>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <div>
                            <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Action Hash</span>
                            <HashChip hash={dec.action_hash} kind="action" head={16} tail={8} />
                          </div>
                          <div>
                            <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Composite Risk Score</span>
                            <span className="text-[var(--text-primary)] font-bold text-amber-500">{dec.composite_risk_score ?? "N/A"}</span>
                          </div>
                        </div>
                      </div>

                      {/* Tool Parameters JSON Inspector */}
                      {dec.tool_call?.parameters && (
                        <div className="bg-[var(--surface-app)] rounded-lg p-3 border border-[var(--border-default)] max-h-40 overflow-y-auto custom-scrollbar">
                          <span className="text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-wider block mb-2">Parameters</span>
                          <pre className="text-[11px] font-mono text-[var(--brand)] whitespace-pre-wrap">
                            {JSON.stringify(dec.tool_call.parameters, null, 2)}
                          </pre>
                        </div>
                      )}

                      {/* Cryptographic Verification Action */}
                      <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-[var(--border-default)]">
                        <div className="flex items-center gap-1.5">
                          <Fingerprint size={16} className="text-[var(--text-secondary)]" />
                          <span className="text-[var(--text-secondary)]">Verifiable receipt available for this transaction.</span>
                        </div>
                        
                        <div className="flex items-center gap-3">
                          {vResult && (
                            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${vResult.loading ? "bg-amber-950/20 border-amber-500/30 text-amber-400" : vResult.ok ? "bg-green-950/20 border-green-500/30 text-green-400" : "bg-red-950/20 border-red-500/30 text-red-400"}`}>
                              {vResult.loading ? (
                                <Cpu size={14} className="animate-spin" />
                              ) : vResult.ok ? (
                                <Check size={14} />
                              ) : (
                                <AlertTriangle size={14} />
                              )}
                              <span>{vResult.loading ? "Verifying signature..." : vResult.msg}</span>
                            </div>
                          )}
                          
                          <button
                            onClick={() => triggerVerification(dec.id)}
                            disabled={vResult?.loading}
                            className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-white border border-[var(--border-default)] px-3.5 py-1.5 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                          >
                            Verify Cryptographic Receipt
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
        </div>
      </div>
    </div>
  );
}
