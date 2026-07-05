"use client";

import React, { useEffect, useMemo, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useAppStore } from "../app/store";
import { fieldsForEntity } from "@/datasources/fieldCatalog";
import { ReceiptDatasource } from "@/datasources/receipt";
import { SocQueryDatasource } from "@/datasources/socQuery";
import { Search, ChevronDown, ChevronUp, Check, AlertTriangle, Fingerprint } from "lucide-react";
import DecisionBadge from "./security/DecisionBadge";
import TrustBadge from "./security/TrustBadge";
import HashChip from "./security/HashChip";
import JsonViewer from "@/components/primitives/JsonViewer";
import {
  appendAqlFilter,
  buildExploreRequest,
  decisionRowsFromFrame,
  exploreEventTime,
  exploreReceiptId,
  exploreResultCount,
  parsedAqlChips,
  type ExploreEntity,
  type ExploreEventRecord,
} from "./exploreData";
import FieldSidebar from "./filters/FieldSidebar";
import { formatTime, errorMessage } from "@/lib/format";

type VerifyState =
  | { status: "idle" }
  | { status: "running" }
  | { status: "verified"; message: string }
  | { status: "failed"; message: string }
  | { status: "unknown"; message: string };

export default function ExploreTab() {
  const { gatewayUrl, bearerToken, activeTenant, authEpoch } = useAppStore();
  const exploreSeed = useAppStore((s) => s.exploreSeed);
  const consumeExploreSeed = useAppStore((s) => s.consumeExploreSeed);
  const exploreQuery = useAppStore((s) => s.exploreQuery);
  const setExploreQuery = useAppStore((s) => s.setExploreQuery);
  const timeRange = useAppStore((s) => s.timeRange);
  const apiOpts = useMemo(
    () => ({ gatewayUrl, bearerToken, tenantId: activeTenant }),
    [gatewayUrl, bearerToken, activeTenant],
  );
  const decisionDatasource = useMemo(
    () => new SocQueryDatasource(apiOpts),
    [apiOpts],
  );
  const receiptDatasource = useMemo(
    () => new ReceiptDatasource(apiOpts),
    [apiOpts],
  );

  const [entity, setEntity] = useState<ExploreEntity>("decision");
  const [searchQuery, setSearchQuery] = useState(() => exploreSeed ?? exploreQuery);
  const [debouncedQuery, setDebouncedQuery] = useState(() => exploreSeed ?? exploreQuery);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [verifyStates, setVerifyStates] = useState<Record<string, VerifyState>>({});

  useEffect(() => {
    if (exploreSeed) consumeExploreSeed();
    // Mount-only seed consumption.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fieldDescriptors = useMemo(() => fieldsForEntity(entity), [entity]);
  const activeFilters = useMemo(() => parsedAqlChips(debouncedQuery), [debouncedQuery]);

  const { data: decisionFrame, isLoading, error, isFetching } = useQuery({
    queryKey: ["explore", entity, gatewayUrl, activeTenant, authEpoch, debouncedQuery, timeRange],
    queryFn: ({ signal }) => decisionDatasource.query(
      buildExploreRequest(entity, debouncedQuery, timeRange, signal),
    ),
    refetchInterval: 10000,
  });
  const events = useMemo(() => decisionRowsFromFrame(decisionFrame), [decisionFrame]);
  const resultCount = exploreResultCount(decisionFrame);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setDebouncedQuery(searchQuery.trim());
    setExploreQuery(searchQuery.trim());
    setExpandedId(null);
    setVerifyStates({});
  };

  const applyFacetFilter = (field: string, value: string) => {
    const next = appendAqlFilter(searchQuery, field, value);
    setSearchQuery(next);
    setDebouncedQuery(next);
    setExploreQuery(next);
    setExpandedId(null);
    setVerifyStates({});
  };

  const verifyMutation = useMutation({
    mutationFn: (receiptId: string) => receiptDatasource.verifyReceipt!(receiptId),
    onSuccess: (result, receiptId) => {
      setVerifyStates((prev) => ({
        ...prev,
        [receiptId]: {
          status: result.status === "verified" ? "verified" : result.status === "unknown" ? "unknown" : "failed",
          message: result.message,
        },
      }));
    },
    onError: (err: unknown, receiptId) => {
      setVerifyStates((prev) => ({
        ...prev,
        [receiptId]: { status: "failed", message: errorMessage(err) },
      }));
    },
  });

  const triggerVerification = (row: ExploreEventRecord) => {
    const receiptId = exploreReceiptId(row);
    if (!receiptId) {
      setVerifyStates((prev) => ({
        ...prev,
        [row.id]: { status: "unknown", message: "No receipt_id is linked to this event." },
      }));
      return;
    }
    setVerifyStates((prev) => ({ ...prev, [receiptId]: { status: "running" } }));
    verifyMutation.mutate(receiptId);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Explore / Discover</h2>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">
            Structured AQL filters over gateway-backed {entity === "ase" ? "Agent Security Events" : "authorization decisions"}.
          </p>
        </div>
        <div className="flex items-center gap-1 rounded-lg border border-[var(--border-default)] p-1 text-xs">
          {(["decision", "ase"] as const).map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => {
                setEntity(option);
                setExpandedId(null);
                setVerifyStates({});
              }}
              className={`rounded-md px-3 py-1.5 cursor-pointer transition-colors ${
                entity === option
                  ? "bg-[var(--brand)] text-white"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              {option === "decision" ? "Decisions" : "ASE"}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleSearch} className="space-y-2">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="AQL: agent_id:coding-agent AND decision:deny AND tool:github"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[var(--surface-panel)] border border-[var(--border-default)] rounded-lg pl-10 pr-4 py-2 text-sm text-[var(--text-primary)] focus:border-[var(--border-active)] focus:outline-none"
              aria-label="Explore AQL query"
            />
            <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={16} />
          </div>
          <button
            type="submit"
            className="bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-white font-medium text-sm rounded-lg px-6 py-2 transition-colors cursor-pointer"
          >
            Search
          </button>
        </div>
        {activeFilters.length > 0 ? (
          <div className="flex flex-wrap items-center gap-2 text-[10px]">
            <span className="text-[var(--text-muted)] uppercase tracking-wider font-semibold">Active filters</span>
            {activeFilters.map((chip) => (
              <span
                key={`${chip.field}:${chip.value}`}
                className="rounded border border-[var(--border-default)] px-2 py-0.5 font-mono text-[var(--text-secondary)]"
              >
                {chip.field}:{chip.value}
              </span>
            ))}
          </div>
        ) : null}
      </form>

      <div className="grid grid-cols-1 lg:grid-cols-[210px_minmax(0,1fr)] gap-4">
        <FieldSidebar
          descriptors={fieldDescriptors}
          rows={events as Array<Record<string, unknown>>}
          onSelect={applyFacetFilter}
        />

        <div className="panel-card min-w-0">
          <div className="flex items-center justify-between gap-3 mb-4">
            <h3 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider">
              {entity === "ase" ? "Agent Security Events" : "Authorization Decisions"}
            </h3>
            <span className="text-[10px] text-[var(--text-muted)] font-mono">
              {isFetching ? "Refreshing…" : resultCount !== undefined ? `${resultCount} result${resultCount === 1 ? "" : "s"}` : ""}
            </span>
          </div>

          {isLoading ? (
            <p className="text-sm text-[var(--text-muted)] text-center py-12">Querying gateway records…</p>
          ) : error ? (
            <p className="text-sm text-center py-12" style={{ color: "var(--state-failed)" }} role="alert">
              Query failed: {errorMessage(error)}
            </p>
          ) : events.length === 0 ? (
            <p className="text-sm text-[var(--text-muted)] text-center py-12">No events matched the query.</p>
          ) : (
            <div className="space-y-2">
              {events.map((event) => (
                <ExploreEventRow
                  key={event.id}
                  event={event}
                  entity={entity}
                  expanded={expandedId === event.id}
                  verifyState={verifyStates[exploreReceiptId(event) ?? event.id] ?? { status: "idle" }}
                  onToggle={() => setExpandedId(expandedId === event.id ? null : event.id)}
                  onVerify={() => triggerVerification(event)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ExploreEventRow({
  event,
  entity,
  expanded,
  verifyState,
  onToggle,
  onVerify,
}: {
  event: ExploreEventRecord;
  entity: ExploreEntity;
  expanded: boolean;
  verifyState: VerifyState;
  onToggle: () => void;
  onVerify: () => void;
}) {
  const label =
    event.tool_call?.name
    || event.tool
    || event.skill
    || event.event_type
    || "event";
  const receiptId = exploreReceiptId(event);

  return (
    <div className="border border-[var(--border-default)] hover:border-[var(--border-default)] rounded-lg overflow-hidden bg-[var(--surface-app)]/50">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex flex-wrap md:flex-nowrap justify-between items-center gap-4 p-4 cursor-pointer select-none hover:bg-[var(--surface-panel)]/40 transition-colors text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          {event.decision ? <DecisionBadge decision={event.decision} /> : null}
          <div className="flex flex-col min-w-0">
            <span className="text-xs font-mono font-bold text-[var(--brand)] truncate">{label}</span>
            <span className="text-[10px] text-[var(--text-muted)] mt-0.5 font-mono truncate">
              Agent: {event.agent_id || "—"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <TrustBadge trust={event.root_trust_level || event.source_trust} />
          <span className="text-xs text-[var(--text-muted)]">{formatTime(exploreEventTime(event))}</span>
          {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </div>
      </button>

      {expanded ? (
        <div className="p-4 bg-[var(--surface-panel)]/60 border-t border-[var(--border-default)] space-y-4 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <InspectorField label="Reason" value={event.reason || "N/A"} />
              <InspectorField
                label="Matched Policies"
                value={event.matched_policies?.join(", ") || event.matched_policy_ids?.join(", ") || "none"}
              />
              <InspectorField label="Run ID" value={event.run_id || "N/A"} mono />
              <InspectorField label="Trace ID" value={event.trace_id || "N/A"} mono />
            </div>
            <div className="space-y-2">
              <div>
                <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Action Hash</span>
                <HashChip hash={event.action_hash} kind="action" head={16} tail={8} />
              </div>
              <div>
                <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">Receipt Hash</span>
                <HashChip hash={event.receipt_hash} kind="receipt" head={16} tail={8} />
              </div>
              <InspectorField
                label="Composite Risk Score"
                value={event.composite_risk_score ?? "N/A"}
                advisory
              />
            </div>
          </div>

          <div>
            <span className="text-[10px] font-semibold text-[var(--text-muted)] uppercase tracking-wider block mb-2">
              Redacted event document
            </span>
            <JsonViewer value={event} />
          </div>

          {entity === "decision" ? (
            <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-[var(--border-default)]">
              <div className="flex items-center gap-1.5 text-[var(--text-secondary)]">
                <Fingerprint size={16} />
                <span>
                  {receiptId
                    ? "Receipt linked — verify cryptographic integrity before trusting this row."
                    : "No receipt_id linked — verification unavailable for this row."}
                </span>
              </div>

              <div className="flex items-center gap-3">
                {verifyState.status !== "idle" ? <VerifyStatusBadge state={verifyState} /> : null}
                <button
                  type="button"
                  onClick={onVerify}
                  disabled={verifyState.status === "running" || !receiptId}
                  className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] border border-[var(--border-default)] px-3.5 py-1.5 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                >
                  Verify receipt
                </button>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function InspectorField({
  label,
  value,
  mono = false,
  advisory = false,
}: {
  label: string;
  value: string | number;
  mono?: boolean;
  advisory?: boolean;
}) {
  return (
    <div>
      <span className="text-[var(--text-muted)] block uppercase text-[10px] tracking-wider font-semibold">{label}</span>
      <span
        className={`text-[var(--text-primary)] ${mono ? "font-mono" : "font-medium"}`}
        style={advisory ? { color: "var(--state-pending)" } : undefined}
      >
        {value}
      </span>
    </div>
  );
}

function VerifyStatusBadge({ state }: { state: VerifyState }) {
  if (state.status === "idle") {
    return null;
  }
  if (state.status === "running") {
    return <span className="text-[var(--state-pending)]">Verifying…</span>;
  }
  const color =
    state.status === "verified"
      ? "var(--state-verified)"
      : state.status === "unknown"
        ? "var(--state-pending)"
        : "var(--state-failed)";
  return (
    <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs" style={{ color, borderColor: `color-mix(in oklab, ${color} 40%, transparent)` }}>
      {state.status === "verified" ? <Check size={14} /> : <AlertTriangle size={14} />}
      <span>{state.message}</span>
    </span>
  );
}