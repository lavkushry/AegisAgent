"use client";

import React, { useMemo, useState } from "react";
import { Bookmark, Copy, Trash2 } from "lucide-react";
import type { ExploreEntity } from "@/components/exploreData";
import {
  deleteSavedSearch,
  listSavedSearches,
  saveSearch,
  validateSavedSearchInput,
} from "@/state/savedSearches";

type SavedSearchPanelProps = {
  tenantId: string;
  entity: ExploreEntity;
  aql: string;
  timeRange: string;
  onApply: (aql: string, entity: ExploreEntity, timeRange: string) => void;
};

export default function SavedSearchPanel({
  tenantId,
  entity,
  aql,
  timeRange,
  onApply,
}: SavedSearchPanelProps) {
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);

  const saved = useMemo(() => {
    void version;
    return listSavedSearches(tenantId);
  }, [tenantId, version]);

  const handleSave = () => {
    const validation = validateSavedSearchInput(name, aql);
    if (validation) {
      setError(validation);
      return;
    }
    try {
      saveSearch(tenantId, { name, aql, entity, timeRange });
      setName("");
      setError(null);
      setVersion((v) => v + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save search.");
    }
  };

  const copyShareLink = async () => {
    const params = new URLSearchParams({
      view: "explore",
      range: timeRange,
      entity,
    });
    if (aql.trim()) params.set("q", aql.trim());
    const url = `${window.location.origin}${window.location.pathname}?${params.toString()}`;
    try {
      await navigator.clipboard.writeText(url);
    } catch {
      setError("Clipboard unavailable — copy the URL from the address bar after searching.");
    }
  };

  return (
    <div className="rounded-lg border border-[var(--border-default)] bg-[var(--surface-app)]/40 p-3 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Bookmark size={12} className="text-[var(--brand)]" />
          Saved searches
        </span>
        <span className="rounded border border-amber-500/30 bg-amber-950/20 px-2 py-0.5 text-[9px] uppercase text-amber-300">
          Local to this browser · tenant {tenantId.slice(0, 8)}…
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name this investigation…"
          className="min-w-[180px] flex-1 rounded-md border border-[var(--border-default)] bg-[var(--surface-panel)] px-3 py-1.5 text-xs text-[var(--text-primary)]"
        />
        <button
          type="button"
          onClick={handleSave}
          disabled={!aql.trim()}
          className="rounded-md bg-[var(--brand)] px-3 py-1.5 text-[10px] font-bold uppercase text-white disabled:opacity-50"
        >
          Save
        </button>
        <button
          type="button"
          onClick={() => void copyShareLink()}
          className="flex items-center gap-1 rounded-md border border-[var(--border-default)] px-3 py-1.5 text-[10px] uppercase text-[var(--text-secondary)]"
        >
          <Copy size={12} /> Copy link
        </button>
      </div>
      {error ? (
        <p className="text-[10px] text-red-400" role="alert">
          {error}
        </p>
      ) : null}

      {saved.length === 0 ? (
        <p className="text-[10px] text-[var(--text-muted)]">No saved searches yet for this tenant.</p>
      ) : (
        <ul className="space-y-1">
          {saved.map((item) => (
            <li
              key={item.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded border border-[var(--border-default)]/60 px-2 py-1.5 text-[10px]"
            >
              <button
                type="button"
                onClick={() => onApply(item.aql, item.entity, item.timeRange)}
                className="text-left font-medium text-[var(--text-primary)] hover:text-[var(--brand)]"
              >
                {item.name}
                <span className="ml-2 font-mono text-[var(--text-muted)]">{item.aql}</span>
              </button>
              <button
                type="button"
                aria-label={`Delete saved search ${item.name}`}
                onClick={() => {
                  deleteSavedSearch(tenantId, item.id);
                  setVersion((v) => v + 1);
                }}
                className="text-[var(--text-muted)] hover:text-red-400"
              >
                <Trash2 size={12} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}