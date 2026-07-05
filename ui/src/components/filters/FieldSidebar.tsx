"use client";

import React, { useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { fieldsForEntity } from "../../datasources/fieldCatalog";
import type { FieldDescriptor } from "../../datasources/types";
import DecisionBadge from "../security/DecisionBadge";
import TrustBadge from "../security/TrustBadge";

type FacetType = "decision" | "trust" | "string";

export interface FacetField {
  key: string;
  label: string;
  type: FacetType;
  /** Alternate keys to read the value from, in order. */
  altKeys?: ReadonlyArray<string>;
}

const DEFAULT_DESCRIPTORS = fieldsForEntity("decision");
const FACET_ALIASES: Readonly<Record<string, ReadonlyArray<string>>> = {
  source_trust: ["root_trust_level"],
  tool: ["skill", "tool_name"],
};

const TOP_N = 6;

type Row = Record<string, unknown>;

function facetType(field: FieldDescriptor): FacetType | null {
  if (field.type === "decision" || field.type === "trust" || field.type === "string") {
    return field.type;
  }
  return null;
}

export function descriptorFacets(descriptors: ReadonlyArray<FieldDescriptor>): ReadonlyArray<FacetField> {
  return descriptors.flatMap((descriptor) => {
    const type = facetType(descriptor);
    if (!descriptor.facetable || type === null) return [];
    return [{
      key: descriptor.name,
      label: descriptor.name,
      type,
      altKeys: FACET_ALIASES[descriptor.name],
    }];
  });
}

function readValue(row: Row, facet: FacetField): string {
  const keys = [facet.key, ...(facet.altKeys ?? [])];
  for (const k of keys) {
    const v = row[k];
    if (v !== null && v !== undefined && v !== "") return String(v);
  }
  // tool may live under tool_call.name
  if (facet.key === "tool") {
    const tc = row.tool_call;
    if (tc && typeof tc === "object" && "name" in tc) {
      const name = (tc as { name?: unknown }).name;
      if (name) return String(name);
    }
  }
  return "";
}

function countFacet(rows: ReadonlyArray<Row>, facet: FacetField): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const value = readValue(row, facet);
    if (!value) continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
}

type Props = {
  rows: ReadonlyArray<Row>;
  descriptors?: ReadonlyArray<FieldDescriptor>;
  onSelect: (field: string, value: string) => void;
};

/** Kibana-Discover-style facet sidebar computed from the loaded results. */
export default function FieldSidebar({ rows, descriptors = DEFAULT_DESCRIPTORS, onSelect }: Props) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const facets = useMemo(() => descriptorFacets(descriptors), [descriptors]);
  const facetData = useMemo(
    () => facets.map((facet) => ({ facet, values: countFacet(rows, facet) })),
    [facets, rows],
  );

  return (
    <aside className="panel-card h-fit space-y-3">
      <h3 className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
        Fields
      </h3>
      {facetData.map(({ facet, values }) => {
        const isCollapsed = collapsed[facet.key];
        return (
          <div key={facet.key} className="border-t border-[var(--border-default)] pt-2 first:border-t-0 first:pt-0">
            <button
              type="button"
              onClick={() => setCollapsed((c) => ({ ...c, [facet.key]: !c[facet.key] }))}
              className="w-full flex items-center justify-between text-[11px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
            >
              <span className="flex items-center gap-1">
                {isCollapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                {facet.label}
              </span>
              <span className="text-[var(--text-muted)]">{values.length}</span>
            </button>
            {!isCollapsed ? (
              <ul className="mt-1.5 space-y-1">
                {values.slice(0, TOP_N).map(([value, count]) => (
                  <li key={value}>
                    <button
                      type="button"
                      onClick={() => onSelect(facet.key, value)}
                      className="w-full flex items-center justify-between gap-2 text-left group cursor-pointer"
                      title={`Filter by ${facet.key}:${value}`}
                    >
                      <span className="truncate">
                        {facet.type === "decision" ? (
                          <DecisionBadge decision={value} />
                        ) : facet.type === "trust" ? (
                          <TrustBadge trust={value} />
                        ) : (
                          <span className="text-[11px] font-mono text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] truncate">
                            {value}
                          </span>
                        )}
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)] tabular-nums shrink-0">{count}</span>
                    </button>
                  </li>
                ))}
                {values.length === 0 ? (
                  <li className="text-[10px] text-[var(--text-muted)]">no values</li>
                ) : null}
              </ul>
            ) : null}
          </div>
        );
      })}
    </aside>
  );
}
