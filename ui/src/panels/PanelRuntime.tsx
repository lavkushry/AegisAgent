"use client";

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { useDatasources } from "@/datasources/registry";
import { useDrilldownRouter } from "@/hooks/useDrilldownRouter";
import { errorMessage } from "@/lib/format";
import type { TimeRange, VariableValues, DataFrame } from "@/datasources/types";
import { getPanelEntry } from "./registry";
import PanelContainer from "./PanelContainer";
import type { DrilldownLink, PanelDefinition } from "./types";

const EMPTY_FRAME: DataFrame = { fields: [], length: 0, meta: { total: 0 } };

type Props = {
  definition: PanelDefinition;
  timeRange: TimeRange;
  variables: VariableValues;
  refreshSec?: number;
  onDrilldown?: (link: DrilldownLink, row?: Record<string, unknown>) => void;
};

/**
 * Turns a PanelDefinition into a live panel: resolves the datasource, builds
 * the QueryRequest from the panel plus global time/variables, fetches via
 * TanStack Query, and renders the registered panel component. This is the
 * ONLY place panels fetch — the components themselves are pure.
 */
export default function PanelRuntime({
  definition,
  timeRange,
  variables,
  refreshSec,
  onDrilldown,
}: Props) {
  const datasources = useDatasources();
  const datasource = datasources.get(definition.datasourceId);
  const entry = getPanelEntry(definition.type);
  const router = useDrilldownRouter();

  const { data, isLoading, error } = useQuery({
    queryKey: [
      "panel",
      definition.id,
      definition.datasourceId,
      definition.entity,
      definition.search,
      definition.query,
      timeRange,
      variables,
    ],
    enabled: Boolean(datasource),
    refetchInterval: refreshSec ? refreshSec * 1000 : false,
    queryFn: ({ signal }) => {
      if (!datasource) throw new Error(`Unknown datasource: ${definition.datasourceId}`);
      return datasource.query({
        entity: definition.entity,
        aql: definition.query,
        search: definition.search,
        timeRange,
        variables,
        signal,
      });
    },
  });

  if (!entry) {
    return (
      <PanelContainer title={definition.title} isLoading={false} isEmpty={false} error={`Unknown panel type: ${definition.type}`}>
        {null}
      </PanelContainer>
    );
  }

  const frame = data ?? EMPTY_FRAME;
  const Component = entry.Component;
  const handleDrilldown = onDrilldown ?? router;

  return (
    <PanelContainer
      title={definition.title}
      isLoading={isLoading}
      error={error ? errorMessage(error) : undefined}
      isEmpty={!isLoading && frame.length === 0}
    >
      <Component
        definition={definition}
        data={frame}
        timeRange={timeRange}
        variables={variables}
        onDrilldown={handleDrilldown}
      />
    </PanelContainer>
  );
}
