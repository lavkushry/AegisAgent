import { useQuery } from "@tanstack/react-query";
import { useDatasources } from "@/datasources/registry";
import { useDrilldownRouter } from "@/hooks/useDrilldownRouter";
import { useAppStore } from "@/app/store";
import { errorMessage } from "@/lib/format";
import type { DataFrame, TimeRange, VariableValues } from "@/datasources/types";
import { getPanelEntry } from "./registry";
import { PanelContainer } from "./PanelContainer";
import type { DrilldownLink, PanelDefinition } from "./types";

const EMPTY_FRAME: DataFrame = { fields: [], length: 0, meta: { total: 0 } };

type Props = {
  definition: PanelDefinition;
  timeRange: TimeRange;
  variables: VariableValues;
  refreshSec?: number;
  onDrilldown?: (
    link: DrilldownLink,
    row?: Record<string, unknown>,
  ) => void;
};

/**
 * Resolves datasource + QueryRequest, fetches via TanStack Query, renders
 * registered panel. ONLY place panels fetch.
 */
export function PanelRuntime({
  definition,
  timeRange,
  variables,
  refreshSec,
  onDrilldown,
}: Props) {
  const datasources = useDatasources();
  const activeTenant = useAppStore((s) => s.activeTenant);
  const datasource = datasources.get(definition.datasourceId);
  const entry = getPanelEntry(definition.type);
  const router = useDrilldownRouter();

  const { data, isLoading, isFetching, isStale, error } = useQuery({
    queryKey: [
      "panel",
      definition.id,
      definition.datasourceId,
      definition.entity,
      definition.snapshot,
      definition.limit,
      definition.search,
      definition.query,
      definition.aggregate,
      definition.groupBy,
      definition.interval,
      activeTenant,
      timeRange,
      variables,
    ],
    enabled:
      Boolean(datasource) &&
      definition.type !== "note" &&
      Boolean(activeTenant.trim()),
    staleTime: (refreshSec ?? 30) * 2_000,
    refetchInterval: refreshSec ? refreshSec * 1000 : false,
    queryFn: ({ signal }) => {
      if (!datasource) {
        throw new Error(`Unknown datasource: ${definition.datasourceId}`);
      }
      return datasource.query({
        entity: definition.entity,
        snapshot: definition.snapshot,
        limit: definition.limit,
        aql: definition.query,
        search: definition.search,
        aggregate: definition.aggregate,
        groupBy: definition.groupBy,
        interval: definition.interval,
        rulesCatalog: definition.rulesCatalog,
        timeRange,
        variables,
        signal,
      });
    },
    retry: false,
  });

  if (!entry) {
    return (
      <PanelContainer
        title={definition.title}
        isLoading={false}
        isEmpty={false}
        error={`Unknown panel type: ${definition.type}`}
      >
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
      isRefreshing={isFetching && !isLoading}
      isStale={isStale && !isFetching}
      error={error ? errorMessage(error) : undefined}
      isEmpty={
        !isLoading && definition.type !== "note" && frame.length === 0
      }
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

export default PanelRuntime;
