import { useMemo } from "react";
import { useAppStore } from "@/app/store";
import {
  DEFAULT_DATASOURCE_ID,
  GatewayEntityDatasource,
} from "./gatewayEntity";
import {
  STREAM_DATASOURCE_ID,
  SocStreamDatasource,
} from "./stream";
import {
  SOC_QUERY_DATASOURCE_ID,
  SocQueryDatasource,
} from "./socQuery";
import type { Datasource } from "./types";

export {
  DEFAULT_DATASOURCE_ID,
  STREAM_DATASOURCE_ID,
  SOC_QUERY_DATASOURCE_ID,
};

/** Datasource map from current gateway connection (stable between renders). */
export function useDatasources(): Map<string, Datasource> {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const tenantId = useAppStore((s) => s.activeTenant);

  return useMemo(() => {
    const opts = { gatewayUrl, bearerToken, tenantId };
    const entity = new GatewayEntityDatasource(opts);
    const stream = new SocStreamDatasource(opts);
    const socQuery = new SocQueryDatasource(opts);
    const map = new Map<string, Datasource>();
    map.set(entity.id, entity);
    map.set(stream.id, stream);
    map.set(socQuery.id, socQuery);
    return map;
  }, [gatewayUrl, bearerToken, tenantId]);
}
