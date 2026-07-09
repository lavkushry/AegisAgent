import { useMemo } from "react";
import { useAppStore } from "@/app/store";
import {
  DEFAULT_DATASOURCE_ID,
  GatewayEntityDatasource,
} from "./gatewayEntity";
import type { Datasource } from "./types";

export { DEFAULT_DATASOURCE_ID };

/** Datasource map from current gateway connection (stable between renders). */
export function useDatasources(): Map<string, Datasource> {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const tenantId = useAppStore((s) => s.activeTenant);

  return useMemo(() => {
    const opts = { gatewayUrl, bearerToken, tenantId };
    const entity = new GatewayEntityDatasource(opts);
    const map = new Map<string, Datasource>();
    map.set(entity.id, entity);
    return map;
  }, [gatewayUrl, bearerToken, tenantId]);
}
