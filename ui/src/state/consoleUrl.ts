export const CONSOLE_VIEWS = [
  "overview",
  "dashboards",
  "integrity",
  "explore",
  "incidents",
  "detections",
  "approvals",
  "agents",
  "mcp",
  "receipts",
  "settings",
] as const;

export type ConsoleView = (typeof CONSOLE_VIEWS)[number];

export interface ConsoleUrlState {
  view: ConsoleView;
  timeRange: string;
  liveMode: boolean;
  exploreQuery?: string;
  incidentId?: string;
  receiptId?: string;
  variables: Record<string, string>;
}

export function parseConsoleUrl(search: string): Partial<ConsoleUrlState> {
  const params = new URLSearchParams(search);
  const view = params.get("view");
  const variables: Record<string, string> = {};
  params.forEach((value, key) => {
    if (key.startsWith("var-") && key.length > 4) variables[key.slice(4)] = value;
  });
  return {
    ...(view && CONSOLE_VIEWS.includes(view as ConsoleView) ? { view: view as ConsoleView } : {}),
    ...(params.get("range") ? { timeRange: params.get("range")! } : {}),
    ...(params.has("live") ? { liveMode: params.get("live") === "1" } : {}),
    ...(params.get("q") ? { exploreQuery: params.get("q")! } : {}),
    ...(params.get("incident") ? { incidentId: params.get("incident")! } : {}),
    ...(params.get("receipt") ? { receiptId: params.get("receipt")! } : {}),
    ...(Object.keys(variables).length ? { variables } : {}),
  };
}

export function serializeConsoleUrl(state: ConsoleUrlState): string {
  const params = new URLSearchParams();
  params.set("view", state.view);
  params.set("range", state.timeRange);
  if (state.liveMode) params.set("live", "1");
  if (state.exploreQuery) params.set("q", state.exploreQuery);
  if (state.incidentId) params.set("incident", state.incidentId);
  if (state.receiptId) params.set("receipt", state.receiptId);
  Object.entries(state.variables).forEach(([key, value]) => value && params.set(`var-${key}`, value));
  return `?${params.toString()}`;
}
