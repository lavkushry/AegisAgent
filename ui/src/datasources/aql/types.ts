import type { EntityKind, FieldDescriptor, QueryRequest } from "../types";

/** Maximum raw AQL string length accepted by the client parser. */
export const MAX_AQL_LENGTH = 2048;

/** Maximum parenthesis nesting depth in the AST. */
export const MAX_AQL_DEPTH = 32;

/** Maximum token count per query (complexity bound). */
export const MAX_AQL_TOKENS = 256;

export const ALLOWED_COUNT_OVER_TIME_INTERVALS = ["minute", "hour", "day"] as const;
export type CountOverTimeInterval = (typeof ALLOWED_COUNT_OVER_TIME_INTERVALS)[number];

export const ALLOWED_COUNT_BY_FIELDS = [
  "agent_id",
  "decision",
  "source_trust",
  "tool",
  "action",
  "event_type",
  "severity",
  "source_component",
] as const;
export type CountByField = (typeof ALLOWED_COUNT_BY_FIELDS)[number];

export type AqlNode =
  | { kind: "term"; field: string; op: "eq" | "range"; value: string; to?: string }
  | { kind: "text"; value: string }
  | { kind: "bool"; op: "and" | "or"; children: readonly AqlNode[] };

export interface AqlAggregate {
  readonly func: "count" | "count_over_time";
  readonly interval?: CountOverTimeInterval;
  readonly by?: CountByField;
}

export interface AqlQuery {
  readonly filter: AqlNode;
  readonly aggregate?: AqlAggregate;
}

/** Flat, parameterized gateway filters — never interpolated into SQL. */
export interface GatewayFilters {
  event_type?: string;
  severity?: string;
  source_component?: string;
  agent_id?: string;
  decision?: string;
  source_trust?: string;
  tool?: string;
  action?: string;
  resource?: string;
  run_id?: string;
  trace_id?: string;
  action_hash?: string;
  receipt_hash?: string;
  from?: string;
  to?: string;
  q?: string;
}

export interface ParseAqlOptions {
  readonly entity?: EntityKind;
}

export class AqlParseError extends Error {
  readonly name = "AqlParseError";

  constructor(
    message: string,
    readonly position: number,
    readonly length = 1,
  ) {
    super(message);
  }
}

export class AqlCompileError extends Error {
  readonly name = "AqlCompileError";

  constructor(message: string) {
    super(message);
  }
}

export type AqlSuggestionKind = "field" | "operator" | "value" | "keyword" | "aggregate";

export interface AqlSuggestion {
  readonly kind: AqlSuggestionKind;
  readonly label: string;
  readonly insertText: string;
  readonly detail?: string;
}

export type CompiledAqlRequest = Pick<
  QueryRequest,
  "aggregate" | "interval" | "groupBy"
> & {
  readonly filters: GatewayFilters;
};