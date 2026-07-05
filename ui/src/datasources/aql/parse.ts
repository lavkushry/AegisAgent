import { isAllowedAqlField } from "./fields";
import {
  AqlParseError,
  MAX_AQL_DEPTH,
  MAX_AQL_LENGTH,
  MAX_AQL_TOKENS,
  type AqlAggregate,
  type AqlNode,
  type AqlQuery,
  type ParseAqlOptions,
} from "./types";

type TokenKind =
  | "ident"
  | "quoted"
  | "colon"
  | "lparen"
  | "rparen"
  | "lbracket"
  | "rbracket"
  | "pipe"
  | "eof";

interface Token {
  kind: TokenKind;
  value: string;
  start: number;
  end: number;
}

const KEYWORDS = new Set(["and", "or", "to", "stats", "count", "count_over_time", "by"]);

function isIdentChar(ch: string, first: boolean): boolean {
  if (first) return /[A-Za-z_#@-]/.test(ch);
  return /[A-Za-z0-9_@.;'#\\/-]/.test(ch);
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;

  while (index < input.length) {
    const ch = input[index];
    if (/\s/.test(ch)) {
      index += 1;
      continue;
    }

    const start = index;
    if (ch === ":") {
      tokens.push({ kind: "colon", value: ":", start, end: index + 1 });
      index += 1;
      continue;
    }
    if (ch === "(") {
      tokens.push({ kind: "lparen", value: "(", start, end: index + 1 });
      index += 1;
      continue;
    }
    if (ch === ")") {
      tokens.push({ kind: "rparen", value: ")", start, end: index + 1 });
      index += 1;
      continue;
    }
    if (ch === "[") {
      tokens.push({ kind: "lbracket", value: "[", start, end: index + 1 });
      index += 1;
      continue;
    }
    if (ch === "]") {
      tokens.push({ kind: "rbracket", value: "]", start, end: index + 1 });
      index += 1;
      continue;
    }
    if (ch === "|") {
      tokens.push({ kind: "pipe", value: "|", start, end: index + 1 });
      index += 1;
      continue;
    }
    if (ch === '"') {
      index += 1;
      let value = "";
      while (index < input.length) {
        const current = input[index];
        if (current === "\\") {
          const next = input[index + 1];
          if (next === undefined) {
            throw new AqlParseError("Unterminated quoted string", start, index - start + 1);
          }
          value += next;
          index += 2;
          continue;
        }
        if (current === '"') {
          index += 1;
          tokens.push({ kind: "quoted", value, start, end: index });
          break;
        }
        value += current;
        index += 1;
      }
      if (input[index - 1] !== '"') {
        throw new AqlParseError("Unterminated quoted string", start, index - start);
      }
      continue;
    }

    if (!isIdentChar(ch, true)) {
      throw new AqlParseError(`Unexpected character '${ch}'`, index, 1);
    }

    index += 1;
    while (index < input.length && isIdentChar(input[index], false)) {
      index += 1;
    }
    tokens.push({ kind: "ident", value: input.slice(start, index), start, end: index });
  }

  tokens.push({ kind: "eof", value: "", start: input.length, end: input.length });
  if (tokens.length - 1 > MAX_AQL_TOKENS) {
    throw new AqlParseError(`Query exceeds ${MAX_AQL_TOKENS} tokens`, 0, input.length);
  }
  return tokens;
}

class Parser {
  private index = 0;
  private depth = 0;

  constructor(
    private readonly tokens: Token[],
    private readonly options: ParseAqlOptions,
  ) {}

  parse(): AqlQuery {
    const filter = this.parseOrExpr();
    let aggregate: AqlAggregate | undefined;
    if (this.peek().kind === "pipe") {
      this.advance();
      aggregate = this.parseAggregateStage();
    }
    const eof = this.peek();
    if (eof.kind !== "eof") {
      throw new AqlParseError("Unexpected tokens after query", eof.start, eof.end - eof.start);
    }
    return { filter, aggregate };
  }

  private parseAggregateStage(): AqlAggregate {
    const stats = this.expectIdent("stats");
    if (stats.value.toLowerCase() !== "stats") {
      throw new AqlParseError('Expected "stats" after "|"', stats.start, stats.end - stats.start);
    }

    const func = this.expectIdent("aggregate");
    if (func.value.toLowerCase() === "count_over_time") {
      this.expect("lparen");
      const interval = this.expectIdent("interval");
      this.expect("rparen");
      const normalized = interval.value.toLowerCase();
      if (!["minute", "hour", "day"].includes(normalized)) {
        throw new AqlParseError(
          `Unsupported interval '${interval.value}' (allowed: minute, hour, day)`,
          interval.start,
          interval.end - interval.start,
        );
      }
      return { func: "count_over_time", interval: normalized as AqlAggregate["interval"] };
    }

    if (func.value.toLowerCase() !== "count") {
      throw new AqlParseError(
        `Unsupported aggregate '${func.value}'`,
        func.start,
        func.end - func.start,
      );
    }

    this.expect("lparen");
    this.expect("rparen");

    const next = this.peek();
    if (next.kind === "ident" && next.value.toLowerCase() === "by") {
      this.advance();
      const field = this.expectIdent("group_by");
      const normalized = field.value.toLowerCase();
      if (
        ![
          "agent_id",
          "decision",
          "source_trust",
          "tool",
          "action",
          "event_type",
          "severity",
          "source_component",
        ].includes(normalized)
      ) {
        throw new AqlParseError(
          `Unsupported group_by field '${field.value}'`,
          field.start,
          field.end - field.start,
        );
      }
      return { func: "count", by: normalized as AqlAggregate["by"] };
    }
    return { func: "count" };
  }

  private parseOrExpr(): AqlNode {
    const nodes = [this.parseAndExpr()];
    while (this.matchIdent("or")) {
      nodes.push(this.parseAndExpr());
    }
    return this.flattenBool("or", nodes);
  }

  private parseAndExpr(): AqlNode {
    const nodes: AqlNode[] = [this.parseUnary()];
    while (true) {
      if (this.matchIdent("and")) {
        nodes.push(this.parseUnary());
        continue;
      }
      if (!this.shouldImplicitAnd()) break;
      nodes.push(this.parseUnary());
    }
    return this.flattenBool("and", nodes);
  }

  private shouldImplicitAnd(): boolean {
    const token = this.peek();
    if (token.kind === "eof" || token.kind === "pipe" || token.kind === "rparen") return false;
    if (token.kind === "ident") {
      const lower = token.value.toLowerCase();
      if (["or", "and", "to", "stats", "by"].includes(lower)) return false;
    }
    return token.kind === "ident" || token.kind === "quoted" || token.kind === "lparen";
  }

  private parseUnary(): AqlNode {
    if (this.peek().kind === "lparen") {
      this.depth += 1;
      if (this.depth > MAX_AQL_DEPTH) {
        const token = this.peek();
        throw new AqlParseError(`Query nesting exceeds ${MAX_AQL_DEPTH}`, token.start, 1);
      }
      this.advance();
      const inner = this.parseOrExpr();
      this.expect("rparen");
      this.depth -= 1;
      return inner;
    }
    return this.parsePrimary();
  }

  private parsePrimary(): AqlNode {
    const token = this.peek();
    if (token.kind === "quoted") {
      this.advance();
      return { kind: "text", value: token.value };
    }
    if (token.kind !== "ident") {
      throw new AqlParseError("Expected filter term", token.start, 1);
    }

    const fieldToken = this.advance();
    if (this.peek().kind === "colon") {
      this.advance();
      return this.parseFieldTerm(fieldToken);
    }

    if (KEYWORDS.has(fieldToken.value.toLowerCase())) {
      throw new AqlParseError(`Unexpected keyword '${fieldToken.value}'`, fieldToken.start, fieldToken.end - fieldToken.start);
    }
    return { kind: "text", value: fieldToken.value };
  }

  private parseFieldTerm(fieldToken: Token): AqlNode {
    const field = fieldToken.value;
    if (!isAllowedAqlField(field, this.options.entity)) {
      throw new AqlParseError(
        `Unknown field '${field}'`,
        fieldToken.start,
        fieldToken.end - fieldToken.start,
      );
    }

    if (this.peek().kind === "lbracket") {
      this.advance();
      const from = this.readValue();
      const toKeyword = this.expectIdent("TO");
      if (toKeyword.value.toUpperCase() !== "TO") {
        throw new AqlParseError('Expected "TO" in range', toKeyword.start, toKeyword.end - toKeyword.start);
      }
      const to = this.readValue();
      this.expect("rbracket");
      return { kind: "term", field, op: "range", value: from, to };
    }

    const value = this.readValue();
    return { kind: "term", field, op: "eq", value };
  }

  private readValue(): string {
    const token = this.peek();
    if (token.kind === "quoted") {
      this.advance();
      return token.value;
    }
    if (token.kind === "ident") {
      let value = this.advance().value;
      while (this.peek().kind === "colon" && this.tokens[this.index + 1]?.kind === "ident") {
        this.advance();
        value += `:${this.advance().value}`;
      }
      return value;
    }
    throw new AqlParseError("Expected value", token.start, 1);
  }

  private flattenBool(op: "and" | "or", nodes: AqlNode[]): AqlNode {
    const merged: AqlNode[] = [];
    for (const node of nodes) {
      if (node.kind === "bool" && node.op === op) {
        merged.push(...node.children);
      } else {
        merged.push(node);
      }
    }
    if (merged.length === 1) return merged[0];
    return { kind: "bool", op, children: merged };
  }

  private peek(): Token {
    return this.tokens[this.index];
  }

  private previous(): Token {
    return this.tokens[this.index - 1];
  }

  private advance(): Token {
    const token = this.tokens[this.index];
    this.index += 1;
    return token;
  }

  private expect(kind: TokenKind): Token {
    const token = this.peek();
    if (token.kind !== kind) {
      throw new AqlParseError(`Expected ${kind}`, token.start, Math.max(1, token.end - token.start));
    }
    return this.advance();
  }

  private expectIdent(label: string): Token {
    const token = this.peek();
    if (token.kind !== "ident") {
      throw new AqlParseError(`Expected ${label}`, token.start, 1);
    }
    return this.advance();
  }

  private matchIdent(word: string): boolean {
    const token = this.peek();
    if (token.kind === "ident" && token.value.toLowerCase() === word) {
      this.advance();
      return true;
    }
    return false;
  }
}

export function parseAql(input: string, options: ParseAqlOptions = {}): AqlQuery {
  const raw = (input ?? "").trim();
  if (!raw) {
    return { filter: { kind: "bool", op: "and", children: [] } };
  }
  if (raw.length > MAX_AQL_LENGTH) {
    throw new AqlParseError(`Query exceeds ${MAX_AQL_LENGTH} characters`, 0, raw.length);
  }
  const tokens = tokenize(raw);
  return new Parser(tokens, options).parse();
}

function quoteValue(value: string): string {
  if (/[\s()"[\]|]/.test(value)) return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  return value;
}

function serializeNode(node: AqlNode): string {
  switch (node.kind) {
    case "text":
      return quoteValue(node.value);
    case "term":
      if (node.op === "range") {
        return `${node.field}:[${quoteValue(node.value)} TO ${quoteValue(node.to ?? "")}]`;
      }
      return `${node.field}:${quoteValue(node.value)}`;
    case "bool": {
      const joiner = node.op === "and" ? " AND " : " OR ";
      return node.children.map((child) => {
        const serialized = serializeNode(child);
        return child.kind === "bool" && child.op !== node.op ? `(${serialized})` : serialized;
      }).join(joiner);
    }
    default:
      return "";
  }
}

export function serializeAql(query: AqlQuery): string {
  const filter = query.filter;
  const hasFilter = !(filter.kind === "bool" && filter.op === "and" && filter.children.length === 0);
  const parts: string[] = [];
  if (hasFilter) parts.push(serializeNode(filter));
  if (query.aggregate) {
    if (query.aggregate.func === "count_over_time") {
      parts.push(`| stats count_over_time(${query.aggregate.interval ?? "hour"})`);
    } else if (query.aggregate.by) {
      parts.push(`| stats count() by ${query.aggregate.by}`);
    } else {
      parts.push("| stats count()");
    }
  }
  return parts.join(" ").trim();
}

/** Encode AQL for URL query parameters (treat decoded values as untrusted). */
export function encodeAqlParam(aql: string): string {
  return encodeURIComponent(aql);
}

export function decodeAqlParam(param: string): string {
  return decodeURIComponent(param);
}