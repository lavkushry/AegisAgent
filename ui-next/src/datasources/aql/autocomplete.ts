import { canonicalAqlField } from "./fields";
import type { AqlSuggestion } from "./types";
import type { FieldDescriptor } from "../types";

const OPERATORS = ["AND", "OR"];
const AGGREGATES = ["| stats count()", "| stats count_over_time(hour)", "| stats count() by agent_id"];

function suffixAfterLastDelimiter(input: string, cursor: number): string {
  const prefix = input.slice(0, cursor);
  const match = /(?:^|[\s(])([^\s:(|]*)$/.exec(prefix);
  return match?.[1] ?? "";
}

function contextBeforeCursor(input: string, cursor: number): "field" | "value" | "operator" | "aggregate" | "keyword" {
  const prefix = input.slice(0, cursor).trimEnd();
  if (prefix.endsWith("|") || /\|\s*stats\s*$/.test(prefix)) return "aggregate";
  if (prefix.endsWith(":") || /:\[[^\]]*$/.test(prefix)) return "value";
  if (/\b(?:AND|OR)\s*$/i.test(prefix)) return "field";
  if (prefix.length === 0 || /[\s(]$/.test(prefix)) return "field";
  if (/(?:^|[\s(])[A-Za-z_@][\w.-]*$/.test(prefix)) return "field";
  if (/\S+:\S*$/.test(prefix) && !prefix.endsWith(":")) return "operator";
  return "keyword";
}

export function aqlAutocomplete(
  input: string,
  cursor: number,
  fields: ReadonlyArray<FieldDescriptor>,
): ReadonlyArray<AqlSuggestion> {
  const safeCursor = Math.max(0, Math.min(cursor, input.length));
  const fragment = suffixAfterLastDelimiter(input, safeCursor).toLowerCase();
  const context = contextBeforeCursor(input, safeCursor);
  const suggestions: AqlSuggestion[] = [];

  if (context === "aggregate") {
    for (const aggregate of AGGREGATES) {
      if (!fragment || aggregate.toLowerCase().includes(fragment)) {
        suggestions.push({
          kind: "aggregate",
          label: aggregate,
          insertText: aggregate,
        });
      }
    }
    return suggestions;
  }

  if (context === "operator") {
    for (const operator of OPERATORS) {
      if (!fragment || operator.toLowerCase().startsWith(fragment)) {
        suggestions.push({ kind: "operator", label: operator, insertText: ` ${operator} ` });
      }
    }
    return suggestions;
  }

  if (context === "field") {
    const catalog = [{ name: "@time", type: "time" as const, facetable: false }, ...fields];
    for (const field of catalog) {
      const names = field.name === "tool" ? ["tool", "skill"] : field.name === "source_trust" ? ["source_trust", "root_trust_level"] : [field.name];
      for (const name of names) {
        if (!fragment || name.toLowerCase().startsWith(fragment)) {
          suggestions.push({
            kind: "field",
            label: name,
            insertText: `${name}:`,
            detail: field.type,
          });
        }
      }
    }
    return suggestions.slice(0, 12);
  }

  if (context === "value") {
    const fieldMatch = /([A-Za-z_@][\w.-]*)\s*:\s*"?([^"]*)"?$/.exec(input.slice(0, safeCursor));
    const fieldName = fieldMatch?.[1];
    if (fieldName) {
      const canonical = canonicalAqlField(fieldName);
      const descriptor = fields.find((field) => field.name === canonical || field.name === fieldName);
      for (const example of descriptor?.examples ?? []) {
        if (!fragment || example.toLowerCase().startsWith(fragment)) {
          suggestions.push({
            kind: "value",
            label: example,
            insertText: example.includes(" ") ? `"${example}"` : example,
          });
        }
      }
      if (canonical === "@time") {
        for (const token of ["now", "now-24h", "now-1h", "now-7d"]) {
          if (!fragment || token.startsWith(fragment)) {
            suggestions.push({ kind: "value", label: token, insertText: `[${token} TO now]` });
          }
        }
      }
    }
    return suggestions;
  }

  for (const operator of OPERATORS) {
    if (!fragment || operator.toLowerCase().startsWith(fragment)) {
      suggestions.push({ kind: "keyword", label: operator, insertText: ` ${operator} ` });
    }
  }
  return suggestions;
}