import type { AqlNode } from "./types";

export interface AqlChip {
  field: string;
  value: string;
}

export function aqlChipsFromNode(node: AqlNode, chips: AqlChip[] = []): AqlChip[] {
  switch (node.kind) {
    case "term":
      if (node.op === "range") {
        chips.push({ field: node.field, value: `[${node.value} TO ${node.to ?? ""}]` });
      } else {
        chips.push({ field: node.field, value: node.value });
      }
      return chips;
    case "text":
      chips.push({ field: "q", value: node.value });
      return chips;
    case "bool":
      for (const child of node.children) aqlChipsFromNode(child, chips);
      return chips;
    default:
      return chips;
  }
}