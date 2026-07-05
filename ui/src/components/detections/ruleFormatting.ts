/** Format RuleCondition JSON for YAML-like display in the rules editor. */
export function jsonToYaml(obj: unknown): string {
  if (!obj) return "";
  if (typeof obj === "string") return obj;
  if (typeof obj !== "object") return String(obj);

  const formatValue = (val: unknown): string => {
    if (typeof val === "string") {
      if (/[\s:#[\]{}]/.test(val)) {
        return JSON.stringify(val);
      }
      return val;
    }
    return String(val);
  };

  const lines: string[] = [];
  for (const [key, val] of Object.entries(obj)) {
    if (val === undefined || val === null) continue;
    if (Array.isArray(val)) {
      if (val.length === 0) {
        lines.push(`${key}: []`);
      } else {
        lines.push(`${key}:`);
        for (const item of val) {
          lines.push(`  - ${formatValue(item)}`);
        }
      }
    } else if (typeof val === "object") {
      lines.push(`${key}:`);
      const sub = jsonToYaml(val);
      for (const subline of sub.split("\n")) {
        if (subline) lines.push(`  ${subline}`);
      }
    } else {
      lines.push(`${key}: ${formatValue(val)}`);
    }
  }
  return lines.join("\n");
}