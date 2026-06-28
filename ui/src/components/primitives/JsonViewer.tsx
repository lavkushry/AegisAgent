const SECRET_KEYS = /token|secret|password|authorization|api[_-]?key|credential/i;

export function redactJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactJson);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, SECRET_KEYS.test(key) ? "[REDACTED]" : redactJson(child)]));
}

export default function JsonViewer({ value }: { value: unknown }) {
  return <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-3 font-mono text-xs text-[var(--text-secondary)]">{JSON.stringify(redactJson(value), null, 2)}</pre>;
}
