import type { ExploreEntity } from "@/components/exploreData";

export interface SavedSearch {
  id: string;
  name: string;
  aql: string;
  entity: ExploreEntity;
  timeRange: string;
  createdAt: string;
}

const STORAGE_PREFIX = "aegis_saved_searches_";
const FORBIDDEN_PATTERN = /(bearer|authorization|api[_-]?key|secret|password|token\s*:)/i;

export function savedSearchStorageKey(tenantId: string): string {
  return `${STORAGE_PREFIX}${tenantId}`;
}

function storage(): Storage | null {
  if (typeof window !== "undefined" && window.localStorage) return window.localStorage;
  if (typeof globalThis !== "undefined" && "localStorage" in globalThis) {
    return globalThis.localStorage as Storage;
  }
  return null;
}

function readRaw(tenantId: string): SavedSearch[] {
  const ls = storage();
  if (!ls) return [];
  try {
    const raw = ls.getItem(savedSearchStorageKey(tenantId));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SavedSearch[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeRaw(tenantId: string, searches: SavedSearch[]): void {
  const ls = storage();
  if (!ls) return;
  ls.setItem(savedSearchStorageKey(tenantId), JSON.stringify(searches));
}

export function validateSavedSearchInput(
  name: string,
  aql: string,
): string | null {
  const trimmedName = name.trim();
  if (!trimmedName) return "Name is required.";
  if (trimmedName.length > 80) return "Name must be 80 characters or fewer.";
  if (FORBIDDEN_PATTERN.test(aql)) return "Saved searches cannot contain credential-shaped fields.";
  return null;
}

export function listSavedSearches(tenantId: string): SavedSearch[] {
  return readRaw(tenantId).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function saveSearch(
  tenantId: string,
  input: Pick<SavedSearch, "name" | "aql" | "entity" | "timeRange">,
): SavedSearch {
  const error = validateSavedSearchInput(input.name, input.aql);
  if (error) throw new Error(error);
  const entry: SavedSearch = {
    id: `ss_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    name: input.name.trim(),
    aql: input.aql.trim(),
    entity: input.entity,
    timeRange: input.timeRange,
    createdAt: new Date().toISOString(),
  };
  const next = [entry, ...readRaw(tenantId)].slice(0, 50);
  writeRaw(tenantId, next);
  return entry;
}

export function deleteSavedSearch(tenantId: string, id: string): void {
  writeRaw(
    tenantId,
    readRaw(tenantId).filter((item) => item.id !== id),
  );
}