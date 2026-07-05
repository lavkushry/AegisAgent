import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  deleteSavedSearch,
  listSavedSearches,
  saveSearch,
  savedSearchStorageKey,
  validateSavedSearchInput,
} from "./savedSearches";

const TENANT = "tenant-a";

function installLocalStorageMock(): void {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
    clear: () => {
      store.clear();
    },
  });
}

describe("saved searches (local-only)", () => {
  beforeEach(() => {
    installLocalStorageMock();
  });

  it("persists tenant-scoped searches without credentials", () => {
    const saved = saveSearch(TENANT, {
      name: "Denied merges",
      aql: "decision:deny AND tool:github",
      entity: "decision",
      timeRange: "7d",
    });
    expect(listSavedSearches(TENANT)).toEqual([saved]);
    expect(listSavedSearches("tenant-b")).toEqual([]);
    expect(localStorage.getItem(savedSearchStorageKey(TENANT))).not.toMatch(/bearer/i);
  });

  it("rejects credential-shaped AQL", () => {
    expect(validateSavedSearchInput("Bad", "bearer:secret")).toMatch(/credential/i);
  });

  it("deletes saved searches by id", () => {
    const one = saveSearch(TENANT, { name: "One", aql: "decision:allow", entity: "decision", timeRange: "24h" });
    const two = saveSearch(TENANT, { name: "Two", aql: "decision:deny", entity: "decision", timeRange: "24h" });
    deleteSavedSearch(TENANT, one.id);
    expect(listSavedSearches(TENANT).map((s) => s.id)).toEqual([two.id]);
  });
});