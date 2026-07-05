-- #1142: explicit monotonic rowid for cursor pagination on policies.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;