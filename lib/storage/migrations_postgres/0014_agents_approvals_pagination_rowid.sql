-- #1142: explicit monotonic rowid for cursor pagination on agents/approvals
-- (SQLite uses the implicit rowid pseudo-column; Postgres needs a real column).
ALTER TABLE agents ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;