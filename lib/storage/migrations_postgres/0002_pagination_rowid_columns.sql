-- #1142: SQLite tables get a stable monotonic ordering key for free via the
-- implicit `rowid` pseudo-column; Postgres has no equivalent, so the cursor
-- queries that order by it need an explicit column on every table they
-- paginate. `action_receipts`/`decisions`/`soc_alerts`/`soc_incidents`
-- already have this (added directly in the baseline) — this migration adds
-- it to the three tables newly converted to cursor pagination.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;
ALTER TABLE webhook_subscriptions ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;
ALTER TABLE response_playbooks ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;
