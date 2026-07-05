-- #1142: explicit monotonic rowid for cursor pagination on detection_rules.
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rowid BIGSERIAL UNIQUE;