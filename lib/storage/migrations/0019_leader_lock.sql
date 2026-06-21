-- REL-003 (#1149): SQLite advisory-lock-based leader election for
-- multi-instance safety. A single global row (id = 'singleton') tracks
-- which instance currently holds the lease — deliberately not tenant-scoped,
-- same precedent as `schema_meta` (cross-tenant infrastructure state, not
-- tenant-owned data).
CREATE TABLE IF NOT EXISTS leader_lock (
    id TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    lease_expires_at TIMESTAMP NOT NULL,
    acquired_at TIMESTAMP NOT NULL
);
