-- See lib/storage/migrations/0043_mcp_server_manifest_signing_key.sql for
-- full rationale. Kept in lockstep across both migration directories per the
-- project's post-#1191 convention: a real migration file, not a SQLite-only
-- ensure_* runtime shim (unlike inspection_enabled/#1333, which took that
-- shortcut and, as a result, never got this column added to Postgres at
-- all -- see lib/storage/src/db/mod.rs's bootstrap_legacy_schema).
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS manifest_signing_public_key TEXT;
