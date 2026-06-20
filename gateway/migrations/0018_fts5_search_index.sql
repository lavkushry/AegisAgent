-- #1450: SQLite FTS5 full-text index for `?q=` keyword search on
-- `GET /v1/audit/events` and `GET /v1/decisions`, avoiding `LIKE '%query%'`
-- full-table scans as the event log grows.
--
-- One shared external-content-style FTS5 table backs both source tables
-- (`audit_events`, `decisions`) instead of a separate virtual table + trigger
-- pair per table: each row is tagged with `source_table`/`source_id` so a
-- search can be scoped back to its origin table, and `tenant_id` so search
-- results can be tenant-filtered directly inside the FTS subquery (in
-- addition to the outer query's own `tenant_id` filter on the source table —
-- defense in depth, not a substitute for it). `tenant_id`/`source_table`/
-- `source_id` are UNINDEXED: they are never matched against text, only
-- equality-filtered, so excluding them from the full-text index keeps it
-- smaller and avoids them ever polluting a MATCH result.
CREATE VIRTUAL TABLE IF NOT EXISTS audit_search_index USING fts5(
    tenant_id UNINDEXED,
    source_table UNINDEXED,
    source_id UNINDEXED,
    searchable_text
);

-- Audit events are append-only (no UPDATE/DELETE path in the gateway today),
-- so an AFTER INSERT trigger is sufficient to keep the index synchronized —
-- there is nothing to keep in sync on update.
CREATE TRIGGER IF NOT EXISTS audit_events_fts_insert AFTER INSERT ON audit_events BEGIN
    INSERT INTO audit_search_index (tenant_id, source_table, source_id, searchable_text)
    VALUES (
        NEW.tenant_id,
        'audit_events',
        NEW.id,
        COALESCE(NEW.event_type, '') || ' ' || COALESCE(NEW.skill, '') || ' ' ||
        COALESCE(NEW.action, '') || ' ' || COALESCE(NEW.resource, '') || ' ' ||
        COALESCE(NEW.agent_id, '')
    );
END;

-- Decisions are likewise append-only.
CREATE TRIGGER IF NOT EXISTS decisions_fts_insert AFTER INSERT ON decisions BEGIN
    INSERT INTO audit_search_index (tenant_id, source_table, source_id, searchable_text)
    VALUES (
        NEW.tenant_id,
        'decisions',
        NEW.id,
        COALESCE(NEW.skill, '') || ' ' || COALESCE(NEW.action, '') || ' ' ||
        COALESCE(NEW.resource, '') || ' ' || COALESCE(NEW.reason, '') || ' ' ||
        COALESCE(NEW.decision, '') || ' ' || COALESCE(NEW.agent_id, '')
    );
END;
