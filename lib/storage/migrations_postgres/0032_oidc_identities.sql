-- OIDC console login. See the SQLite 0047 migration for the design note:
-- UNIQUE(issuer, subject), no auto-provisioning, self-service linking only.
CREATE TABLE IF NOT EXISTS oidc_identities (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_tenant ON oidc_identities(tenant_id);
