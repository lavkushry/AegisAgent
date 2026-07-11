-- OIDC console login (roadmap: "OIDC/SAML for console/admin"). Self-service
-- identity linking: an already-authenticated tenant links their own IdP
-- identity (issuer + subject) to their tenant via POST /v1/oidc/link/start,
-- then can log in directly afterward via GET /v1/auth/oidc/login without a
-- prior bearer token. UNIQUE(issuer, subject) means one external identity
-- maps to exactly one tenant -- there is no auto-provisioning: an
-- unrecognized (issuer, subject) pair at login fails closed (403), it never
-- creates a tenant or guesses a mapping.
CREATE TABLE IF NOT EXISTS oidc_identities (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_oidc_identities_tenant ON oidc_identities(tenant_id);
