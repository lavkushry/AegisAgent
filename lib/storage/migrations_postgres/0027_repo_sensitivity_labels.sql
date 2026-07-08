-- Per-repo sensitivity labels for the GitHub App protection layer (#1380).
-- See migrations/0042_repo_sensitivity_labels.sql for the full rationale.
CREATE TABLE IF NOT EXISTS repo_sensitivity_labels (
    id                 TEXT NOT NULL PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    repo_full_name     TEXT NOT NULL,
    sensitivity_label  TEXT NOT NULL CHECK (sensitivity_label IN ('low', 'medium', 'high', 'critical')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, repo_full_name)
);

CREATE INDEX IF NOT EXISTS idx_repo_sensitivity_labels_tenant ON repo_sensitivity_labels(tenant_id);
