-- Per-repo sensitivity labels for the GitHub App protection layer (#1380).
-- Configurable per (tenant, repo) so the merge-protection gate can weigh a
-- denied/pending decision on a "critical" repo more heavily than the same
-- decision on a "low" one. No row for a repo means "low" (backwards-compatible
-- default, matching the unrestricted-unless-configured precedent used by
-- agent_tool_permissions/agent_mcp_server_permissions).
CREATE TABLE repo_sensitivity_labels (
    id                 TEXT NOT NULL PRIMARY KEY,
    tenant_id          TEXT NOT NULL REFERENCES tenants(id),
    repo_full_name     TEXT NOT NULL,
    sensitivity_label  TEXT NOT NULL CHECK (sensitivity_label IN ('low', 'medium', 'high', 'critical')),
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE (tenant_id, repo_full_name)
);

CREATE INDEX idx_repo_sensitivity_labels_tenant ON repo_sensitivity_labels(tenant_id);
