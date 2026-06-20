# Database schema (ERD)

The gateway uses a single SQLite database (`gateway/src/db.rs`, `run_migrations`).
Every tenant-owned table carries a `tenant_id` column, and every tenant-scoped
query filters/binds on it (multi-tenant isolation — see `CLAUDE.md`). New
columns are added via additive `ensure_*_column` migrations (checked with
`PRAGMA table_info` before `ALTER TABLE ... ADD COLUMN`), never by altering or
dropping existing columns.

```mermaid
erDiagram
    TENANTS ||--o{ AGENTS : owns
    TENANTS ||--o{ SKILLS : owns
    TENANTS ||--o{ MCP_SERVERS : owns
    TENANTS ||--o{ POLICIES : owns
    TENANTS ||--o{ DECISIONS : owns
    TENANTS ||--o{ APPROVALS : owns
    TENANTS ||--o{ AUDIT_EVENTS : owns
    TENANTS ||--o{ ACTION_RECEIPTS : owns
    TENANTS ||--o{ SOC_ALERTS : owns
    TENANTS ||--o{ SOC_INCIDENTS : owns

    SKILLS ||--o{ SKILL_ACTIONS : defines
    MCP_SERVERS ||--o{ MCP_TOOLS : exposes

    AGENTS ||--o{ DECISIONS : triggers
    DECISIONS ||--o| APPROVALS : "may require"
    DECISIONS ||--o| ACTION_RECEIPTS : "emits"

    AUDIT_EVENTS ||--o{ AUDIT_EVENTS_ARCHIVE : "archived to (by id)"

    TENANTS {
        text id PK
        text name
        text plan
        datetime created_at
    }

    AGENTS {
        text id PK
        text tenant_id FK
        text agent_key UK
        text agent_token UK
        text name
        text owner_team
        text owner_email
        text environment
        text framework
        text model_provider
        text model_name
        text purpose
        text risk_tier
        text status
        datetime quarantined_at "additive #0078"
        text frozen_reason "additive #0079"
        datetime last_seen_at "additive #0080"
        datetime created_at
        datetime updated_at
    }

    SKILLS {
        text id PK
        text tenant_id FK
        text skill_key UK
        text name
        text type
        text auth_type
        text owner_team
        text default_risk
        datetime created_at
    }

    SKILL_ACTIONS {
        text id PK
        text skill_id FK
        text action_key UK
        text description
        text risk
        bool mutates_state
        text data_access
        bool approval_required
        text default_decision
        datetime created_at
    }

    MCP_SERVERS {
        text id PK
        text tenant_id FK
        text server_key UK
        text name
        text owner_team
        text transport
        text source
        text trust_level
        text endpoint "additive"
        text manifest_hash "additive #0095"
        text version
        text status
        datetime created_at
    }

    MCP_TOOLS {
        text id PK
        text tenant_id FK
        text server_id FK
        text tool_key UK
        text name
        text description
        text input_schema
        text risk
        bool mutates_state
        bool approval_required
        text status
        datetime created_at
        datetime updated_at
    }

    POLICIES {
        text id PK
        text tenant_id FK
        text policy_key UK
        text name
        text language
        text body
        int version
        text status
        text created_by
        datetime created_at
    }

    DECISIONS {
        text id PK
        text tenant_id FK
        text agent_id FK
        text user_id
        text run_id
        text trace_id
        text skill
        text action
        text resource
        text input_json
        text decision
        int risk_score
        text reason
        text matched_policy_ids
        text request_id "additive #0072, idempotency"
        int latency_ms "additive #0081"
        datetime created_at
    }

    APPROVALS {
        text id PK
        text tenant_id FK
        text decision_id FK
        text status
        text approver_group
        text approver_user_id
        text reason
        text original_skill_call
        text original_call_hash "additive"
        text edited_skill_call
        datetime expires_at
        datetime decided_at
        datetime consumed_at "additive, single-use replay defense"
        datetime created_at
    }

    AUDIT_EVENTS {
        text id PK
        text tenant_id FK
        text event_type
        text agent_id
        text user_id
        text run_id
        text trace_id
        text span_id
        text skill
        text action
        text resource
        text event_json
        text input_hash
        text output_hash
        datetime created_at
    }

    AUDIT_EVENTS_ARCHIVE {
        text id PK
        text tenant_id
        text event_type
        text agent_id
        text user_id
        text run_id
        text trace_id
        text span_id
        text skill
        text action
        text resource
        text event_json
        text input_hash
        text output_hash
        datetime created_at
        datetime archived_at "#0106"
    }

    ACTION_RECEIPTS {
        text id PK
        text tenant_id FK
        text decision_id
        text ts
        text agent_id
        text user_id
        text run_id
        text trace_id
        text tool
        text action
        text resource
        text source_trust
        text decision
        text approver
        text action_hash
        text prev_receipt_hash
        text receipt_hash
        text canon_version "additive"
        text signature "additive, optional Ed25519"
        text signer_public_key "additive"
        datetime created_at
    }

    SOC_ALERTS {
        text id PK
        text tenant_id
        text rule
        text severity
        text agent_id
        text source_event_id
        text summary
        text created_at
    }

    SOC_INCIDENTS {
        text id PK
        text tenant_id
        text kind
        text severity
        text agent_id
        text summary
        text source_event_ids
        text opened_at
        text status "additive lifecycle"
        text closed_at "additive lifecycle"
    }
```

## Notes

- **`action_receipts`** forms a per-tenant hash chain: each row's
  `prev_receipt_hash` must equal the previous row's `receipt_hash` (oldest
  `created_at` first), and `receipt_hash` is `SHA-256(canonical(body))` under
  scheme `aegis-jcs-1`. Verified by `gateway/src/jobs.rs::verify_tenant_receipt_chain`
  (periodic background job, #0107) and `POST /v1/receipts/verify-chain`.
- **`audit_events_archive`** has no foreign key to `tenants`, since archived
  rows must outlive any later tenant deletion. Populated by
  `db::archive_audit_events_older_than` (#0106), run periodically by
  `jobs::run_audit_event_archival_job`.
- **Composite indexes** (`idx_decisions_tenant_agent_created`,
  `idx_approvals_tenant_status_created`, `idx_audit_events_tenant_type_created`,
  `idx_action_receipts_tenant_created`, #940-#943) match the hot tenant-scoped
  list/query paths: `WHERE tenant_id [AND <filter>] ORDER BY created_at DESC`.
- **Migrations are additive and idempotent**: every `ensure_*_column` function
  checks `PRAGMA table_info(<table>)` before `ALTER TABLE ... ADD COLUMN`, so
  re-running `run_migrations` against an already-migrated database is a no-op
  (locked in by `db::tests::migrations_are_idempotent_on_existing_database`, #0108).
- **Qdrant Vector Database:** When enabled, Agent Security Events (`AseEvent`) are asynchronously vectorized and indexed in Qdrant. See the [Qdrant guide](qdrant-integration.md) for details on semantic indexing and configurations.

