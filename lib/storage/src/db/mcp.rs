use crate::db::DbPool;
use aegis_api::models::*;

/// Read the pinned MCP tool-manifest hash for a server (`""` if never pinned).
/// Tenant-scoped, parameterized.
pub async fn get_mcp_server_manifest_hash(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
) -> Result<String, sqlx::Error> {
    let res: Option<String> = crate::fetch_optional_scalar!(
        String,
        pool,
        "SELECT manifest_hash FROM mcp_servers WHERE tenant_id = ? AND server_key = ?",
        tenant_id,
        server_key,
    )?;
    Ok(res.unwrap_or_default())
}

/// Pin (or re-pin) the MCP tool-manifest hash for a server. Tenant-scoped,
/// parameterized.
pub async fn set_mcp_server_manifest_hash(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    manifest_hash: &str,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "UPDATE mcp_servers SET manifest_hash = ? WHERE tenant_id = ? AND server_key = ?",
        manifest_hash,
        tenant_id,
        server_key
    )?;
    Ok(())
}

/// DB-007 (#932): record that `server_key`'s tool manifest was just
/// (re-)discovered via `POST /v1/mcp/servers/:server_key/tools`. Tenant-scoped,
/// parameterized.
pub async fn touch_mcp_server_discovery(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "UPDATE mcp_servers SET last_discovery_at = CURRENT_TIMESTAMP \
         WHERE tenant_id = ? AND server_key = ?",
        tenant_id,
        server_key
    )?;
    Ok(())
}

/// TASK-0090 (#936): record a snapshot of the discovered MCP tool manifest
/// (its computed `mcp-manifest-1` hash and the raw tool list) on every
/// `POST /v1/mcp/servers/:server_key/tools` discovery call. Tenant-scoped,
/// parameterized. Returns the new snapshot's id.
pub async fn insert_mcp_manifest_snapshot(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    manifest_hash: &str,
    manifest_json: &str,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(pool, "INSERT INTO mcp_manifest_snapshots (id, tenant_id, server_key, manifest_hash, manifest_json) \
         VALUES (?, ?, ?, ?, ?)", &id, tenant_id, server_key, manifest_hash, manifest_json)?;
    Ok(id)
}

/// TASK-0090 (#936): list manifest snapshots for a server, most recent first.
/// Tenant-scoped, parameterized. Also used by #1336 drift-severity classification
/// to diff the newly discovered manifest against the previous snapshot.
pub async fn list_mcp_manifest_snapshots(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    limit: i64,
) -> Result<Vec<McpManifestSnapshotRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        McpManifestSnapshotRecord,
        pool,
        "SELECT * FROM mcp_manifest_snapshots WHERE tenant_id = ? AND server_key = ? \
         ORDER BY created_at DESC LIMIT ?",
        tenant_id,
        server_key,
        limit,
    )
}

/// #1193: re-registering a previously soft-deleted `server_key` revives it
/// (clears `deleted_at`) rather than erroring on the `(tenant_id,
/// server_key)` unique constraint — a soft-deleted row still occupies that
/// key, so "register again" is the only way back in without a hard delete.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_mcp_server(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    name: &str,
    owner_team: Option<&str>,
    transport: &str,
    source: Option<&str>,
    trust_level: &str,
    endpoint: &str,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    crate::execute_query!(pool, "INSERT INTO mcp_servers (id, tenant_id, server_key, name, owner_team, transport, source, trust_level, endpoint, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
         ON CONFLICT(tenant_id, server_key) DO UPDATE SET
            name=excluded.name,
            owner_team=excluded.owner_team,
            transport=excluded.transport,
            source=excluded.source,
            trust_level=excluded.trust_level,
            endpoint=excluded.endpoint,
            status='active',
            deleted_at=NULL", &id, tenant_id, server_key, name, owner_team, transport, source, trust_level, endpoint)?;

    let id: String = crate::fetch_one_scalar!(
        String,
        pool,
        "SELECT id FROM mcp_servers WHERE tenant_id = ? AND server_key = ?",
        tenant_id,
        server_key,
    )?;

    Ok(id)
}

pub async fn get_mcp_server_by_key(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Option<McpServerRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        McpServerRecord,
        pool,
        "SELECT * FROM mcp_servers WHERE tenant_id = ? AND server_key = ? AND deleted_at IS NULL",
        tenant_id,
        server_key,
    )
}

pub async fn upsert_mcp_tool(
    pool: &DbPool,
    tenant_id: &str,
    server_id: &str,
    tool: &McpToolManifestItem,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let input_schema = tool.input_schema.as_ref().map(|schema| schema.to_string());

    crate::execute_query!(pool, "INSERT INTO mcp_tools (id, tenant_id, server_id, tool_key, name, description, input_schema, risk, mutates_state, approval_required, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
         ON CONFLICT(tenant_id, server_id, tool_key) DO UPDATE SET
            name=excluded.name,
            description=excluded.description,
            input_schema=excluded.input_schema,
            risk=excluded.risk,
            mutates_state=excluded.mutates_state,
            approval_required=excluded.approval_required,
            status='pending',
            updated_at=CURRENT_TIMESTAMP", &id, tenant_id, server_id, &tool.tool_key, &tool.name, &tool.description, &input_schema, &tool.risk, tool.mutates_state, tool.approval_required)?;

    let id: String = crate::fetch_one_scalar!(
        String,
        pool,
        "SELECT id FROM mcp_tools WHERE tenant_id = ? AND server_id = ? AND tool_key = ?",
        tenant_id,
        server_id,
        &tool.tool_key,
    )?;

    Ok(id)
}

pub async fn list_mcp_tools(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Vec<McpToolRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        McpToolRecord,
        pool,
        "SELECT mt.*
         FROM mcp_tools mt
         JOIN mcp_servers ms ON mt.server_id = ms.id AND mt.tenant_id = ms.tenant_id
         WHERE mt.tenant_id = ? AND ms.server_key = ?
         ORDER BY mt.tool_key ASC",
        tenant_id,
        server_key
    )
}

pub async fn get_mcp_tool_by_key(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    tool_key: &str,
) -> Result<Option<McpToolRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        McpToolRecord,
        pool,
        "SELECT mt.*
         FROM mcp_tools mt
         JOIN mcp_servers ms ON mt.server_id = ms.id AND mt.tenant_id = ms.tenant_id
         WHERE mt.tenant_id = ? AND ms.server_key = ? AND mt.tool_key = ?",
        tenant_id,
        server_key,
        tool_key
    )
}

pub async fn set_mcp_tool_status(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    tool_key: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "UPDATE mcp_tools
         SET status = ?, updated_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ?
           AND tool_key = ?
           AND server_id = (SELECT id FROM mcp_servers WHERE tenant_id = ? AND server_key = ?)",
        status,
        tenant_id,
        tool_key,
        tenant_id,
        server_key
    )?;

    Ok(result.rows_affected() > 0)
}

/// Quarantine an MCP server — all its tools become deny-by-default.
/// Sets `status = 'quarantined'` on the server; the authorize path checks this.
pub async fn set_mcp_server_status(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "UPDATE mcp_servers SET status = ?
         WHERE tenant_id = ? AND server_key = ?",
        status,
        tenant_id,
        server_key
    )?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_mcp_servers(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<McpServerRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        McpServerRecord,
        pool,
        "SELECT * FROM mcp_servers WHERE tenant_id = ? AND deleted_at IS NULL
         ORDER BY created_at DESC LIMIT ? OFFSET ?",
        tenant_id,
        limit,
        offset
    )
}

/// #1193: soft delete — marks `deleted_at` instead of removing the row.
/// `deleted_at IS NULL` in the `WHERE` clause makes this idempotent: a
/// second delete of an already-deleted server affects zero rows. Filtered
/// back out by `list_mcp_servers`/`get_mcp_server_by_key`/
/// `get_mcp_server_by_id`, and (security-relevant) by the authorize path's
/// own lookups — a deleted server's tools stop being callable, not just
/// hidden from the management UI.
pub async fn delete_mcp_server(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "UPDATE mcp_servers SET deleted_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ? AND server_key = ? AND deleted_at IS NULL",
        tenant_id,
        server_key
    )?;
    Ok(result.rows_affected() > 0)
}

/// #1193: same revive-on-conflict reasoning as [`upsert_mcp_server`] —
/// re-registering a soft-deleted `server_key` clears `deleted_at`.
pub async fn register_mcp_server(
    pool: &DbPool,
    record: &McpServerRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(pool, "INSERT INTO mcp_servers (id, tenant_id, server_key, name, owner_team, transport, source, trust_level, endpoint, status, inspection_enabled, version) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(tenant_id, server_key) DO UPDATE SET \
            name=excluded.name, owner_team=excluded.owner_team, transport=excluded.transport, \
            source=excluded.source, trust_level=excluded.trust_level, endpoint=excluded.endpoint, \
            status=excluded.status, inspection_enabled=excluded.inspection_enabled, version=excluded.version, \
            deleted_at=NULL", &record.id, &record.tenant_id, &record.server_key, &record.name, &record.owner_team, &record.transport, &record.source, &record.trust_level, &record.endpoint, &record.status, record.inspection_enabled, &record.version)?;
    Ok(())
}

pub async fn get_mcp_server_by_id(
    pool: &DbPool,
    tenant_id: &str,
    server_id: &str,
) -> Result<Option<McpServerRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        McpServerRecord,
        pool,
        "SELECT * FROM mcp_servers WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL",
        tenant_id,
        server_id
    )
}

pub async fn get_last_mcp_manifest_snapshot(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Option<McpManifestSnapshotRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        McpManifestSnapshotRecord,
        pool,
        "SELECT * FROM mcp_manifest_snapshots WHERE tenant_id = ? AND server_key = ? \
         ORDER BY created_at DESC LIMIT 1",
        tenant_id,
        server_key
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn update_mcp_server(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    name: Option<&str>,
    owner_team: Option<Option<&str>>,
    transport: Option<&str>,
    source: Option<Option<&str>>,
    trust_level: Option<&str>,
    endpoint: Option<&str>,
    status: Option<&str>,
) -> Result<bool, sqlx::Error> {
    let mut query_str = "UPDATE mcp_servers SET ".to_string();
    let mut bindings = Vec::new();

    if let Some(n) = name {
        query_str.push_str("name = ?, ");
        bindings.push(Some(n.to_string()));
    }
    if let Some(ot) = owner_team {
        query_str.push_str("owner_team = ?, ");
        bindings.push(ot.map(|s| s.to_string()));
    }
    if let Some(t) = transport {
        query_str.push_str("transport = ?, ");
        bindings.push(Some(t.to_string()));
    }
    if let Some(s) = source {
        query_str.push_str("source = ?, ");
        bindings.push(s.map(|v| v.to_string()));
    }
    if let Some(tl) = trust_level {
        query_str.push_str("trust_level = ?, ");
        bindings.push(Some(tl.to_string()));
    }
    if let Some(ep) = endpoint {
        query_str.push_str("endpoint = ?, ");
        bindings.push(Some(ep.to_string()));
    }
    if let Some(st) = status {
        query_str.push_str("status = ?, ");
        bindings.push(Some(st.to_string()));
    }

    if bindings.is_empty() {
        return Ok(false);
    }
    query_str.truncate(query_str.len() - 2);

    query_str.push_str(" WHERE tenant_id = ? AND server_key = ?");

    match pool {
        DbPool::Sqlite(p) => {
            let mut q = sqlx::query(&query_str);
            for val in bindings {
                q = q.bind(val);
            }
            q = q.bind(tenant_id).bind(server_key);
            let result = q.execute(p).await?;
            Ok(result.rows_affected() > 0)
        }
        #[cfg(feature = "postgres")]
        DbPool::Postgres(p) => {
            let pg_sql = crate::db::to_postgres_sql(&query_str);
            let mut q = sqlx::query(&pg_sql);
            for val in bindings {
                q = q.bind(val);
            }
            q = q.bind(tenant_id).bind(server_key);
            let result = q.execute(p).await?;
            Ok(result.rows_affected() > 0)
        }
    }
}

/// Set the per-server MCP response-inspection toggle (#1333). Tenant-scoped;
/// no-op (returns `Ok(false)`) if the server doesn't belong to this tenant.
pub async fn set_mcp_server_inspection_enabled(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let result = crate::execute_query!(
        pool,
        "UPDATE mcp_servers SET inspection_enabled = ? WHERE tenant_id = ? AND server_key = ?",
        enabled,
        tenant_id,
        server_key
    )?;
    Ok(result.rows_affected() > 0)
}

/// Discover MCP tools and register corresponding skills and actions.
pub async fn discover_mcp_tools(
    pool: &DbPool,
    tenant_id: &str,
    server_key: &str,
    tools: &[McpToolManifestItem],
    _new_hash: &str,
) -> Result<Vec<McpToolRecord>, sqlx::Error> {
    let server = get_mcp_server_by_key(pool, tenant_id, server_key)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)?;

    let skill_key = format!("mcp:{}", server_key);
    let skill_id = crate::db::agents::insert_skill(
        pool,
        tenant_id,
        &skill_key,
        &server.name,
        "mcp",
        None,
        server.owner_team.as_deref(),
        None,
    )
    .await?;

    for tool in tools {
        upsert_mcp_tool(pool, tenant_id, &server.id, tool).await?;

        let default_decision = if tool.approval_required {
            "require_approval"
        } else {
            "policy"
        };
        crate::db::agents::insert_skill_action(
            pool,
            &skill_id,
            &tool.tool_key,
            tool.description.as_deref(),
            &tool.risk,
            tool.mutates_state,
            None,
            tool.approval_required,
            default_decision,
        )
        .await?;
    }

    list_mcp_tools(pool, tenant_id, server_key).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_utils::*;
    use crate::db::*;

    /// TASK-0151 (#997): registering an MCP server twice with the same
    /// `(tenant_id, server_key)` must update the existing row in place (new
    /// name/transport/etc., re-activated status) rather than creating a
    /// second row or erroring on the unique constraint.
    #[tokio::test]
    async fn upsert_mcp_server_upserts_on_duplicate_server_key() {
        let pool = setup_pool("mcp_server_upsert").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();

        let first_id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP",
            Some("platform"),
            "http",
            Some("internal-registry"),
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        // Quarantine it, then re-register with the same server_key but new fields.
        set_mcp_server_status(&pool, "tenant_a", "github-mcp", "quarantined")
            .await
            .unwrap();

        let second_id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP v2",
            Some("security"),
            "stdio",
            Some("internal-registry-v2"),
            "semi_trusted_customer",
            "http://127.0.0.1:9002/mcp",
        )
        .await
        .unwrap();

        assert_eq!(first_id, second_id, "upsert must reuse the existing row id");

        let servers = list_mcp_servers(&pool, "tenant_a", 100, 0).await.unwrap();
        assert_eq!(
            servers.len(),
            1,
            "duplicate server_key must not create a second row"
        );

        let server = get_mcp_server_by_key(&pool, "tenant_a", "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.id, first_id);
        assert_eq!(server.name, "GitHub MCP v2");
        assert_eq!(server.owner_team.as_deref(), Some("security"));
        assert_eq!(server.transport, "stdio");
        assert_eq!(server.source.as_deref(), Some("internal-registry-v2"));
        assert_eq!(server.trust_level, "semi_trusted_customer");
        assert_eq!(server.endpoint, "http://127.0.0.1:9002/mcp");
        assert_eq!(
            server.status, "active",
            "re-registration must re-activate a quarantined server"
        );
    }

    /// #1193: `delete_mcp_server` soft-deletes (sets `deleted_at`) instead
    /// of removing the row — it must disappear from `list_mcp_servers`/
    /// `get_mcp_server_by_key`/`get_mcp_server_by_id` while the row persists.
    #[tokio::test]
    async fn delete_mcp_server_soft_deletes_and_hides_from_reads() {
        let pool = setup_pool("mcp_server_soft_delete").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        let id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP",
            None,
            "http",
            None,
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        assert!(delete_mcp_server(&pool, "tenant_a", "github-mcp")
            .await
            .unwrap());

        assert!(
            get_mcp_server_by_key(&pool, "tenant_a", "github-mcp")
                .await
                .unwrap()
                .is_none(),
            "a soft-deleted server must not be returned by get_mcp_server_by_key"
        );
        assert!(
            get_mcp_server_by_id(&pool, "tenant_a", &id)
                .await
                .unwrap()
                .is_none(),
            "a soft-deleted server must not be returned by get_mcp_server_by_id"
        );
        assert!(
            list_mcp_servers(&pool, "tenant_a", 100, 0)
                .await
                .unwrap()
                .is_empty(),
            "a soft-deleted server must not appear in list_mcp_servers"
        );

        let deleted_at: Option<String> = crate::fetch_one_scalar!(
            Option<String>,
            &pool,
            "SELECT deleted_at FROM mcp_servers WHERE tenant_id = ? AND id = ?",
            "tenant_a",
            &id,
        )
        .unwrap();
        assert!(
            deleted_at.is_some(),
            "the row must persist with deleted_at set, not be removed"
        );
    }

    /// #1193: deleting an already-deleted server is a no-op (zero rows
    /// affected), not an error or a double "deleted" event.
    #[tokio::test]
    async fn delete_mcp_server_is_idempotent() {
        let pool = setup_pool("mcp_server_delete_idempotent").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP",
            None,
            "http",
            None,
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();

        assert!(delete_mcp_server(&pool, "tenant_a", "github-mcp")
            .await
            .unwrap());
        assert!(
            !delete_mcp_server(&pool, "tenant_a", "github-mcp")
                .await
                .unwrap(),
            "deleting an already-deleted server must affect zero rows"
        );
    }

    /// #1193: re-registering a previously soft-deleted `server_key` revives
    /// it (clears `deleted_at`) — the unique constraint on `(tenant_id,
    /// server_key)` means the only way back in is reusing the same row.
    #[tokio::test]
    async fn upsert_mcp_server_revives_a_soft_deleted_server() {
        let pool = setup_pool("mcp_server_revive_on_upsert").await;
        register_tenant(&pool, "tenant_a", "Tenant A", "developer")
            .await
            .unwrap();
        let first_id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP",
            None,
            "http",
            None,
            "trusted_internal_signed",
            "http://127.0.0.1:9001/mcp",
        )
        .await
        .unwrap();
        delete_mcp_server(&pool, "tenant_a", "github-mcp")
            .await
            .unwrap();

        let second_id = upsert_mcp_server(
            &pool,
            "tenant_a",
            "github-mcp",
            "GitHub MCP Revived",
            None,
            "http",
            None,
            "trusted_internal_signed",
            "http://127.0.0.1:9002/mcp",
        )
        .await
        .unwrap();
        assert_eq!(first_id, second_id, "revive must reuse the existing row id");

        let server = get_mcp_server_by_key(&pool, "tenant_a", "github-mcp")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.name, "GitHub MCP Revived");
    }
}
