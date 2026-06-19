use crate::models::*;
use sqlx::SqlitePool;

/// Read the pinned MCP tool-manifest hash for a server (`""` if never pinned).
/// Tenant-scoped, parameterized.
pub async fn get_mcp_server_manifest_hash(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<String, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT manifest_hash FROM mcp_servers WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.0).unwrap_or_default())
}

/// Pin (or re-pin) the MCP tool-manifest hash for a server. Tenant-scoped,
/// parameterized.
pub async fn set_mcp_server_manifest_hash(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    manifest_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE mcp_servers SET manifest_hash = ? WHERE tenant_id = ? AND server_key = ?")
        .bind(manifest_hash)
        .bind(tenant_id)
        .bind(server_key)
        .execute(pool)
        .await?;
    Ok(())
}

/// DB-007 (#932): record that `server_key`'s tool manifest was just
/// (re-)discovered via `POST /v1/mcp/servers/:server_key/tools`. Tenant-scoped,
/// parameterized.
pub async fn touch_mcp_server_discovery(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE mcp_servers SET last_discovery_at = CURRENT_TIMESTAMP \
         WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .execute(pool)
    .await?;
    Ok(())
}

/// TASK-0090 (#936): record a snapshot of the discovered MCP tool manifest
/// (its computed `mcp-manifest-1` hash and the raw tool list) on every
/// `POST /v1/mcp/servers/:server_key/tools` discovery call. Tenant-scoped,
/// parameterized. Returns the new snapshot's id.
pub async fn insert_mcp_manifest_snapshot(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    manifest_hash: &str,
    manifest_json: &str,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO mcp_manifest_snapshots (id, tenant_id, server_key, manifest_hash, manifest_json) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(server_key)
    .bind(manifest_hash)
    .bind(manifest_json)
    .execute(pool)
    .await?;
    Ok(id)
}

/// TASK-0090 (#936): list manifest snapshots for a server, most recent first.
/// Tenant-scoped, parameterized. Also used by #1336 drift-severity classification
/// to diff the newly discovered manifest against the previous snapshot.
pub async fn list_mcp_manifest_snapshots(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    limit: i64,
) -> Result<Vec<McpManifestSnapshotRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpManifestSnapshotRecord>(
        "SELECT * FROM mcp_manifest_snapshots WHERE tenant_id = ? AND server_key = ? \
         ORDER BY created_at DESC LIMIT ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .bind(limit)
    .fetch_all(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_mcp_server(
    pool: &SqlitePool,
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
    sqlx::query(
        "INSERT INTO mcp_servers (id, tenant_id, server_key, name, owner_team, transport, source, trust_level, endpoint, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
         ON CONFLICT(tenant_id, server_key) DO UPDATE SET
            name=excluded.name,
            owner_team=excluded.owner_team,
            transport=excluded.transport,
            source=excluded.source,
            trust_level=excluded.trust_level,
            endpoint=excluded.endpoint,
            status='active'",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(server_key)
    .bind(name)
    .bind(owner_team)
    .bind(transport)
    .bind(source)
    .bind(trust_level)
    .bind(endpoint)
    .execute(pool)
    .await?;

    let row: (String,) =
        sqlx::query_as("SELECT id FROM mcp_servers WHERE tenant_id = ? AND server_key = ?")
            .bind(tenant_id)
            .bind(server_key)
            .fetch_one(pool)
            .await?;

    Ok(row.0)
}

pub async fn get_mcp_server_by_key(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Option<McpServerRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpServerRecord>(
        "SELECT * FROM mcp_servers WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .fetch_optional(pool)
    .await
}

pub async fn upsert_mcp_tool(
    pool: &SqlitePool,
    tenant_id: &str,
    server_id: &str,
    tool: &McpToolManifestItem,
) -> Result<String, sqlx::Error> {
    let id = uuid::Uuid::new_v4().to_string();
    let input_schema = tool.input_schema.as_ref().map(|schema| schema.to_string());

    sqlx::query(
        "INSERT INTO mcp_tools (id, tenant_id, server_id, tool_key, name, description, input_schema, risk, mutates_state, approval_required, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
         ON CONFLICT(tenant_id, server_id, tool_key) DO UPDATE SET
            name=excluded.name,
            description=excluded.description,
            input_schema=excluded.input_schema,
            risk=excluded.risk,
            mutates_state=excluded.mutates_state,
            approval_required=excluded.approval_required,
            status='pending',
            updated_at=CURRENT_TIMESTAMP",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(server_id)
    .bind(&tool.tool_key)
    .bind(&tool.name)
    .bind(&tool.description)
    .bind(&input_schema)
    .bind(&tool.risk)
    .bind(tool.mutates_state)
    .bind(tool.approval_required)
    .execute(pool)
    .await?;

    let row: (String,) = sqlx::query_as(
        "SELECT id FROM mcp_tools WHERE tenant_id = ? AND server_id = ? AND tool_key = ?",
    )
    .bind(tenant_id)
    .bind(server_id)
    .bind(&tool.tool_key)
    .fetch_one(pool)
    .await?;

    Ok(row.0)
}

pub async fn list_mcp_tools(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
) -> Result<Vec<McpToolRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpToolRecord>(
        "SELECT mt.*
         FROM mcp_tools mt
         JOIN mcp_servers ms ON mt.server_id = ms.id AND mt.tenant_id = ms.tenant_id
         WHERE mt.tenant_id = ? AND ms.server_key = ?
         ORDER BY mt.tool_key ASC",
    )
    .bind(tenant_id)
    .bind(server_key)
    .fetch_all(pool)
    .await
}

pub async fn get_mcp_tool_by_key(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    tool_key: &str,
) -> Result<Option<McpToolRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpToolRecord>(
        "SELECT mt.*
         FROM mcp_tools mt
         JOIN mcp_servers ms ON mt.server_id = ms.id AND mt.tenant_id = ms.tenant_id
         WHERE mt.tenant_id = ? AND ms.server_key = ? AND mt.tool_key = ?",
    )
    .bind(tenant_id)
    .bind(server_key)
    .bind(tool_key)
    .fetch_optional(pool)
    .await
}

pub async fn set_mcp_tool_status(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    tool_key: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE mcp_tools
         SET status = ?, updated_at = CURRENT_TIMESTAMP
         WHERE tenant_id = ?
           AND tool_key = ?
           AND server_id = (SELECT id FROM mcp_servers WHERE tenant_id = ? AND server_key = ?)",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(tool_key)
    .bind(tenant_id)
    .bind(server_key)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Quarantine an MCP server — all its tools become deny-by-default.
/// Sets `status = 'quarantined'` on the server; the authorize path checks this.
pub async fn set_mcp_server_status(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    status: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE mcp_servers SET status = ?
         WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(status)
    .bind(tenant_id)
    .bind(server_key)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_mcp_servers(
    pool: &SqlitePool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<McpServerRecord>, sqlx::Error> {
    sqlx::query_as::<_, McpServerRecord>(
        "SELECT * FROM mcp_servers WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn update_mcp_server(
    pool: &SqlitePool,
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

    let mut q = sqlx::query(&query_str);
    for val in bindings {
        q = q.bind(val);
    }
    q = q.bind(tenant_id).bind(server_key);

    let result = q.execute(pool).await?;
    Ok(result.rows_affected() > 0)
}

/// Set the per-server MCP response-inspection toggle (#1333). Tenant-scoped;
/// no-op (returns `Ok(false)`) if the server doesn't belong to this tenant.
pub async fn set_mcp_server_inspection_enabled(
    pool: &SqlitePool,
    tenant_id: &str,
    server_key: &str,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE mcp_servers SET inspection_enabled = ? WHERE tenant_id = ? AND server_key = ?",
    )
    .bind(enabled)
    .bind(tenant_id)
    .bind(server_key)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
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
}
