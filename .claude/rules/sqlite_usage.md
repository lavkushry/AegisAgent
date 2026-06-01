# AI Skill: SQLite Database Usage & SQLx (`skills/sqlite_usage.md`)

This skill defines the configurations, transaction management guidelines, compile-time query verifications, and migrations when using SQLx with SQLite.

---

## 1. Concurrent Settings & Connection Tuning

Since SQLite locks the database file on write, we configure connection pool properties to allow concurrent reading while avoiding database locks or writer timeouts.

### Guidelines:
- **Write-Ahead Logging (WAL):** Enable WAL mode to allow readers to query while writers lock rows.
- **Busy Timeout:** Define a retry wait time (5 seconds) so database write locks don't instantly throw errors.
- **Synchronous Normal:** Reduce disk synchronization sync levels to increase transaction throughput safely.
  ```rust
  let opts = SqliteConnectOptions::new()
      .filename("db/aegisagent.db")
      .create_if_missing(true)
      .journal_mode(SqliteJournalMode::Wal)
      .synchronous(SqliteSynchronous::Normal)
      .busy_timeout(Duration::from_secs(5));
  ```

---

## 2. Compile-Time Query Verification (`sqlx::query!`)

We prefer compile-time checked queries to catch SQL schema mismatches during compilation.

### Guidelines:
- **Macro Usage:** Use `sqlx::query!` and `sqlx::query_as!` instead of raw string queries where possible:
  ```rust
  let agent = sqlx::query_as!(
      AgentModel,
      "SELECT id, name, risk_tier FROM agents WHERE id = ? AND tenant_id = ?",
      agent_id,
      tenant_id
  )
  .fetch_optional(&pool)
  .await?;
  ```
- **Offline Metadata Preparation:** In CI pipelines or environments without a running database, run the SQLx prepare command to save query cache states into `sqlx-data.json`:
  ```bash
  cargo sqlx prepare -- --all-targets
  ```

---

## 3. Database Transactions

Write operations that involve multiple table updates (e.g. creating an approval and writing a log) must be wrapped in transactional scopes.

### Guidelines:
- **Keep Transactions Small:** Acquire transactions as late as possible, and commit them immediately after work completes.
  ```rust
  let mut tx = pool.begin().await?;
  
  sqlx::query("INSERT INTO approvals ...")
      .bind(...)
      .execute(&mut *tx)
      .await?;
      
  tx.commit().await?;
  ```

---

## 4. DB Migration Lifecycle

Schema modifications are written as SQL migration files.
- Add migrations using: `sqlx migrate add -r <migration_name>`
- Apply migrations automatically on startup inside `main.rs`:
  ```rust
  sqlx::migrate!("./migrations")
      .run(&pool)
      .await?;
  ```
