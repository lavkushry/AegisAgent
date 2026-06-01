# AI Skill: SQLite Database Migration & Management (`skills/database_migration.md`)

This skill describes how to manage the SQLite database schema, run migrations using SQLx, handle database concurrency, and use compile-time checked queries.

---

## 1. Concurrency and Write-Ahead Logging (WAL)

SQLite is an in-process database. While reads are highly concurrent, database write operations lock the file. To prevent write contention and application latency, AegisAgent configures SQLx with **Write-Ahead Logging (WAL)** and a **busy timeout**.

### Connection Setup:
When establishing database pools, configure the connect options as follows:

```rust
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalModePool};
use std::time::Duration;

pub async fn establish_connection() -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::new()
        .filename("db/aegisagent.db")
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal) // Enable WAL mode
        .synchronous(SqliteSynchronous::Normal) // Balance performance and durability
        .busy_timeout(Duration::from_secs(5)); // Retry locked writes for 5 seconds

    SqlitePool::connect_with(opts).await
}
```

---

## 2. SQLx Migrations

We use the SQLx CLI tool to manage database schemas.

### Commands:

1. **Install SQLx CLI (if not present):**
   ```bash
   cargo install sqlx-cli --no-default-features --features sqlite
   ```
2. **Create a New Migration:**
   ```bash
   # Execute from repository root
   sqlx migrate add -r <migration_name>
   ```
   This creates up and down SQL files in the `migrations/` directory.
3. **Run Pending Migrations:**
   ```bash
   export DATABASE_URL="sqlite://db/aegisagent.db"
   sqlx migrate run
   ```
4. **Revert Last Migration:**
   ```bash
   sqlx migrate revert
   ```

---

## 3. Compile-Time Query Verification (`sqlx-data.json`)

SQLx verify queries against a live database schema at compile time when using `sqlx::query!`. 

### Offline Mode:
To build without a running SQLite instance (e.g., in CI environments or local code editors), SQLx uses a metadata file named `sqlx-data.json`.

### Rebuilding Offline Metadata:
If you modify database schemas or queries:
1. Start the SQLite database with applied migrations.
2. Set the `DATABASE_URL` environment variable.
3. Run the prepare command:
   ```bash
   export DATABASE_URL="sqlite://db/aegisagent.db"
   cargo sqlx prepare -- --all-targets
   ```
4. This updates `sqlx-data.json` at the gateway folder root. Commit this file.

---

## 4. Database Concurrency Runbook
1. **Asynchronous Writes:** For non-critical writes (like `audit_events`), offload database inserts to a background worker using Tokio channels (`tokio::sync::mpsc`) to prevent blocking the HTTP response lifecycle.
2. **Transaction Scopes:** Keep transactions (`pool.begin()`) as short as possible to release file write locks quickly.
