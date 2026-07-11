# Runbook: Backup and Restore

**Endpoint:** `POST /v1/admin/backup` (#945) · **Restore:** manual procedure (no restore API exists — see below)

> **Status:** Implemented for the SQLite deployment path. PostgreSQL backup/restore requires database-native tooling and a separately tested procedure.

## Overview

Use this runbook before schema-risking changes, during disaster-recovery exercises, or after suspected corruption/deletion. A successful restore is not merely “the process starts”: readiness, expected tenant data, migrations, and receipt-chain integrity must all pass.

Prerequisites are an authenticated admin credential, access to the gateway host/volume, enough backup capacity, a recorded database path, and a maintenance window for restore.

## Symptoms

- Scheduled maintenance before a risky migration or upgrade.
- Suspected database corruption, accidental data deletion, or a failed migration that needs rollback.
- Routine disaster-recovery drill.

## Taking a backup (investigation/prep step)

`POST /v1/admin/backup` writes a **consistent point-in-time copy** via SQLite's `VACUUM INTO` — safe to run against a live database, no downtime required:

```bash
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://127.0.0.1:8080/v1/admin/backup" \
  -d '{"filename": "pre-migration-2026-06-17.db"}'
# {"path": "backups/pre-migration-2026-06-17.db", "size_bytes": 1048576}
```

Notes:
- `filename` must be a **bare filename** — no path separators, no `..`. The gateway rejects (`400`) anything that looks like a path-traversal attempt; this is a deliberate restriction, not a bug.
- Files are written under `AEGIS_BACKUP_DIR` (default `backups/` relative to the gateway's working directory; created automatically if missing).
- `VACUUM INTO` refuses to overwrite an existing file — a duplicate filename returns `409`. Use a unique, ideally timestamped, filename per backup.
- There is no automatic backup schedule built in. For routine backups, call this endpoint from your own cron/scheduler — AegisAgent only provides the point-in-time-copy primitive.

## Restoring from a backup

**There is no `POST /v1/admin/restore` endpoint.** SQLite restoration is a file-level operation, done with the gateway stopped:

1. **Stop the gateway process.** A restore while the gateway holds the live database open risks corrupting either file.
2. **Move the current (possibly corrupted/bad) database out of the way** rather than deleting it immediately — keep it until you've confirmed the restore worked:
   ```bash
   mv db/aegisagent.db db/aegisagent.db.bad-$(date +%s)
   ```
3. **Copy the backup file into place** as the live database path:
   ```bash
   cp backups/pre-migration-2026-06-17.db db/aegisagent.db
   ```
4. **Restart the gateway.** It runs `sqlx::migrate!` on startup — if the backup predates a migration that has since landed, the migration runs against the restored file as if it were a fresh upgrade. If the backup is *newer* than the currently deployed binary's migrations (rare — restoring "forward"), do not start an older binary version against it.
5. Confirm the gateway starts cleanly and `GET /health` / `GET /readyz` report healthy before declaring the restore complete.

## Verification

- `GET /readyz` returns healthy.
- Spot-check that expected data is present: e.g. `GET /v1/agents`, `GET /v1/decisions?limit=5` return data consistent with the backup's point in time (not the bad state you restored away from).
- `aegis-verify-receipts` or `POST /v1/receipts/verify-chain` against the restored database confirms the receipt hash chain is intact (see [`receipt-chain-verification.md`](receipt-chain-verification.md)) — a restore from a clean backup should never break chain continuity, since `VACUUM INTO` copies the database byte-for-byte at the row level.
- Once confident, remove the `*.bad-*` file you set aside in step 2 (or archive it for postmortem if the corruption cause is still unclear).

## Security and Failure Handling

- Backups contain tenant data and security evidence. Encrypt them at rest, restrict access, record custody, and apply retention/deletion policy.
- Never accept a user-controlled path; the API deliberately requires a bare filename under `AEGIS_BACKUP_DIR`.
- Do not start an older binary against a database whose schema is newer than that binary supports.
- If receipt verification fails, preserve both restored and displaced databases and treat the result as an evidence-integrity incident.
- Test restore on an isolated copy before relying on a backup for production recovery.

## Rollback and Recovery

If the restored database fails readiness or verification, stop the gateway and restore the displaced `*.bad-*` database only when doing so is safer and its integrity is understood. Otherwise select an earlier verified backup. Keep traffic disabled until one candidate passes startup, readiness, tenant spot checks, and receipt verification.

Record actual recovery point and recovery time. The product must not claim an RPO/RTO that has not been exercised on deployment-class storage.

## References

- [Receipt Chain Verification](receipt-chain-verification.md)
- [Deployment Guide](../deployment-guide.md)
- [Production Hardening](../production-hardening.md)
- [Fail-Closed Behavior](../fail-closed-behavior.md)
