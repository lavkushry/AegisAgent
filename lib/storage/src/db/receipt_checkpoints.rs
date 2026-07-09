//! Phase 8.3: receipt chain checkpoints for investigation evidence export.

use crate::db::DbPool;
use aegis_api::models::ReceiptCheckpointRecord;

pub async fn insert_receipt_checkpoint(
    pool: &DbPool,
    record: &ReceiptCheckpointRecord,
) -> Result<(), sqlx::Error> {
    crate::execute_query!(
        pool,
        "INSERT INTO receipt_checkpoints (
            id, tenant_id, sequence_start, sequence_end, chain_head_hash,
            merkle_root, receipt_count, signature, signer_key_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &record.id,
        &record.tenant_id,
        record.sequence_start,
        record.sequence_end,
        &record.chain_head_hash,
        &record.merkle_root,
        record.receipt_count,
        &record.signature,
        &record.signer_key_id,
        record.created_at
    )?;
    Ok(())
}

pub async fn get_receipt_checkpoint_by_id(
    pool: &DbPool,
    tenant_id: &str,
    checkpoint_id: &str,
) -> Result<Option<ReceiptCheckpointRecord>, sqlx::Error> {
    crate::fetch_optional_as!(
        ReceiptCheckpointRecord,
        pool,
        "SELECT id, tenant_id, sequence_start, sequence_end, chain_head_hash,
                merkle_root, receipt_count, signature, signer_key_id, created_at
         FROM receipt_checkpoints
         WHERE tenant_id = ? AND id = ?",
        tenant_id,
        checkpoint_id
    )
}

pub async fn list_receipt_checkpoints(
    pool: &DbPool,
    tenant_id: &str,
    limit: i64,
) -> Result<Vec<ReceiptCheckpointRecord>, sqlx::Error> {
    crate::fetch_all_as!(
        ReceiptCheckpointRecord,
        pool,
        "SELECT id, tenant_id, sequence_start, sequence_end, chain_head_hash,
                merkle_root, receipt_count, signature, signer_key_id, created_at
         FROM receipt_checkpoints
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT ?",
        tenant_id,
        limit
    )
}
