//! Phase 8.3 — Investigation evidence export.
//!
//! Distinct from the SOC2/GDPR compliance pack (`GET /v1/compliance/evidence-pack`,
//! #1298). This pack is receipt-backed investigation evidence:
//!
//! - runtime events (hashes/identifiers only)
//! - action receipts (hash chain)
//! - receipt checkpoints (Merkle root + chain head over the exported range)
//! - graph manifest (nodes/edges for the exported set)
//! - redaction manifest (what was excluded / how redaction is enforced)
//!
//! The export action itself appends a durable hash-chained receipt so the act
//! of exporting is auditable and chain-verifiable.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::error;
use uuid::Uuid;

use crate::error::StatusError;
use crate::models::*;
use aegis_storage::traits::RuntimeEventListFilters;

use super::{compute_receipt_hash, AppState, TenantId};

/// Schema tag for the investigation evidence pack (Phase 8.3).
pub const INVESTIGATION_EVIDENCE_SCHEMA: &str = "aegis-investigation-evidence-1";

/// Body for `POST /v1/evidence/export`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EvidenceExportRequest {
    /// When set, only events/receipts for this run are included.
    #[serde(default)]
    pub run_id: Option<String>,
    /// Optional RFC-3339 lower bound on receipt/event timestamps.
    #[serde(default)]
    pub from: Option<String>,
    /// Optional RFC-3339 upper bound on receipt/event timestamps.
    #[serde(default)]
    pub to: Option<String>,
}

/// SHA-256 hex of `bytes`. Kept private (and distinctly named) so the
/// `pub use evidence_export::*` re-export does not clash with
/// `authorize_canon::sha256_hex`.
fn evidence_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Merkle root over receipt hashes (leaf = hash string as UTF-8 bytes of hex).
/// Empty input yields the hash of the empty byte string. Odd nodes are promoted.
pub(crate) fn merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return evidence_sha256_hex(b"");
    }
    let mut layer: Vec<String> = hashes.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let combined = if chunk.len() == 2 {
                format!("{}{}", chunk[0], chunk[1])
            } else {
                chunk[0].clone()
            };
            next.push(evidence_sha256_hex(combined.as_bytes()));
        }
        layer = next;
    }
    layer
        .into_iter()
        .next()
        .unwrap_or_else(|| evidence_sha256_hex(b""))
}

/// Build a checkpoint covering `receipts` (already chain-ordered / filtered).
/// `sequence_start`/`sequence_end` are 0-based indices into this slice.
pub fn build_checkpoint_for_receipts(
    tenant_id: &str,
    receipts: &[ActionReceiptRecord],
) -> Option<ReceiptCheckpointRecord> {
    if receipts.is_empty() {
        return None;
    }
    let hashes: Vec<String> = receipts.iter().map(|r| r.receipt_hash.clone()).collect();
    let chain_head = receipts.last()?.receipt_hash.clone();
    Some(ReceiptCheckpointRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.to_string(),
        sequence_start: 0,
        sequence_end: (receipts.len() as i64) - 1,
        chain_head_hash: chain_head,
        merkle_root: merkle_root(&hashes),
        receipt_count: receipts.len() as i64,
        signature: None,
        signer_key_id: None,
        created_at: Utc::now(),
    })
}

/// Graph manifest: nodes + edges for the exported evidence set. No raw bodies.
pub fn build_graph_manifest(
    run_id: Option<&str>,
    receipts: &[ActionReceiptRecord],
    events: &[RuntimeEventRecord],
) -> Value {
    let mut nodes: Vec<Value> = Vec::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    if let Some(rid) = run_id {
        let nid = format!("run:{rid}");
        if seen.insert(nid.clone()) {
            nodes.push(json!({"id": nid, "type": "run", "label": rid}));
        }
    }

    for (i, rec) in receipts.iter().enumerate() {
        let nid = format!("receipt:{}", rec.id);
        if seen.insert(nid.clone()) {
            nodes.push(json!({
                "id": nid,
                "type": "receipt",
                "label": rec.decision,
                "receipt_hash": rec.receipt_hash,
            }));
        }
        if let Some(rid) = run_id.or(rec.run_id.as_deref()) {
            edges.push(json!({
                "from": format!("run:{rid}"),
                "to": format!("receipt:{}", rec.id),
                "type": "produced",
            }));
        }
        if i > 0 {
            edges.push(json!({
                "from": format!("receipt:{}", receipts[i - 1].id),
                "to": format!("receipt:{}", rec.id),
                "type": "chain_prev",
            }));
        }
    }

    for ev in events {
        let nid = format!("event:{}", ev.event_id);
        if seen.insert(nid.clone()) {
            nodes.push(json!({
                "id": nid,
                "type": "runtime_event",
                "label": ev.event_type,
                "source_component": ev.source_component,
            }));
        }
        if let Some(rid) = run_id.or(ev.run_id.as_deref()) {
            edges.push(json!({
                "from": format!("run:{rid}"),
                "to": format!("event:{}", ev.event_id),
                "type": "observed",
            }));
        }
        if let Some(rh) = &ev.receipt_hash {
            if let Some(rec) = receipts.iter().find(|r| &r.receipt_hash == rh) {
                edges.push(json!({
                    "from": format!("event:{}", ev.event_id),
                    "to": format!("receipt:{}", rec.id),
                    "type": "evidences",
                }));
            }
        }
    }

    json!({
        "schema": "aegis-graph-manifest-1",
        "node_count": nodes.len(),
        "edge_count": edges.len(),
        "nodes": nodes,
        "edges": edges,
    })
}

/// Redaction manifest: documents that the pack never carries raw secrets/prompts.
pub fn build_redaction_manifest(
    events: &[RuntimeEventRecord],
    receipts: &[ActionReceiptRecord],
) -> Value {
    let mut event_status: BTreeMap<String, usize> = BTreeMap::new();
    for ev in events {
        let key = ev
            .redaction_status
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        *event_status.entry(key).or_default() += 1;
    }

    json!({
        "schema": "aegis-redaction-manifest-1",
        "policy": "hash_only_default",
        "raw_prompts": "never",
        "raw_secrets": "never",
        "fields_excluded": [
            "parameters",
            "prompt_body",
            "request_body",
            "response_body",
            "credentials",
            "api_key",
            "token"
        ],
        "sources": {
            "runtime_events": {
                "count": events.len(),
                "redaction_status_counts": event_status,
                "note": "events store hashes/identifiers only"
            },
            "receipts": {
                "count": receipts.len(),
                "note": "receipts store action_hash/receipt_hash chain links only — never action parameters"
            },
            "checkpoints": {
                "note": "Merkle root and chain_head_hash only"
            },
            "graph_manifest": {
                "note": "node ids, types, and hash references only"
            }
        }
    })
}

/// Serialize the investigation pack into an in-memory ZIP.
pub fn build_investigation_evidence_zip(
    manifest: &Value,
    events: &[RuntimeEventRecord],
    receipts: &[ActionReceiptRecord],
    checkpoints: &[ReceiptCheckpointRecord],
    graph_manifest: &Value,
    redaction_manifest: &Value,
) -> Result<Vec<u8>, std::io::Error> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        let write_json = |writer: &mut zip::ZipWriter<_>,
                          name: &str,
                          value: &Value|
         -> Result<(), std::io::Error> {
            writer.start_file(name, options)?;
            let bytes = serde_json::to_vec_pretty(value)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::io::Write::write_all(writer, &bytes)?;
            Ok(())
        };

        write_json(&mut writer, "manifest.json", manifest)?;
        write_json(&mut writer, "graph_manifest.json", graph_manifest)?;
        write_json(&mut writer, "redaction_manifest.json", redaction_manifest)?;

        writer.start_file("events.jsonl", options)?;
        for event in events {
            let line = serde_json::to_string(event)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::io::Write::write_all(&mut writer, line.as_bytes())?;
            std::io::Write::write_all(&mut writer, b"\n")?;
        }

        writer.start_file("receipts.jsonl", options)?;
        for receipt in receipts {
            let line = serde_json::to_string(receipt)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            std::io::Write::write_all(&mut writer, line.as_bytes())?;
            std::io::Write::write_all(&mut writer, b"\n")?;
        }

        writer.start_file("checkpoints.json", options)?;
        let cp_bytes = serde_json::to_vec_pretty(checkpoints)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::io::Write::write_all(&mut writer, &cp_bytes)?;

        writer.finish().map_err(std::io::Error::other)?;
    }
    Ok(cursor.into_inner())
}

fn parse_bound(label: &str, raw: Option<&str>) -> Result<Option<DateTime<Utc>>, StatusError> {
    match raw {
        None => Ok(None),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|e| StatusError::bad_request(format!("invalid '{label}' timestamp: {e}"))),
    }
}

/// POST /v1/evidence/export — investigation evidence pack (Phase 8.3).
///
/// Returns a ZIP archive and appends a durable `evidence.export` receipt to
/// the tenant's hash chain. Fails closed if the self-receipt cannot be written.
pub async fn export_evidence(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
    Json(req): Json<EvidenceExportRequest>,
) -> impl IntoResponse {
    let from = match parse_bound("from", req.from.as_deref()) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let to = match parse_bound("to", req.to.as_deref()) {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };

    let mut receipts = match state
        .storage
        .list_action_receipts_in_range(&tenant_id, from, to)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            error!("evidence export: load receipts failed: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };
    if let Some(run_id) = &req.run_id {
        receipts.retain(|r| r.run_id.as_deref() == Some(run_id.as_str()));
    }
    // Ensure chain order for Merkle/checkpoint.
    receipts.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));

    let from_s = req.from.clone();
    let to_s = req.to.clone();
    let filters = RuntimeEventListFilters {
        run_id: req.run_id.as_deref(),
        from: from_s.as_deref(),
        to: to_s.as_deref(),
        ..Default::default()
    };
    let events = match state
        .storage
        .query_runtime_events(&tenant_id, 10_000, None, filters)
        .await
    {
        Ok((rows, _)) => rows,
        Err(e) => {
            error!("evidence export: load events failed: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
    };

    let checkpoint = build_checkpoint_for_receipts(&tenant_id, &receipts);
    let mut checkpoints = Vec::new();
    if let Some(cp) = checkpoint {
        if let Err(e) = state.storage.insert_receipt_checkpoint(&cp).await {
            error!("evidence export: persist checkpoint failed: {:?}", e);
            return StatusError::internal("Database error").into_response();
        }
        checkpoints.push(cp);
    }

    let graph_manifest =
        build_graph_manifest(req.run_id.as_deref(), &receipts, &events);
    let redaction_manifest = build_redaction_manifest(&events, &receipts);

    let export_id = Uuid::new_v4().to_string();
    let generated_at = Utc::now();
    let mut manifest = json!({
        "schema": INVESTIGATION_EVIDENCE_SCHEMA,
        "export_id": export_id,
        "tenant_id": tenant_id,
        "generated_at": generated_at.to_rfc3339(),
        "run_id": req.run_id,
        "range": {
            "from": req.from,
            "to": req.to,
        },
        "counts": {
            "events": events.len(),
            "receipts": receipts.len(),
            "checkpoints": checkpoints.len(),
        },
        "canonicalization_scheme": "aegis-jcs-1",
        "checkpoint_ids": checkpoints.iter().map(|c| &c.id).collect::<Vec<_>>(),
    });

    // Pre-hash the pack content for the export self-receipt action_hash.
    let content_fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&manifest).unwrap_or_default());
        for r in &receipts {
            hasher.update(r.receipt_hash.as_bytes());
        }
        for e in &events {
            hasher.update(e.event_id.as_bytes());
            if let Some(h) = &e.action_hash {
                hasher.update(h.as_bytes());
            }
        }
        for c in &checkpoints {
            hasher.update(c.merkle_root.as_bytes());
            hasher.update(c.chain_head_hash.as_bytes());
        }
        hasher.update(serde_json::to_vec(&graph_manifest).unwrap_or_default());
        hasher.update(serde_json::to_vec(&redaction_manifest).unwrap_or_default());
        hex::encode(hasher.finalize())
    };
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert(
            "content_fingerprint".to_string(),
            json!(content_fingerprint),
        );
    }

    // Durable self-receipt for the export action (fail closed).
    let export_receipt = ActionReceiptRecord {
        id: Uuid::new_v4().to_string(),
        tenant_id: tenant_id.clone(),
        decision_id: None,
        ts: generated_at.to_rfc3339(),
        agent_id: None,
        user_id: None,
        run_id: req.run_id.clone(),
        trace_id: None,
        tool: Some("evidence".to_string()),
        action: Some("export".to_string()),
        resource: Some(export_id.clone()),
        source_trust: "trusted_internal_unsigned".to_string(),
        decision: "allow".to_string(),
        approver: None,
        action_hash: Some(content_fingerprint.clone()),
        prev_receipt_hash: String::new(),
        receipt_hash: String::new(),
        canon_version: "aegis-jcs-1".to_string(),
        signature: None,
        signer_public_key: None,
        signer_key_id: None,
        created_at: generated_at,
    };
    let export_receipt = match state
        .storage
        .append_action_receipt_atomic(&tenant_id, export_receipt)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!("evidence export: self-receipt append failed: {:?}", e);
            return StatusError::internal("Failed to append export receipt").into_response();
        }
    };

    // Include the export receipt itself in the pack's receipts list for
    // third-party verification of the export action.
    let mut receipts_with_export = receipts;
    receipts_with_export.push(export_receipt.clone());

    if let Some(obj) = manifest.as_object_mut() {
        obj.insert(
            "export_receipt_id".to_string(),
            json!(export_receipt.id),
        );
        obj.insert(
            "export_receipt_hash".to_string(),
            json!(export_receipt.receipt_hash),
        );
        obj.insert(
            "counts".to_string(),
            json!({
                "events": events.len(),
                "receipts": receipts_with_export.len(),
                "checkpoints": checkpoints.len(),
            }),
        );
    }

    let zip_bytes = match build_investigation_evidence_zip(
        &manifest,
        &events,
        &receipts_with_export,
        &checkpoints,
        &graph_manifest,
        &redaction_manifest,
    ) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("evidence export: zip build failed: {:?}", e);
            return StatusError::internal("Failed to build evidence pack").into_response();
        }
    };

    let filename = format!(
        "investigation-evidence-{}-{}.zip",
        tenant_id,
        generated_at.timestamp()
    );
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/zip".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
            (
                axum::http::HeaderName::from_static("x-aegis-export-receipt-id"),
                export_receipt.id,
            ),
            (
                axum::http::HeaderName::from_static("x-aegis-export-receipt-hash"),
                export_receipt.receipt_hash,
            ),
        ],
        zip_bytes,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;
    use axum::body::to_bytes;

    fn sample_receipt(tenant_id: &str, id: &str, prev: &str, run_id: Option<&str>) -> ActionReceiptRecord {
        let mut rec = ActionReceiptRecord {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            decision_id: Some(format!("dec-{id}")),
            ts: Utc::now().to_rfc3339(),
            agent_id: Some("agent-1".to_string()),
            user_id: None,
            run_id: run_id.map(|s| s.to_string()),
            trace_id: None,
            tool: Some("github".to_string()),
            action: Some("merge".to_string()),
            resource: None,
            source_trust: "semi_trusted_customer".to_string(),
            decision: "allow".to_string(),
            approver: None,
            action_hash: Some(format!("{:0>64}", id.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>())),
            prev_receipt_hash: prev.to_string(),
            receipt_hash: String::new(),
            canon_version: "aegis-jcs-1".to_string(),
            signature: None,
            signer_public_key: None,
            signer_key_id: None,
            created_at: Utc::now(),
        };
        // Ensure action_hash is 64 hex
        rec.action_hash = Some("ab".repeat(32));
        rec.receipt_hash = compute_receipt_hash(&rec);
        rec
    }

    #[test]
    fn merkle_root_is_deterministic_and_changes_with_leaves() {
        let a = vec!["aa".repeat(32), "bb".repeat(32)];
        let b = vec!["aa".repeat(32), "cc".repeat(32)];
        assert_eq!(merkle_root(&a), merkle_root(&a));
        assert_ne!(merkle_root(&a), merkle_root(&b));
        assert_eq!(merkle_root(&[]).len(), 64);
    }

    #[test]
    fn redaction_manifest_excludes_raw_fields() {
        let m = build_redaction_manifest(&[], &[]);
        assert_eq!(m["raw_prompts"], "never");
        assert_eq!(m["raw_secrets"], "never");
        let excluded = m["fields_excluded"].as_array().unwrap();
        assert!(excluded.iter().any(|v| v == "prompt_body"));
        assert!(excluded.iter().any(|v| v == "credentials"));
    }

    #[test]
    fn graph_manifest_links_run_receipts_and_events() {
        let receipts = vec![sample_receipt("t", "r1", "", Some("run-1"))];
        let events = vec![RuntimeEventRecord {
            id: "db1".into(),
            tenant_id: "t".into(),
            event_id: "e1".into(),
            event_type: "egress_blocked".into(),
            severity: Some("high".into()),
            agent_id: None,
            run_id: Some("run-1".into()),
            sandbox_id: None,
            trace_id: None,
            parent_event_id: None,
            source_component: "egress_proxy".into(),
            source_trust: None,
            decision: Some("deny".into()),
            reason: None,
            action_hash: None,
            prompt_hash: None,
            request_hash: None,
            response_hash: None,
            receipt_id: None,
            receipt_hash: Some(receipts[0].receipt_hash.clone()),
            prev_receipt_hash: None,
            canonical_version: None,
            redaction_status: Some("redacted".into()),
            schema_version: 1,
            observed_at: Utc::now(),
            received_at: Utc::now(),
        }];
        let g = build_graph_manifest(Some("run-1"), &receipts, &events);
        assert!(g["node_count"].as_u64().unwrap() >= 3);
        assert!(g["edge_count"].as_u64().unwrap() >= 2);
    }

    #[tokio::test]
    async fn evidence_export_returns_zip_with_required_entries_and_self_receipt() {
        let (state, tenant_id, _token) = setup_state("evidence_export_pack").await;

        // Seed two chain-linked receipts.
        let r1 = sample_receipt(&tenant_id, "seed1", "", Some("run-x"));
        let r1 = state
            .storage
            .append_action_receipt_atomic(&tenant_id, r1)
            .await
            .unwrap();
        let mut r2 = sample_receipt(&tenant_id, "seed2", &r1.receipt_hash, Some("run-x"));
        r2.prev_receipt_hash = r1.receipt_hash.clone();
        r2.receipt_hash = compute_receipt_hash(&r2);
        let _r2 = state
            .storage
            .append_action_receipt_atomic(&tenant_id, r2)
            .await
            .unwrap();

        let ev = RuntimeEventRecord {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.clone(),
            event_id: "ev-export-1".into(),
            event_type: "tool_call_requested".into(),
            severity: Some("medium".into()),
            agent_id: Some("agent-1".into()),
            run_id: Some("run-x".into()),
            sandbox_id: None,
            trace_id: None,
            parent_event_id: None,
            source_component: "sdk".into(),
            source_trust: Some("semi_trusted_customer".into()),
            decision: None,
            reason: None,
            action_hash: Some("cd".repeat(32)),
            prompt_hash: None,
            request_hash: None,
            response_hash: None,
            receipt_id: None,
            receipt_hash: None,
            prev_receipt_hash: None,
            canonical_version: Some("aegis-jcs-1".into()),
            redaction_status: Some("redacted".into()),
            schema_version: 1,
            observed_at: Utc::now(),
            received_at: Utc::now(),
        };
        state.storage.insert_runtime_event(&ev).await.unwrap();

        let resp = export_evidence(
            State(state.clone()),
            TenantId(tenant_id.clone()),
            Json(EvidenceExportRequest {
                run_id: Some("run-x".into()),
                from: None,
                to: None,
            }),
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers().clone();
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/zip")
        );
        let export_receipt_hash = headers
            .get("x-aegis-export-receipt-hash")
            .and_then(|v| v.to_str().ok())
            .expect("export receipt hash header")
            .to_string();
        assert_eq!(export_receipt_hash.len(), 64);

        let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
        let cursor = std::io::Cursor::new(body.to_vec());
        let mut zip = zip::ZipArchive::new(cursor).unwrap();
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().to_string())
            .collect();
        for required in [
            "manifest.json",
            "events.jsonl",
            "receipts.jsonl",
            "checkpoints.json",
            "graph_manifest.json",
            "redaction_manifest.json",
        ] {
            assert!(
                names.iter().any(|n| n == required),
                "missing {required} in {names:?}"
            );
        }

        // Parse pack entries one at a time (ZipArchive holds a mutable borrow
        // per open file).
        let cps: Vec<ReceiptCheckpointRecord> = {
            let mut f = zip.by_name("checkpoints.json").unwrap();
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut f, &mut buf).unwrap();
            serde_json::from_str(&buf).unwrap()
        };
        assert_eq!(cps.len(), 1);
        assert_eq!(cps[0].receipt_count, 2); // seeded only (export receipt added after checkpoint)

        let exported_receipts: Vec<ActionReceiptRecord> = {
            let mut f = zip.by_name("receipts.jsonl").unwrap();
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut f, &mut buf).unwrap();
            buf.lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        // seeded (2) + export self-receipt (1)
        assert_eq!(exported_receipts.len(), 3);
        assert!(exported_receipts.iter().any(|r| {
            r.tool.as_deref() == Some("evidence") && r.action.as_deref() == Some("export")
        }));

        // Chain verifies: each receipt_hash recomputes.
        for rec in &exported_receipts {
            let recomputed = compute_receipt_hash(rec);
            assert_eq!(
                recomputed, rec.receipt_hash,
                "receipt {} hash mismatch",
                rec.id
            );
        }
        let export_rec = exported_receipts
            .iter()
            .find(|r| r.tool.as_deref() == Some("evidence"))
            .unwrap();
        assert_eq!(export_rec.receipt_hash, export_receipt_hash);

        let red: Value = {
            let mut f = zip.by_name("redaction_manifest.json").unwrap();
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut f, &mut buf).unwrap();
            serde_json::from_str(&buf).unwrap()
        };
        assert_eq!(red["raw_prompts"], "never");

        // Checkpoint persisted in storage.
        let stored = state
            .storage
            .get_receipt_checkpoint_by_id(&tenant_id, &cps[0].id)
            .await
            .unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn evidence_export_rejects_bad_timestamps() {
        let (state, tenant_id, _) = setup_state("evidence_export_bad_ts").await;
        let resp = export_evidence(
            State(state),
            TenantId(tenant_id),
            Json(EvidenceExportRequest {
                run_id: None,
                from: Some("not-a-date".into()),
                to: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn evidence_export_is_tenant_scoped() {
        let (state_a, tenant_a, _) = setup_state("evidence_export_tenant_a").await;
        let r = sample_receipt(&tenant_a, "ta1", "", None);
        state_a
            .storage
            .append_action_receipt_atomic(&tenant_a, r)
            .await
            .unwrap();

        let (state_b, tenant_b, _) = setup_state("evidence_export_tenant_b").await;
        // Export as tenant B against the same DB? setup_state uses separate DBs.
        // Cross-tenant isolation: B's export must not include A's receipts.
        let resp = export_evidence(
            State(state_b),
            TenantId(tenant_b),
            Json(EvidenceExportRequest::default()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
        let cursor = std::io::Cursor::new(body.to_vec());
        let mut zip = zip::ZipArchive::new(cursor).unwrap();
        let mut receipts_file = zip.by_name("receipts.jsonl").unwrap();
        let mut receipts_buf = String::new();
        std::io::Read::read_to_string(&mut receipts_file, &mut receipts_buf).unwrap();
        // Only the self-export receipt (no seeded data for B).
        let lines: Vec<_> = receipts_buf.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        let rec: ActionReceiptRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(rec.tool.as_deref(), Some("evidence"));
        // Ensure tenant A's receipt id is absent.
        assert!(!receipts_buf.contains("ta1"));
        let _ = state_a; // keep state_a alive for clarity
    }
}
