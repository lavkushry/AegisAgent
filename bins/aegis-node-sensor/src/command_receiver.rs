//! Phase 3.5 (Agent Cage / Control Command Protocol): verifies and executes
//! signed commands the gateway issues to this sensor.
//!
//! Canonicalization here covers the fields that actually exist on today's
//! gateway `ControlCommandRecord` (Phase 2.3/2.7) — `command_id`,
//! `tenant_id`, `target_type`, `target_id`, `action`, `reason`,
//! `issued_by`, `issued_at`, `expires_at`, `nonce`, `requires_ack`,
//! `receipt_required` — sorted-key compact JSON, matching the spirit of the
//! Control Command Protocol doc's `aegis-command-jcs-1` scheme. The doc's
//! richer schema (`payload`, `schema_version`, `signer_key_id`, key
//! rotation) lands when the gateway's command model grows to match it; this
//! verifies against the schema that exists today rather than one that
//! doesn't yet.
//!
//! Verification order matters: signature is checked before the nonce is
//! recorded as seen, so a forged command bearing a stolen nonce can't burn
//! the slot a legitimately signed command with that nonce would need.

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::json;

use crate::gateway_client::SignedCommand;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CommandError {
    #[error("no gateway public key is configured — cannot verify any command")]
    NoPublicKeyConfigured,
    #[error("command signature is invalid")]
    InvalidSignature,
    #[error("command is for tenant {command_tenant:?}, this sensor belongs to {sensor_tenant:?}")]
    WrongTenant {
        command_tenant: String,
        sensor_tenant: String,
    },
    #[error("command expired at {0}")]
    Expired(DateTime<Utc>),
    #[error("nonce {0:?} was already used — rejecting as a replay")]
    ReplayedNonce(String),
}

/// The canonical, sorted-key, compact-JSON byte representation of a
/// command's signable fields (everything except `signature` and `status`,
/// which aren't part of what's signed).
pub fn canonical_bytes(cmd: &SignedCommand) -> Vec<u8> {
    let mut map: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
    map.insert("command_id", json!(cmd.command_id));
    map.insert("tenant_id", json!(cmd.tenant_id));
    map.insert("target_type", json!(cmd.target_type));
    map.insert("target_id", json!(cmd.target_id));
    map.insert("action", json!(cmd.action));
    map.insert("reason", json!(cmd.reason));
    map.insert("issued_by", json!(cmd.issued_by));
    map.insert("issued_at", json!(cmd.issued_at.to_rfc3339()));
    map.insert("expires_at", json!(cmd.expires_at.to_rfc3339()));
    map.insert("nonce", json!(cmd.nonce));
    map.insert("requires_ack", json!(cmd.requires_ack));
    map.insert("receipt_required", json!(cmd.receipt_required));
    // BTreeMap's Serialize impl emits keys in sorted order; serde_json's
    // default writer uses compact (no extra whitespace) separators.
    serde_json::to_vec(&map).expect("a BTreeMap<&str, Value> always serializes")
}

pub enum ExecutionOutcome {
    Acked,
    Nacked(String),
}

pub struct CommandReceiver {
    verifying_key: Option<VerifyingKey>,
    tenant_id: String,
    seen_nonces: Mutex<HashSet<String>>,
}

impl CommandReceiver {
    /// `gateway_public_key_hex` is the sensor's pinned copy of the
    /// gateway's Ed25519 signing public key (from config, per the Control
    /// Command Protocol doc 3.2 — "config" is an explicitly allowed
    /// alternative to fetching it at registration). `None` means the
    /// sensor cannot verify anything and every command is rejected —
    /// failing closed rather than trusting an unverifiable command.
    pub fn new(gateway_public_key_hex: Option<&str>, tenant_id: String) -> Self {
        let verifying_key = gateway_public_key_hex.and_then(|hex_key| {
            let bytes = hex::decode(hex_key).ok()?;
            let arr: [u8; 32] = bytes.try_into().ok()?;
            VerifyingKey::from_bytes(&arr).ok()
        });
        Self {
            verifying_key,
            tenant_id,
            seen_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Verify a command's signature, tenant binding, freshness, and nonce
    /// uniqueness. Does not execute it — see [`execute`](Self::execute).
    pub fn verify(&self, cmd: &SignedCommand, now: DateTime<Utc>) -> Result<(), CommandError> {
        let verifying_key = self
            .verifying_key
            .ok_or(CommandError::NoPublicKeyConfigured)?;

        if cmd.tenant_id != self.tenant_id {
            return Err(CommandError::WrongTenant {
                command_tenant: cmd.tenant_id.clone(),
                sensor_tenant: self.tenant_id.clone(),
            });
        }
        if cmd.expires_at <= now {
            return Err(CommandError::Expired(cmd.expires_at));
        }

        let sig_bytes = hex::decode(&cmd.signature).map_err(|_| CommandError::InvalidSignature)?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| CommandError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&canonical_bytes(cmd), &signature)
            .map_err(|_| CommandError::InvalidSignature)?;

        // Nonce is recorded as seen only after the signature verifies, so a
        // forged command replaying a legitimate command's nonce can't burn
        // that nonce before the real one arrives.
        let mut seen = self.seen_nonces.lock().unwrap();
        if seen.contains(&cmd.nonce) {
            return Err(CommandError::ReplayedNonce(cmd.nonce.clone()));
        }
        seen.insert(cmd.nonce.clone());
        Ok(())
    }

    /// Execute a verified command. Only `kill_run` exists today — the mock
    /// handler this phase requires; the cage runner (Phase 4) provides real
    /// process control. Any other action NACKs as unsupported rather than
    /// silently no-op'ing.
    pub fn execute(&self, cmd: &SignedCommand) -> ExecutionOutcome {
        match cmd.action.as_str() {
            "kill_run" => ExecutionOutcome::Acked,
            other => ExecutionOutcome::Nacked(format!("unsupported action: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn base_command(now: DateTime<Utc>) -> SignedCommand {
        SignedCommand {
            command_id: "cmd-1".to_string(),
            tenant_id: "tenant_a".to_string(),
            target_type: "sensor".to_string(),
            target_id: "sensor-1".to_string(),
            action: "kill_run".to_string(),
            reason: Some("exfil detected".to_string()),
            issued_by: "user:admin@example.com".to_string(),
            issued_at: now,
            expires_at: now + Duration::minutes(5),
            nonce: "nonce-1".to_string(),
            requires_ack: true,
            receipt_required: true,
            signature: String::new(),
            status: "issued".to_string(),
        }
    }

    fn signed_command(now: DateTime<Utc>, signing_key: &SigningKey) -> SignedCommand {
        let mut cmd = base_command(now);
        let sig = signing_key.sign(&canonical_bytes(&cmd));
        cmd.signature = hex::encode(sig.to_bytes());
        cmd
    }

    fn receiver(signing_key: &SigningKey) -> CommandReceiver {
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        CommandReceiver::new(Some(&public_hex), "tenant_a".to_string())
    }

    #[test]
    fn valid_signed_command_verifies_and_executes() {
        let key = signing_key();
        let now = Utc::now();
        let cmd = signed_command(now, &key);
        let receiver = receiver(&key);

        receiver.verify(&cmd, now).unwrap();
        assert!(matches!(receiver.execute(&cmd), ExecutionOutcome::Acked));
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let key = signing_key();
        let wrong_key = SigningKey::from_bytes(&[9u8; 32]);
        let now = Utc::now();
        let mut cmd = base_command(now);
        // Signed by the WRONG key — the receiver is pinned to `key`'s public key.
        let sig = wrong_key.sign(&canonical_bytes(&cmd));
        cmd.signature = hex::encode(sig.to_bytes());

        let receiver = receiver(&key);
        assert_eq!(
            receiver.verify(&cmd, now).unwrap_err(),
            CommandError::InvalidSignature
        );
    }

    #[test]
    fn tampered_field_after_signing_is_rejected() {
        let key = signing_key();
        let now = Utc::now();
        let mut cmd = signed_command(now, &key);
        cmd.action = "kill_all".to_string(); // tampered after signing

        let receiver = receiver(&key);
        assert_eq!(
            receiver.verify(&cmd, now).unwrap_err(),
            CommandError::InvalidSignature
        );
    }

    #[test]
    fn expired_command_is_rejected() {
        let key = signing_key();
        let now = Utc::now();
        let mut cmd = base_command(now);
        cmd.expires_at = now - Duration::seconds(1);
        let sig = key.sign(&canonical_bytes(&cmd));
        cmd.signature = hex::encode(sig.to_bytes());

        let receiver = receiver(&key);
        assert!(matches!(
            receiver.verify(&cmd, now).unwrap_err(),
            CommandError::Expired(_)
        ));
    }

    #[test]
    fn replayed_nonce_is_rejected_on_second_verify() {
        let key = signing_key();
        let now = Utc::now();
        let cmd = signed_command(now, &key);
        let receiver = receiver(&key);

        receiver.verify(&cmd, now).unwrap();
        assert_eq!(
            receiver.verify(&cmd, now).unwrap_err(),
            CommandError::ReplayedNonce("nonce-1".to_string())
        );
    }

    #[test]
    fn wrong_tenant_command_is_rejected() {
        let key = signing_key();
        let now = Utc::now();
        let mut cmd = base_command(now);
        cmd.tenant_id = "tenant_other".to_string();
        let sig = key.sign(&canonical_bytes(&cmd));
        cmd.signature = hex::encode(sig.to_bytes());

        let receiver = receiver(&key);
        assert!(matches!(
            receiver.verify(&cmd, now).unwrap_err(),
            CommandError::WrongTenant { .. }
        ));
    }

    #[test]
    fn no_configured_public_key_rejects_everything_fail_closed() {
        let key = signing_key();
        let now = Utc::now();
        let cmd = signed_command(now, &key);
        let receiver = CommandReceiver::new(None, "tenant_a".to_string());

        assert_eq!(
            receiver.verify(&cmd, now).unwrap_err(),
            CommandError::NoPublicKeyConfigured
        );
    }

    #[test]
    fn unsupported_action_nacks_instead_of_executing() {
        let key = signing_key();
        let now = Utc::now();
        let mut cmd = base_command(now);
        cmd.action = "reformat_disk".to_string();
        let sig = key.sign(&canonical_bytes(&cmd));
        cmd.signature = hex::encode(sig.to_bytes());

        let receiver = receiver(&key);
        receiver.verify(&cmd, now).unwrap();
        match receiver.execute(&cmd) {
            ExecutionOutcome::Nacked(reason) => assert!(reason.contains("reformat_disk")),
            ExecutionOutcome::Acked => panic!("must not execute an unsupported action"),
        }
    }
}
