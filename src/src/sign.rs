//! Optional Ed25519 signing of action receipts — third-party-verifiable evidence.
//!
//! Receipt signing backends live in `aegis_common::receipt_signer` (#1311 adds
//! KMS-backed signing via `kms_receipt_signer`). This module retains
//! [`CommandSigner`] for cage-run control commands and re-exports receipt helpers.

pub use aegis_common::receipt_signer::{
    global_signer, init_global_signer, init_global_signer_from_env_key, verify_signature,
    LocalReceiptSigner, ReceiptSignBackend,
};

/// Backward-compatible alias used throughout gateway tests and policy bundles.
pub type ReceiptSigner = LocalReceiptSigner;

use ed25519_dalek::{Signature, Signer, SigningKey, SECRET_KEY_LENGTH};

/// Phase 4.3 (Agent Cage): Ed25519 signing of gateway-initiated control commands.
pub struct CommandSigner {
    signing_key: SigningKey,
    key_id: Option<String>,
}

impl CommandSigner {
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(secret_hex.trim())
            .map_err(|e| format!("secret key is not valid hex: {e}"))?;
        let arr: [u8; SECRET_KEY_LENGTH] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("secret key must be {SECRET_KEY_LENGTH} bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
            key_id: None,
        })
    }

    pub fn from_env_value(value: &str) -> Result<Self, String> {
        match value.trim().split_once(':') {
            Some((key_id, hex_secret)) if !key_id.is_empty() => {
                let mut signer = Self::from_secret_hex(hex_secret)?;
                signer.key_id = Some(key_id.to_string());
                Ok(signer)
            }
            _ => Self::from_secret_hex(value),
        }
    }

    pub fn sign(&self, canonical_bytes: &[u8]) -> String {
        let signature: Signature = self.signing_key.sign(canonical_bytes);
        hex::encode(signature.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

/// Canonical byte representation of a control command's signable fields.
pub fn canonical_command_bytes(record: &crate::models::ControlCommandRecord) -> Vec<u8> {
    use std::collections::BTreeMap;

    let mut map: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
    map.insert("command_id", serde_json::json!(record.command_id));
    map.insert("tenant_id", serde_json::json!(record.tenant_id));
    map.insert("target_type", serde_json::json!(record.target_type));
    map.insert("target_id", serde_json::json!(record.target_id));
    map.insert("action", serde_json::json!(record.action));
    map.insert("reason", serde_json::json!(record.reason));
    map.insert("issued_by", serde_json::json!(record.issued_by));
    map.insert(
        "issued_at",
        serde_json::json!(record.issued_at.to_rfc3339()),
    );
    map.insert(
        "expires_at",
        serde_json::json!(record.expires_at.to_rfc3339()),
    );
    map.insert("nonce", serde_json::json!(record.nonce));
    map.insert("requires_ack", serde_json::json!(record.requires_ack));
    map.insert(
        "receipt_required",
        serde_json::json!(record.receipt_required),
    );
    serde_json::to_vec(&map).expect("a BTreeMap<&str, Value> always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn test_signer() -> ReceiptSigner {
        ReceiptSigner::from_secret_hex(TEST_SECRET_HEX).expect("valid test secret")
    }

    #[test]
    fn sign_verify_round_trip() {
        let signer = test_signer();
        let hash = "a84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        let sig = signer.sign_hash(hash);
        let pk = signer.public_key_hex();
        assert!(verify_signature(&pk, hash, &sig));
    }

    #[test]
    fn command_signer_sign_verify_round_trip() {
        let signer = CommandSigner::from_secret_hex(TEST_SECRET_HEX).unwrap();
        let record = sample_command_record();
        let bytes = canonical_command_bytes(&record);
        let sig_hex = signer.sign(&bytes);

        let sig_bytes = hex::decode(&sig_hex).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
        let signature = Signature::from_bytes(&sig_arr);
        let pk_bytes = hex::decode(signer.public_key_hex()).unwrap();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
        use ed25519_dalek::VerifyingKey;
        let verifying_key = VerifyingKey::from_bytes(&pk_arr).unwrap();
        assert!(verifying_key.verify_strict(&bytes, &signature).is_ok());
    }

    fn sample_command_record() -> crate::models::ControlCommandRecord {
        let issued_at = "2026-01-01T00:00:00Z".parse().unwrap();
        let expires_at = "2026-01-01T00:05:00Z".parse().unwrap();
        crate::models::ControlCommandRecord {
            command_id: "cmd-1".to_string(),
            tenant_id: "tenant_a".to_string(),
            target_type: "run".to_string(),
            target_id: "run-1".to_string(),
            action: "kill_run".to_string(),
            reason: Some("exfil detected".to_string()),
            issued_by: "user:admin@example.com".to_string(),
            issued_at,
            expires_at,
            nonce: "nonce-1".to_string(),
            requires_ack: true,
            receipt_required: true,
            signature: String::new(),
            status: "issued".to_string(),
            created_at: issued_at,
        }
    }
}
