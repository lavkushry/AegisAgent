//! Pluggable receipt signing backends (#1311).
//!
//! Signatures are computed over the UTF-8 bytes of `receipt_hash` and stored as
//! additive metadata — never an input to `compute_receipt_hash`. The hermetic
//! default is unsigned (`global_signer() == None`).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use std::sync::{Arc, OnceLock};
use tracing::warn;

/// Signs `receipt_hash` strings for optional third-party receipt verification.
pub trait ReceiptSignBackend: Send + Sync {
    fn sign_hash(&self, receipt_hash: &str) -> String;
    fn public_key_hex(&self) -> String;
    fn key_id(&self) -> Option<&str>;
}

/// Local Ed25519 signer from a hex-encoded 32-byte secret (file/env based).
pub struct LocalReceiptSigner {
    signing_key: SigningKey,
    key_id: Option<String>,
}

impl LocalReceiptSigner {
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

    /// Build a local signer with an explicit KMS-style key identifier.
    pub fn from_secret_hex_with_key_id(secret_hex: &str, key_id: &str) -> Result<Self, String> {
        let mut signer = Self::from_secret_hex(secret_hex)?;
        signer.key_id = Some(key_id.to_string());
        Ok(signer)
    }

    /// Parse `AEGIS_RECEIPT_SIGNING_KEY` (`key_id:hex_secret` or plain hex).
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

    /// Inherent wrappers so callers need not import [`ReceiptSignBackend`].
    pub fn sign_hash(&self, receipt_hash: &str) -> String {
        ReceiptSignBackend::sign_hash(self, receipt_hash)
    }

    pub fn public_key_hex(&self) -> String {
        ReceiptSignBackend::public_key_hex(self)
    }

    pub fn key_id(&self) -> Option<&str> {
        ReceiptSignBackend::key_id(self)
    }
}

impl ReceiptSignBackend for LocalReceiptSigner {
    fn sign_hash(&self, receipt_hash: &str) -> String {
        let signature: Signature = self.signing_key.sign(receipt_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

/// Verify an Ed25519 signature over a `receipt_hash`. Returns `false` on any error.
pub fn verify_signature(public_key_hex: &str, receipt_hash: &str, signature_hex: &str) -> bool {
    let pk_bytes = match hex::decode(public_key_hex.trim()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let sig_bytes = match hex::decode(signature_hex.trim()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify_strict(receipt_hash.as_bytes(), &signature)
        .is_ok()
}

static GLOBAL_SIGNER: OnceLock<Option<Arc<dyn ReceiptSignBackend>>> = OnceLock::new();

/// Install the process-wide receipt signer (called once at gateway startup).
pub fn init_global_signer(signer: Option<Arc<dyn ReceiptSignBackend>>) {
    let _ = GLOBAL_SIGNER.set(signer);
}

fn build_local_signer_from_env() -> Option<Arc<dyn ReceiptSignBackend>> {
    match std::env::var("AEGIS_RECEIPT_SIGNING_KEY") {
        Ok(hex_key) if !hex_key.trim().is_empty() => {
            match LocalReceiptSigner::from_env_value(&hex_key) {
                Ok(s) => Some(Arc::new(s) as Arc<dyn ReceiptSignBackend>),
                Err(e) => {
                    warn!(
                        "AEGIS_RECEIPT_SIGNING_KEY is set but invalid ({e}); \
                         receipts will be emitted UNSIGNED"
                    );
                    None
                }
            }
        }
        _ => None,
    }
}

/// Fallback init from `AEGIS_RECEIPT_SIGNING_KEY` when no KMS signer was installed.
pub fn init_global_signer_from_env_key() {
    if GLOBAL_SIGNER.get().is_some() {
        return;
    }
    let _ = GLOBAL_SIGNER.set(build_local_signer_from_env());
}

/// Process-wide receipt signer. `None` when unset or invalid — unsigned default.
/// Lazy-inits from `AEGIS_RECEIPT_SIGNING_KEY` when the gateway has not called
/// [`init_global_signer`] (storage unit tests).
pub fn global_signer() -> Option<Arc<dyn ReceiptSignBackend>> {
    if GLOBAL_SIGNER.get().is_none() {
        init_global_signer_from_env_key();
    }
    GLOBAL_SIGNER.get().cloned().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn local_sign_verify_round_trip() {
        let signer = LocalReceiptSigner::from_secret_hex(TEST_SECRET_HEX).unwrap();
        let hash = "a84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        let sig = signer.sign_hash(hash);
        assert!(verify_signature(&signer.public_key_hex(), hash, &sig));
    }
}
