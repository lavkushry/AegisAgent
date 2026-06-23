use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use tracing::warn;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub struct ReceiptSigner {
    signing_key: SigningKey,
    key_id: Option<String>,
}

impl ReceiptSigner {
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

    pub fn sign_hash(&self, receipt_hash: &str) -> String {
        let signature: Signature = self.signing_key.sign(receipt_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

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

static GLOBAL_SIGNER: OnceLock<Option<ReceiptSigner>> = OnceLock::new();

pub fn global_signer() -> Option<&'static ReceiptSigner> {
    GLOBAL_SIGNER
        .get_or_init(|| match std::env::var("AEGIS_RECEIPT_SIGNING_KEY") {
            Ok(hex_key) if !hex_key.trim().is_empty() => {
                match ReceiptSigner::from_env_value(&hex_key) {
                    Ok(signer) => Some(signer),
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
        })
        .as_ref()
}

/// Verify an `X-Aegis-Request-Signature: sha256=<hex>` header against the raw
/// request body (#1403). Uses `Mac::verify_slice` for constant-time comparison.
/// Returns `true` only when the signature is present, well-formed, and correct.
pub fn verify_request_signature(signing_key: &str, body: &[u8], sig_header: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let Some(hex_digest) = sig_header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_digest) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}
