//! Optional Ed25519 signing of action receipts — third-party-verifiable evidence.
//!
//! The signature is computed **over the final `receipt_hash` string** (its UTF-8
//! bytes) and stored ALONGSIDE the receipt as additive metadata. It is NEVER an
//! input to `compute_receipt_hash` and NEVER part of the canonicalized receipt
//! body, so the byte-parity-locked `aegis-jcs-1` hash chain is untouched
//! (`tests/receipt_chain_vectors.json` stays green). A third party who holds the
//! signer's public key can verify a receipt independently of this gateway:
//!
//! ```text
//! verify_signature(signer_public_key, receipt_hash, signature) == true
//! ```
//!
//! Signing is OPTIONAL and the hermetic default is **unsigned**: with no key
//! configured, `global_signer()` returns `None`, receipts carry NULL signature
//! fields, and everything still works. We sign hashes, never payloads (redaction).

use std::sync::OnceLock;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use tracing::warn;

/// Holds an Ed25519 signing key derived from a 32-byte secret. Constructed from a
/// hex-encoded secret (provisioned out-of-band — never logged, never hashed).
pub struct ReceiptSigner {
    signing_key: SigningKey,
}

impl ReceiptSigner {
    /// Parse a 32-byte Ed25519 secret key from a hex string. Returns `Err` on any
    /// malformed input (bad hex, wrong length) — never panics.
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(secret_hex.trim())
            .map_err(|e| format!("secret key is not valid hex: {e}"))?;
        let arr: [u8; SECRET_KEY_LENGTH] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("secret key must be {SECRET_KEY_LENGTH} bytes"))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    /// Sign the UTF-8 bytes of a `receipt_hash` string; return a lowercase-hex
    /// Ed25519 signature (64 bytes → 128 hex chars).
    pub fn sign_hash(&self, receipt_hash: &str) -> String {
        let signature: Signature = self.signing_key.sign(receipt_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    /// Lowercase-hex of the verifying (public) key, persisted with each signed
    /// receipt so a third party can verify without contacting the gateway.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

/// Verify an Ed25519 signature over a `receipt_hash`. Returns `false` on ANY
/// parse or verification error (bad hex, wrong length, signature mismatch, wrong
/// key) — never panics. This is the function a third-party auditor runs.
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

/// Process-wide receipt signer, initialized once from the `AEGIS_RECEIPT_SIGNING_KEY`
/// environment variable (hex-encoded 32-byte Ed25519 secret). Returns `None` when
/// the variable is unset or invalid (a warning is logged on invalid) — the
/// hermetic default is unsigned. Idempotent and thread-safe via `OnceLock`.
pub fn global_signer() -> Option<&'static ReceiptSigner> {
    GLOBAL_SIGNER
        .get_or_init(|| match std::env::var("AEGIS_RECEIPT_SIGNING_KEY") {
            Ok(hex_key) if !hex_key.trim().is_empty() => {
                match ReceiptSigner::from_secret_hex(&hex_key) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed 32-byte test secret in hex (bytes 0x01..0x20). Deterministic so the
    // round-trip is stable. Test-only material — not a real key.
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
        assert!(
            verify_signature(&pk, hash, &sig),
            "valid signature must verify"
        );
    }

    #[test]
    fn tampered_hash_fails() {
        let signer = test_signer();
        let hash = "a84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        let sig = signer.sign_hash(hash);
        let pk = signer.public_key_hex();
        let tampered = "b84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        assert!(
            !verify_signature(&pk, tampered, &sig),
            "a tampered hash must not verify"
        );
    }

    #[test]
    fn wrong_public_key_fails() {
        let signer = test_signer();
        let hash = "a84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        let sig = signer.sign_hash(hash);
        // A different key.
        let other = ReceiptSigner::from_secret_hex(
            "2020202020202020202020202020202020202020202020202020202020202020",
        )
        .unwrap();
        assert!(
            !verify_signature(&other.public_key_hex(), hash, &sig),
            "a wrong public key must not verify"
        );
    }

    #[test]
    fn malformed_inputs_never_panic_and_return_false() {
        let signer = test_signer();
        let hash = "a84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        let sig = signer.sign_hash(hash);
        let pk = signer.public_key_hex();

        assert!(!verify_signature("not-hex", hash, &sig));
        assert!(!verify_signature(&pk, hash, "not-hex"));
        assert!(!verify_signature("aabb", hash, &sig)); // too short pubkey
        assert!(!verify_signature(&pk, hash, "aabb")); // too short sig
        assert!(!verify_signature("", hash, &sig));
        assert!(!verify_signature(&pk, hash, ""));
    }

    #[test]
    fn from_secret_hex_rejects_bad_input() {
        assert!(ReceiptSigner::from_secret_hex("zzzz").is_err()); // bad hex
        assert!(ReceiptSigner::from_secret_hex("aabb").is_err()); // wrong length
                                                                  // The fixed test secret IS valid 32-byte hex.
        assert!(ReceiptSigner::from_secret_hex(TEST_SECRET_HEX).is_ok());
    }
}
