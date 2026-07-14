use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub use crate::receipt_signer::{
    global_signer, init_global_signer, init_global_signer_from_env_key, verify_signature,
    LocalReceiptSigner, ReceiptSignBackend,
};

/// Backward-compatible alias for [`LocalReceiptSigner`].
pub type ReceiptSigner = LocalReceiptSigner;

/// Build an `X-Aegis-Request-Signature: sha256=<hex>` value for the raw body
/// (#1403). Returns `None` when the signing key cannot initialize HMAC-SHA256.
pub fn request_signature_header(signing_key: &str, body: &[u8]) -> Option<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes()).ok()?;
    mac.update(body);
    Some(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_signature_round_trip() {
        let key = "unit-test-key";
        let body = b"authorize-body";
        let header = request_signature_header(key, body).expect("sign");
        assert!(header.starts_with("sha256="));
        assert!(verify_request_signature(key, body, &header));
        assert!(!verify_request_signature(key, b"tampered", &header));
        assert!(!verify_request_signature("other-key", body, &header));
        assert!(!verify_request_signature(key, body, "sha256=00"));
        assert!(!verify_request_signature(key, body, "not-a-sig"));
    }
}
