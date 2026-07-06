//! KMS-backed receipt signing (#1311).
//!
//! When `AEGIS_KMS_KEY_URI` is set, receipt signatures are produced by a cloud
//! KMS asymmetric Ed25519 key instead of a local hex secret. Supported schemes:
//!
//! - `kms-mock://<key_id>/<hex_secret>` — local dev/test (signs in-process)
//! - `aws-kms://<key-arn>` — AWS KMS (requires `kms-aws` feature + IAM creds)
//! - `gcp-kms://<cryptoKeyVersion resource>` — GCP Cloud KMS (service account)
//!
//! Falls back to `AEGIS_RECEIPT_SIGNING_KEY` when `AEGIS_KMS_KEY_URI` is unset.

use aegis_common::receipt_signer::{init_global_signer, LocalReceiptSigner, ReceiptSignBackend};
use std::sync::Arc;
use tracing::{info, warn};

/// Initialize the process-wide receipt signer from `AEGIS_KMS_KEY_URI` (preferred)
/// or `AEGIS_RECEIPT_SIGNING_KEY` (fallback). Idempotent — only the first call
/// installs the signer.
pub fn init_receipt_signer_from_env() {
    if let Ok(uri) = std::env::var("AEGIS_KMS_KEY_URI") {
        let trimmed = uri.trim();
        if !trimmed.is_empty() {
            match build_kms_signer(trimmed) {
                Ok(signer) => {
                    info!(
                        key_id = signer.key_id().unwrap_or(""),
                        "KMS receipt signing enabled via AEGIS_KMS_KEY_URI"
                    );
                    init_global_signer(Some(signer));
                    return;
                }
                Err(e) => {
                    warn!(
                        "AEGIS_KMS_KEY_URI is set but invalid ({e}); \
                         falling back to AEGIS_RECEIPT_SIGNING_KEY if set"
                    );
                }
            }
        }
    }
    aegis_common::receipt_signer::init_global_signer_from_env_key();
}

fn build_kms_signer(uri_str: &str) -> Result<Arc<dyn ReceiptSignBackend>, String> {
    if let Some(rest) = uri_str.strip_prefix("kms-mock://") {
        return build_mock_signer(rest);
    }
    if let Some(arn) = uri_str.strip_prefix("aws-kms:") {
        return build_aws_signer(arn.trim());
    }
    if let Some(resource) = uri_str.strip_prefix("gcp-kms:") {
        return build_gcp_signer(resource.trim());
    }
    Err("unsupported KMS URI scheme (expected kms-mock://, aws-kms:, or gcp-kms:)".to_string())
}

/// `kms-mock://<key_id>/<hex_secret>` exercises the KMS code path in tests without
/// cloud credentials. NOT for production.
fn build_mock_signer(rest: &str) -> Result<Arc<dyn ReceiptSignBackend>, String> {
    let (key_id, hex_secret) = rest
        .split_once('/')
        .ok_or_else(|| "kms-mock URI requires <key_id>/<hex_secret>".to_string())?;
    if key_id.is_empty() || hex_secret.is_empty() {
        return Err("kms-mock URI requires non-empty key_id and hex_secret".into());
    }
    let local = LocalReceiptSigner::from_secret_hex_with_key_id(hex_secret, key_id)?;
    Ok(Arc::new(local))
}

fn build_aws_signer(key_arn: &str) -> Result<Arc<dyn ReceiptSignBackend>, String> {
    if key_arn.is_empty() {
        return Err("aws-kms URI requires key ARN after aws-kms:".into());
    }
    #[cfg(feature = "kms-aws")]
    {
        return AwsKmsReceiptSigner::new(key_arn)
            .map(|s| Arc::new(s) as Arc<dyn ReceiptSignBackend>);
    }
    #[cfg(not(feature = "kms-aws"))]
    {
        let _ = key_arn;
        Err("aws-kms signing requires building gateway with --features kms-aws".to_string())
    }
}

fn build_gcp_signer(resource: &str) -> Result<Arc<dyn ReceiptSignBackend>, String> {
    if resource.is_empty() {
        return Err("gcp-kms URI requires cryptoKeyVersion resource after gcp-kms:".into());
    }
    GcpKmsReceiptSigner::new(resource).map(|s| Arc::new(s) as Arc<dyn ReceiptSignBackend>)
}

// ── AWS KMS ──────────────────────────────────────────────────────────────────

#[cfg(feature = "kms-aws")]
struct AwsKmsReceiptSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
    public_key_hex: String,
    rt: tokio::runtime::Runtime,
}

#[cfg(feature = "kms-aws")]
impl AwsKmsReceiptSigner {
    fn new(key_arn: &str) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let (client, public_key_hex) = rt.block_on(async {
            let config = aws_config::load_from_env().await;
            let client = aws_sdk_kms::Client::new(&config);
            let pk = client
                .get_public_key()
                .key_id(key_arn)
                .send()
                .await
                .map_err(|e| format!("AWS GetPublicKey failed: {e}"))?;
            let blob = pk
                .public_key()
                .ok_or_else(|| "AWS GetPublicKey returned empty key".to_string())?;
            let raw = ed25519_public_key_from_spki(blob.as_ref())?;
            Ok::<_, String>((client, hex::encode(raw)))
        })?;
        Ok(Self {
            client,
            key_id: key_arn.to_string(),
            public_key_hex,
            rt,
        })
    }
}

#[cfg(feature = "kms-aws")]
impl ReceiptSignBackend for AwsKmsReceiptSigner {
    fn sign_hash(&self, receipt_hash: &str) -> String {
        self.rt
            .block_on(async {
                let out = self
                    .client
                    .sign()
                    .key_id(&self.key_id)
                    .message(receipt_hash.as_bytes().into())
                    .message_type(aws_sdk_kms::types::MessageType::Raw)
                    .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::Ed25519)
                    .send()
                    .await
                    .map_err(|e| format!("AWS Sign failed: {e}"))?;
                let sig = out
                    .signature()
                    .ok_or_else(|| "AWS Sign returned empty signature".to_string())?;
                Ok::<_, String>(hex::encode(sig.as_ref()))
            })
            .unwrap_or_else(|e| {
                warn!("KMS sign failed: {e}");
                String::new()
            })
    }

    fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.key_id)
    }
}

// ── GCP Cloud KMS (REST) ─────────────────────────────────────────────────────

struct GcpKmsReceiptSigner {
    http: reqwest::blocking::Client,
    resource: String,
    key_id: String,
    public_key_hex: String,
    access_token: String,
}

impl GcpKmsReceiptSigner {
    fn new(resource: &str) -> Result<Self, String> {
        let token = gcp_access_token()?;
        let http = reqwest::blocking::Client::new();
        let pk_url = format!(
            "https://cloudkms.googleapis.com/v1/{}:getPublicKey",
            resource
        );
        let resp: serde_json::Value = http
            .get(&pk_url)
            .bearer_auth(&token)
            .send()
            .map_err(|e| format!("GCP GetPublicKey request failed: {e}"))?
            .error_for_status()
            .map_err(|e| format!("GCP GetPublicKey HTTP error: {e}"))?
            .json()
            .map_err(|e| format!("GCP GetPublicKey JSON error: {e}"))?;
        let pem = resp["pem"]
            .as_str()
            .ok_or_else(|| "GCP GetPublicKey missing pem field".to_string())?;
        let raw = ed25519_public_key_from_pem(pem)?;
        let key_id = resource.rsplit('/').next().unwrap_or(resource).to_string();
        Ok(Self {
            http,
            resource: resource.to_string(),
            key_id,
            public_key_hex: hex::encode(raw),
            access_token: token,
        })
    }
}

impl ReceiptSignBackend for GcpKmsReceiptSigner {
    fn sign_hash(&self, receipt_hash: &str) -> String {
        let url = format!(
            "https://cloudkms.googleapis.com/v1/{}:asymmetricSign",
            self.resource
        );
        use base64::Engine;
        let body = serde_json::json!({
            "data": base64::engine::general_purpose::STANDARD.encode(receipt_hash.as_bytes()),
        });
        match self
            .http
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
        {
            Ok(resp) => match resp.error_for_status() {
                Ok(ok) => match ok.json::<serde_json::Value>() {
                    Ok(json) => {
                        let b64 = match json["signature"].as_str() {
                            Some(s) => s,
                            None => {
                                warn!("GCP asymmetricSign missing signature field");
                                return String::new();
                            }
                        };
                        use base64::Engine;
                        match base64::engine::general_purpose::STANDARD.decode(b64) {
                            Ok(sig) => hex::encode(sig),
                            Err(e) => {
                                warn!("GCP signature base64 decode failed: {e}");
                                String::new()
                            }
                        }
                    }
                    Err(e) => {
                        warn!("GCP asymmetricSign JSON error: {e}");
                        String::new()
                    }
                },
                Err(e) => {
                    warn!("GCP asymmetricSign HTTP error: {e}");
                    String::new()
                }
            },
            Err(e) => {
                warn!("GCP asymmetricSign request failed: {e}");
                String::new()
            }
        }
    }

    fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    fn key_id(&self) -> Option<&str> {
        Some(&self.key_id)
    }
}

fn gcp_access_token() -> Result<String, String> {
    let creds_path = std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
        .map_err(|_| "GOOGLE_APPLICATION_CREDENTIALS must be set for gcp-kms".to_string())?;
    let creds_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&creds_path).map_err(|e| format!("read GCP credentials: {e}"))?,
    )
    .map_err(|e| format!("parse GCP credentials: {e}"))?;
    let client_email = creds_json["client_email"]
        .as_str()
        .ok_or_else(|| "GCP credentials missing client_email".to_string())?;
    let private_key = creds_json["private_key"]
        .as_str()
        .ok_or_else(|| "GCP credentials missing private_key".to_string())?;
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": client_email,
        "scope": "https://www.googleapis.com/auth/cloudkms",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    });
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key.as_bytes())
        .map_err(|e| format!("GCP private key parse: {e}"))?;
    let jwt =
        jsonwebtoken::encode(&header, &claims, &key).map_err(|e| format!("GCP JWT encode: {e}"))?;
    let http = reqwest::blocking::Client::new();
    let resp: serde_json::Value = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()
        .map_err(|e| format!("GCP token request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GCP token HTTP error: {e}"))?
        .json()
        .map_err(|e| format!("GCP token JSON error: {e}"))?;
    resp["access_token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "GCP token response missing access_token".to_string())
}

/// Extract raw 32-byte Ed25519 public key from a PKIX DER blob (AWS/GCP SPKI).
fn ed25519_public_key_from_spki(der: &[u8]) -> Result<[u8; 32], String> {
    if der.len() < 32 {
        return Err("SPKI DER too short for Ed25519".into());
    }
    let raw: [u8; 32] = der[der.len() - 32..]
        .try_into()
        .map_err(|_| "SPKI tail not 32 bytes".to_string())?;
    Ok(raw)
}

fn ed25519_public_key_from_pem(pem: &str) -> Result<[u8; 32], String> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("PEM base64 decode: {e}"))?;
    ed25519_public_key_from_spki(&der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_common::receipt_signer::verify_signature;

    const TEST_SECRET_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn kms_mock_signer_round_trip() {
        let uri = format!("kms-mock://enterprise-key/{TEST_SECRET_HEX}");
        let signer = build_kms_signer(&uri).expect("mock kms signer");
        let hash = "a84bcc5881e29fe1da822f50fe7458e7e942f2dd3c6df2b9ce1ca85d716dc603";
        let sig = signer.sign_hash(hash);
        assert_eq!(signer.key_id(), Some("enterprise-key"));
        assert!(verify_signature(&signer.public_key_hex(), hash, &sig));
    }

    #[test]
    fn aws_kms_without_feature_returns_error() {
        let result = build_kms_signer("aws-kms:arn:aws:kms:us-east-1:123456789012:key/abc");
        assert!(result.is_err());
        let err = result.err().expect("expected Err");
        assert!(err.contains("kms-aws"));
    }
}
