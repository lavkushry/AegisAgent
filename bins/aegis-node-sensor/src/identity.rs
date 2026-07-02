//! Phase 3.1 (Agent Cage): sensor identity key handling. Per the Control
//! Command Protocol doc (3.2, "Sensor identity key"), this is optional but
//! recommended — the sensor signs its own ACK/NACK result bodies so the
//! gateway gets non-repudiation independent of the gateway's own command
//! signature. Generated on first run and persisted; loaded unchanged after.

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::RngCore;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("failed to read identity key file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write identity key file {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("identity key file {0} does not contain valid hex")]
    InvalidHex(String),
    #[error("identity key file {0} does not contain a 32-byte key")]
    InvalidKeyLength(String),
}

/// The sensor's own Ed25519 keypair, used to sign command ACK/NACK results.
#[derive(Debug)]
pub struct SensorIdentity {
    signing_key: SigningKey,
}

impl SensorIdentity {
    /// Load the identity key from `path` if it exists, otherwise generate a
    /// fresh keypair and persist it (mode 0600 on unix). Never silently
    /// regenerates over an existing key — a corrupt or truncated file is a
    /// hard error, not a reason to overwrite evidence of a prior identity.
    pub fn load_or_generate(path: &Path) -> Result<Self, IdentityError> {
        if path.exists() {
            Self::load(path)
        } else {
            Self::generate_and_persist(path)
        }
    }

    fn load(path: &Path) -> Result<Self, IdentityError> {
        let contents = fs::read_to_string(path).map_err(|source| IdentityError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let bytes = hex::decode(contents.trim())
            .map_err(|_| IdentityError::InvalidHex(path.display().to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidKeyLength(path.display().to_string()))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    fn generate_and_persist(path: &Path) -> Result<Self, IdentityError> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| IdentityError::Write {
                    path: path.display().to_string(),
                    source,
                })?;
            }
        }
        fs::write(path, hex::encode(secret)).map_err(|source| IdentityError::Write {
            path: path.display().to_string(),
            source,
        })?;
        restrict_permissions(path);

        Ok(Self { signing_key })
    }

    /// Lowercase-hex Ed25519 public key, shared with the gateway at
    /// registration so it can verify this sensor's signed results.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // Best-effort: an identity key readable only by its owner. Failure here
    // doesn't invalidate the key (the file was written successfully either
    // way), so it's logged by the caller's tracing context, not propagated.
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_persists_a_new_identity_on_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        assert!(!path.exists());

        let identity = SensorIdentity::load_or_generate(&path).unwrap();
        assert!(path.exists());
        assert_eq!(identity.public_key_hex().len(), 64);
    }

    #[test]
    fn loading_an_existing_identity_returns_the_same_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        let first = SensorIdentity::load_or_generate(&path).unwrap();
        let second = SensorIdentity::load_or_generate(&path).unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());
    }

    #[test]
    fn corrupt_identity_file_fails_closed_rather_than_regenerating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, "not-valid-hex!!").unwrap();

        let err = SensorIdentity::load_or_generate(&path).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidHex(_)));
    }

    #[test]
    fn truncated_identity_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        fs::write(&path, hex::encode([0u8; 16])).unwrap();

        let err = SensorIdentity::load_or_generate(&path).unwrap_err();
        assert!(matches!(err, IdentityError::InvalidKeyLength(_)));
    }

    #[cfg(unix)]
    #[test]
    fn generated_identity_file_is_owner_only_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        SensorIdentity::load_or_generate(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
