//! Credential references and resolution. Agents (and broker tool
//! registrations) carry only an opaque [`CredentialRef`] — a *name* for a
//! credential, never its value. The broker resolves the reference at
//! execution time through a [`CredentialResolver`], and the resolved
//! [`Secret`] refuses to leak through `Debug`, `Display`, or `Serialize`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize, Serializer};

use crate::redact::REDACTED;

/// An opaque pointer to a credential, e.g. `env:GITHUB_TOKEN` or
/// `vault:kv/data/ci/github`. Safe to store, log, and put in events —
/// it names a credential without containing it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn new(reference: impl Into<String>) -> Self {
        Self(reference.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The scheme prefix (`env` in `env:GITHUB_TOKEN`), if any.
    pub fn scheme(&self) -> Option<&str> {
        self.0.split_once(':').map(|(scheme, _)| scheme)
    }

    /// Everything after the scheme prefix.
    pub fn key(&self) -> Option<&str> {
        self.0.split_once(':').map(|(_, key)| key)
    }
}

impl std::fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A resolved credential value. The inner string is only reachable through
/// [`Secret::expose`] — an explicit, greppable act. Every implicit path
/// out (`Debug`, `Display`, `Serialize`) yields `[REDACTED]`.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Deliberately loud accessor: call sites that truly need the raw
    /// value (connector auth headers) are easy to audit.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl std::fmt::Display for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("unknown credential reference {reference:?}")]
    Unknown { reference: String },
    #[error("credential reference {reference:?} has unsupported scheme {scheme:?}")]
    UnsupportedScheme { reference: String, scheme: String },
}

/// Resolves a [`CredentialRef`] to its [`Secret`]. Implementations own the
/// actual storage (process env, vault, cloud secret manager); the broker
/// core never persists a resolved value.
pub trait CredentialResolver: Send + Sync {
    fn resolve(&self, reference: &CredentialRef) -> Result<Secret, ResolveError>;
}

/// Resolves `env:VAR_NAME` references from the process environment.
/// Fail-closed: a missing variable or a non-`env` scheme is an error, not
/// an empty secret.
#[derive(Debug, Default)]
pub struct EnvCredentialResolver;

impl CredentialResolver for EnvCredentialResolver {
    fn resolve(&self, reference: &CredentialRef) -> Result<Secret, ResolveError> {
        match reference.scheme() {
            Some("env") => {}
            other => {
                return Err(ResolveError::UnsupportedScheme {
                    reference: reference.as_str().to_string(),
                    scheme: other.unwrap_or("").to_string(),
                });
            }
        }
        let var = reference.key().unwrap_or_default();
        match std::env::var(var) {
            Ok(value) if !value.is_empty() => Ok(Secret::new(value)),
            _ => Err(ResolveError::Unknown {
                reference: reference.as_str().to_string(),
            }),
        }
    }
}

/// A fixed in-memory map — test/dev instrumentation.
#[derive(Default)]
pub struct StaticCredentialResolver {
    secrets: HashMap<CredentialRef, Secret>,
}

impl StaticCredentialResolver {
    pub fn with(mut self, reference: impl Into<String>, value: impl Into<String>) -> Self {
        self.secrets
            .insert(CredentialRef::new(reference), Secret::new(value));
        self
    }
}

impl CredentialResolver for StaticCredentialResolver {
    fn resolve(&self, reference: &CredentialRef) -> Result<Secret, ResolveError> {
        self.secrets
            .get(reference)
            .cloned()
            .ok_or_else(|| ResolveError::Unknown {
                reference: reference.as_str().to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_display_and_serialize_are_all_redacted() {
        let secret = Secret::new("ghp_supersecrettoken");
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
        let json = serde_json::to_string(&secret).expect("serialize secret");
        assert_eq!(json, format!("\"{REDACTED}\""));
        assert!(!json.contains("supersecret"));
        // The raw value is only reachable through the explicit accessor.
        assert_eq!(secret.expose(), "ghp_supersecrettoken");
    }

    #[test]
    fn credential_ref_is_safe_to_serialize_and_names_its_scheme() {
        let reference = CredentialRef::new("env:GITHUB_TOKEN");
        assert_eq!(reference.scheme(), Some("env"));
        assert_eq!(reference.key(), Some("GITHUB_TOKEN"));
        assert_eq!(
            serde_json::to_string(&reference).expect("serialize ref"),
            "\"env:GITHUB_TOKEN\""
        );
    }

    #[test]
    fn static_resolver_round_trips_and_fails_closed_on_unknown_refs() {
        let resolver = StaticCredentialResolver::default().with("env:TOKEN", "value-1");
        let secret = resolver
            .resolve(&CredentialRef::new("env:TOKEN"))
            .expect("known ref resolves");
        assert_eq!(secret.expose(), "value-1");
        assert!(resolver.resolve(&CredentialRef::new("env:OTHER")).is_err());
    }

    #[test]
    fn env_resolver_rejects_non_env_schemes() {
        let err = EnvCredentialResolver
            .resolve(&CredentialRef::new("vault:kv/github"))
            .expect_err("non-env scheme must fail");
        assert!(matches!(err, ResolveError::UnsupportedScheme { .. }));
    }

    #[test]
    fn env_resolver_treats_a_missing_variable_as_an_error_not_an_empty_secret() {
        let err = EnvCredentialResolver
            .resolve(&CredentialRef::new(
                "env:AEGIS_TEST_DEFINITELY_UNSET_VARIABLE",
            ))
            .expect_err("missing env var must fail closed");
        assert!(matches!(err, ResolveError::Unknown { .. }));
    }
}
