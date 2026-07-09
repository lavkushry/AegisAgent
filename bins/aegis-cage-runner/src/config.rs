//! aegis-cage-runner configuration. Loaded from an optional TOML file,
//! overridden by CLI flags, then validated. Invalid configuration fails
//! closed — the runner refuses to start rather than run with guessed
//! values. Mirrors `aegis-node-sensor`'s `config.rs` shape, with one
//! deliberate divergence: `gateway_public_key_hex` is hard-required here
//! (not optional) -- a runner that can't verify signed commands can never
//! legitimately execute anything, so it should refuse to start at all
//! rather than start and only ever nack.

use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

const DEFAULT_WORKSPACE_ROOT: &str = "aegis-cage-workspaces";
const DEFAULT_CLAIM_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_CONTROL_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// Raw, unvalidated configuration as deserialized from the TOML config
/// file. Every field is optional here — CLI flags and defaults fill the
/// gaps, and [`RunnerConfig::resolve`] is the single place validation
/// happens.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRunnerConfig {
    pub gateway_url: Option<String>,
    pub tenant_id: Option<String>,
    /// Bearer credential presented as `Authorization: Bearer <api_token>` on
    /// every gateway call — the runner authenticates like any other API
    /// client (matches `aegis-node-sensor`/`aegis-egress-proxy`), reusing
    /// the tenant-wide bearer-token pattern rather than a new per-run
    /// scoped credential.
    pub api_token: Option<String>,
    /// Opaque id used for `claimed_by` bookkeeping only -- not a security
    /// boundary (the tenant bearer token already is one). Defaults to the
    /// local hostname if unset.
    pub runner_id: Option<String>,
    /// Hex-encoded Ed25519 public key the runner pins for verifying signed
    /// control commands. Hard-required (see module doc comment).
    pub gateway_public_key_hex: Option<String>,
    pub workspace_root: Option<PathBuf>,
    pub claim_poll_interval_secs: Option<u64>,
    pub control_poll_interval_secs: Option<u64>,
    pub heartbeat_interval_secs: Option<u64>,
}

/// CLI-supplied overrides, applied on top of the config file before
/// defaults.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub gateway_url: Option<String>,
    pub tenant_id: Option<String>,
    pub api_token: Option<String>,
    pub runner_id: Option<String>,
    pub gateway_public_key_hex: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("gateway_url is required (set it in the config file or pass --gateway-url)")]
    MissingGatewayUrl,
    #[error("gateway_url {0:?} is not a valid http(s) URL: {1}")]
    InvalidGatewayUrl(String, String),
    #[error("gateway_url must use http or https, got scheme {0:?}")]
    UnsupportedGatewayUrlScheme(String),
    #[error("tenant_id is required (set it in the config file or pass --tenant-id)")]
    MissingTenantId,
    #[error("tenant_id must not be empty or whitespace-only")]
    EmptyTenantId,
    #[error("api_token is required (set it in the config file or pass --api-token)")]
    MissingApiToken,
    #[error("api_token must not be empty or whitespace-only")]
    EmptyApiToken,
    #[error(
        "gateway_public_key_hex is required (set it in the config file or pass \
         --gateway-public-key-hex) -- a runner that cannot verify signed commands \
         can never legitimately execute anything"
    )]
    MissingGatewayPublicKey,
    #[error("gateway_public_key_hex must not be empty or whitespace-only")]
    EmptyGatewayPublicKey,
    #[error("claim_poll_interval_secs must be greater than zero")]
    ZeroClaimPollInterval,
    #[error("control_poll_interval_secs must be greater than zero")]
    ZeroControlPollInterval,
    #[error("heartbeat_interval_secs must be greater than zero")]
    ZeroHeartbeatInterval,
}

/// Validated runner configuration — every field here is known-good.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    pub gateway_url: Url,
    pub tenant_id: String,
    pub api_token: String,
    pub runner_id: String,
    pub gateway_public_key_hex: String,
    pub workspace_root: PathBuf,
    pub claim_poll_interval_secs: u64,
    pub control_poll_interval_secs: u64,
    pub heartbeat_interval_secs: u64,
}

impl RunnerConfig {
    /// Merge file config + CLI overrides (CLI wins), fill defaults, and
    /// validate. Fails closed: any invalid or missing required field is an
    /// error, never a silently-guessed value.
    pub fn resolve(raw: RawRunnerConfig, overrides: CliOverrides) -> Result<Self, ConfigError> {
        let gateway_url_raw = overrides
            .gateway_url
            .or(raw.gateway_url)
            .ok_or(ConfigError::MissingGatewayUrl)?;
        let gateway_url = Url::parse(&gateway_url_raw)
            .map_err(|e| ConfigError::InvalidGatewayUrl(gateway_url_raw.clone(), e.to_string()))?;
        if gateway_url.scheme() != "http" && gateway_url.scheme() != "https" {
            return Err(ConfigError::UnsupportedGatewayUrlScheme(
                gateway_url.scheme().to_string(),
            ));
        }

        let tenant_id = overrides
            .tenant_id
            .or(raw.tenant_id)
            .ok_or(ConfigError::MissingTenantId)?;
        if tenant_id.trim().is_empty() {
            return Err(ConfigError::EmptyTenantId);
        }

        let api_token = overrides
            .api_token
            .or(raw.api_token)
            .ok_or(ConfigError::MissingApiToken)?;
        if api_token.trim().is_empty() {
            return Err(ConfigError::EmptyApiToken);
        }

        let gateway_public_key_hex = overrides
            .gateway_public_key_hex
            .or(raw.gateway_public_key_hex)
            .ok_or(ConfigError::MissingGatewayPublicKey)?;
        if gateway_public_key_hex.trim().is_empty() {
            return Err(ConfigError::EmptyGatewayPublicKey);
        }

        let runner_id = overrides.runner_id.or(raw.runner_id).unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "unknown-runner".to_string())
        });

        let claim_poll_interval_secs = raw
            .claim_poll_interval_secs
            .unwrap_or(DEFAULT_CLAIM_POLL_INTERVAL_SECS);
        if claim_poll_interval_secs == 0 {
            return Err(ConfigError::ZeroClaimPollInterval);
        }

        let control_poll_interval_secs = raw
            .control_poll_interval_secs
            .unwrap_or(DEFAULT_CONTROL_POLL_INTERVAL_SECS);
        if control_poll_interval_secs == 0 {
            return Err(ConfigError::ZeroControlPollInterval);
        }

        let heartbeat_interval_secs = raw
            .heartbeat_interval_secs
            .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_SECS);
        if heartbeat_interval_secs == 0 {
            return Err(ConfigError::ZeroHeartbeatInterval);
        }

        Ok(Self {
            gateway_url,
            tenant_id,
            api_token,
            runner_id,
            gateway_public_key_hex,
            workspace_root: raw
                .workspace_root
                .unwrap_or_else(|| PathBuf::from(DEFAULT_WORKSPACE_ROOT)),
            claim_poll_interval_secs,
            control_poll_interval_secs,
            heartbeat_interval_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_with(gateway_url: Option<&str>, tenant_id: Option<&str>) -> RawRunnerConfig {
        RawRunnerConfig {
            gateway_url: gateway_url.map(str::to_string),
            tenant_id: tenant_id.map(str::to_string),
            api_token: Some("tok_a".to_string()),
            gateway_public_key_hex: Some("deadbeef".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn parses_a_minimal_valid_toml_file() {
        let toml_str = r#"
            gateway_url = "https://gateway.internal:8080"
            tenant_id = "tenant_a"
            api_token = "tok_a"
            gateway_public_key_hex = "deadbeef"
        "#;
        let raw: RawRunnerConfig = toml::from_str(toml_str).unwrap();
        let config = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap();
        assert_eq!(
            config.gateway_url.as_str(),
            "https://gateway.internal:8080/"
        );
        assert_eq!(config.tenant_id, "tenant_a");
        assert_eq!(config.api_token, "tok_a");
        assert_eq!(config.gateway_public_key_hex, "deadbeef");
        assert_eq!(
            config.claim_poll_interval_secs,
            DEFAULT_CLAIM_POLL_INTERVAL_SECS
        );
        assert_eq!(
            config.heartbeat_interval_secs,
            DEFAULT_HEARTBEAT_INTERVAL_SECS
        );
    }

    #[test]
    fn rejects_unknown_fields_in_config_file() {
        let toml_str = r#"
            gateway_url = "https://gateway.internal"
            tenant_id = "tenant_a"
            typo_field = "oops"
        "#;
        assert!(toml::from_str::<RawRunnerConfig>(toml_str).is_err());
    }

    #[test]
    fn cli_overrides_win_over_file_config() {
        let raw = raw_with(Some("https://from-file.example"), Some("tenant_file"));
        let overrides = CliOverrides {
            gateway_url: Some("https://from-cli.example".to_string()),
            tenant_id: Some("tenant_cli".to_string()),
            api_token: Some("tok_cli".to_string()),
            runner_id: None,
            gateway_public_key_hex: None,
        };
        let config = RunnerConfig::resolve(raw, overrides).unwrap();
        assert_eq!(config.gateway_url.host_str(), Some("from-cli.example"));
        assert_eq!(config.tenant_id, "tenant_cli");
        assert_eq!(config.api_token, "tok_cli");
    }

    #[test]
    fn missing_gateway_url_fails_closed() {
        let raw = raw_with(None, Some("tenant_a"));
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingGatewayUrl);
    }

    #[test]
    fn missing_tenant_id_fails_closed() {
        let raw = raw_with(Some("https://gateway.internal"), None);
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingTenantId);
    }

    #[test]
    fn empty_tenant_id_fails_closed() {
        let raw = raw_with(Some("https://gateway.internal"), Some("   "));
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::EmptyTenantId);
    }

    #[test]
    fn missing_api_token_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.api_token = None;
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingApiToken);
    }

    #[test]
    fn missing_gateway_public_key_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.gateway_public_key_hex = None;
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingGatewayPublicKey);
    }

    #[test]
    fn empty_gateway_public_key_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.gateway_public_key_hex = Some("   ".to_string());
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::EmptyGatewayPublicKey);
    }

    #[test]
    fn malformed_gateway_url_fails_closed() {
        let raw = raw_with(Some("not a url"), Some("tenant_a"));
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGatewayUrl(_, _)));
    }

    #[test]
    fn non_http_gateway_url_scheme_fails_closed() {
        let raw = raw_with(Some("ftp://gateway.internal"), Some("tenant_a"));
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(
            err,
            ConfigError::UnsupportedGatewayUrlScheme("ftp".to_string())
        );
    }

    #[test]
    fn zero_claim_poll_interval_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.claim_poll_interval_secs = Some(0);
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::ZeroClaimPollInterval);
    }

    #[test]
    fn zero_heartbeat_interval_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.heartbeat_interval_secs = Some(0);
        let err = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::ZeroHeartbeatInterval);
    }

    #[test]
    fn runner_id_defaults_when_unset() {
        let raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        let config = RunnerConfig::resolve(raw, CliOverrides::default()).unwrap();
        assert!(!config.runner_id.is_empty());
    }

    #[test]
    fn explicit_runner_id_is_honored() {
        let raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        let overrides = CliOverrides {
            runner_id: Some("runner-explicit".to_string()),
            ..Default::default()
        };
        let config = RunnerConfig::resolve(raw, overrides).unwrap();
        assert_eq!(config.runner_id, "runner-explicit");
    }
}
