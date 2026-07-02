//! Phase 3.1 (Agent Cage): sensor configuration. Loaded from an optional TOML
//! file, overridden by CLI flags, then validated. Invalid configuration fails
//! closed — the sensor refuses to start rather than run with guessed values.

use std::path::PathBuf;

use serde::Deserialize;
use url::Url;

const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_IDENTITY_KEY_PATH: &str = "aegis-sensor-identity.key";
const DEFAULT_SPOOL_DIR: &str = "aegis-sensor-spool";
const DEFAULT_SPOOL_MAX_BYTES_PER_LANE: u64 = 100 * 1024 * 1024;

/// Sensor enforcement posture. Mirrors the gateway's `agent_runs.mode` values
/// (`observe` | `enforce` | `lockdown`) so a run's mode and its sensor's mode
/// speak the same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SensorMode {
    #[default]
    Observe,
    Enforce,
    Lockdown,
}

impl SensorMode {
    fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw {
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            "lockdown" => Ok(Self::Lockdown),
            other => Err(ConfigError::InvalidMode(other.to_string())),
        }
    }
}

impl std::fmt::Display for SensorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
            Self::Lockdown => "lockdown",
        };
        f.write_str(s)
    }
}

/// Raw, unvalidated configuration as deserialized from the TOML config file.
/// Every field is optional here — CLI flags and defaults fill the gaps, and
/// [`SensorConfig::resolve`] is the single place validation happens.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSensorConfig {
    pub gateway_url: Option<String>,
    pub tenant_id: Option<String>,
    /// Bearer credential presented as `Authorization: Bearer <api_token>` on
    /// every gateway call (registration, heartbeat, event ingest, command
    /// polling) — the sensor authenticates like any other API client, there
    /// is no sensor-specific auth mechanism.
    pub api_token: Option<String>,
    pub mode: Option<String>,
    pub identity_key_path: Option<PathBuf>,
    pub spool_dir: Option<PathBuf>,
    pub spool_max_bytes_per_lane: Option<u64>,
    pub heartbeat_interval_secs: Option<u64>,
    /// Hex-encoded Ed25519 public key the sensor pins for verifying signed
    /// commands (Control Command Protocol doc, 3.2 — config is an
    /// explicitly allowed alternative to fetching it at registration).
    /// Unset means the sensor cannot verify any command and rejects them
    /// all fail-closed, rather than trusting an unverifiable one.
    pub gateway_public_key_hex: Option<String>,
}

/// CLI-supplied overrides, applied on top of the config file before defaults.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub gateway_url: Option<String>,
    pub tenant_id: Option<String>,
    pub api_token: Option<String>,
    pub mode: Option<String>,
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
    #[error("mode {0:?} is invalid (expected observe, enforce, or lockdown)")]
    InvalidMode(String),
    #[error("heartbeat_interval_secs must be greater than zero")]
    ZeroHeartbeatInterval,
    #[error("spool_max_bytes_per_lane must be greater than zero")]
    ZeroSpoolMaxBytesPerLane,
}

/// Validated sensor configuration — every field here is known-good.
#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub gateway_url: Url,
    pub tenant_id: String,
    pub api_token: String,
    pub mode: SensorMode,
    pub identity_key_path: PathBuf,
    pub spool_dir: PathBuf,
    pub spool_max_bytes_per_lane: u64,
    pub heartbeat_interval_secs: u64,
    pub gateway_public_key_hex: Option<String>,
}

impl SensorConfig {
    /// Merge file config + CLI overrides (CLI wins), fill defaults, and
    /// validate. Fails closed: any invalid or missing required field is an
    /// error, never a silently-guessed value.
    pub fn resolve(raw: RawSensorConfig, overrides: CliOverrides) -> Result<Self, ConfigError> {
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

        let mode = match overrides.mode.or(raw.mode) {
            Some(m) => SensorMode::parse(&m)?,
            None => SensorMode::default(),
        };

        let heartbeat_interval_secs = raw
            .heartbeat_interval_secs
            .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_SECS);
        if heartbeat_interval_secs == 0 {
            return Err(ConfigError::ZeroHeartbeatInterval);
        }

        let spool_max_bytes_per_lane = raw
            .spool_max_bytes_per_lane
            .unwrap_or(DEFAULT_SPOOL_MAX_BYTES_PER_LANE);
        if spool_max_bytes_per_lane == 0 {
            return Err(ConfigError::ZeroSpoolMaxBytesPerLane);
        }

        Ok(Self {
            gateway_url,
            tenant_id,
            api_token,
            mode,
            identity_key_path: raw
                .identity_key_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_KEY_PATH)),
            spool_dir: raw
                .spool_dir
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SPOOL_DIR)),
            spool_max_bytes_per_lane,
            heartbeat_interval_secs,
            gateway_public_key_hex: raw.gateway_public_key_hex,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_with(gateway_url: Option<&str>, tenant_id: Option<&str>) -> RawSensorConfig {
        RawSensorConfig {
            gateway_url: gateway_url.map(str::to_string),
            tenant_id: tenant_id.map(str::to_string),
            api_token: Some("tok_a".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn parses_a_minimal_valid_toml_file() {
        let toml_str = r#"
            gateway_url = "https://gateway.internal:8080"
            tenant_id = "tenant_a"
            api_token = "tok_a"
        "#;
        let raw: RawSensorConfig = toml::from_str(toml_str).unwrap();
        let config = SensorConfig::resolve(raw, CliOverrides::default()).unwrap();
        assert_eq!(
            config.gateway_url.as_str(),
            "https://gateway.internal:8080/"
        );
        assert_eq!(config.tenant_id, "tenant_a");
        assert_eq!(config.api_token, "tok_a");
        assert_eq!(config.mode, SensorMode::Observe);
        assert_eq!(
            config.heartbeat_interval_secs,
            DEFAULT_HEARTBEAT_INTERVAL_SECS
        );
    }

    #[test]
    fn parses_a_fully_specified_toml_file() {
        let toml_str = r#"
            gateway_url = "http://127.0.0.1:8080"
            tenant_id = "tenant_b"
            api_token = "tok_b"
            mode = "enforce"
            identity_key_path = "/etc/aegis/sensor.key"
            spool_dir = "/var/lib/aegis/spool"
            heartbeat_interval_secs = 15
        "#;
        let raw: RawSensorConfig = toml::from_str(toml_str).unwrap();
        let config = SensorConfig::resolve(raw, CliOverrides::default()).unwrap();
        assert_eq!(config.mode, SensorMode::Enforce);
        assert_eq!(
            config.identity_key_path,
            PathBuf::from("/etc/aegis/sensor.key")
        );
        assert_eq!(config.spool_dir, PathBuf::from("/var/lib/aegis/spool"));
        assert_eq!(config.heartbeat_interval_secs, 15);
    }

    #[test]
    fn rejects_unknown_fields_in_config_file() {
        let toml_str = r#"
            gateway_url = "https://gateway.internal"
            tenant_id = "tenant_a"
            typo_field = "oops"
        "#;
        assert!(toml::from_str::<RawSensorConfig>(toml_str).is_err());
    }

    #[test]
    fn cli_overrides_win_over_file_config() {
        let raw = raw_with(Some("https://from-file.example"), Some("tenant_file"));
        let overrides = CliOverrides {
            gateway_url: Some("https://from-cli.example".to_string()),
            tenant_id: Some("tenant_cli".to_string()),
            api_token: Some("tok_cli".to_string()),
            mode: None,
        };
        let config = SensorConfig::resolve(raw, overrides).unwrap();
        assert_eq!(config.gateway_url.host_str(), Some("from-cli.example"));
        assert_eq!(config.tenant_id, "tenant_cli");
        assert_eq!(config.api_token, "tok_cli");
    }

    #[test]
    fn missing_gateway_url_fails_closed() {
        let raw = raw_with(None, Some("tenant_a"));
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingGatewayUrl);
    }

    #[test]
    fn missing_tenant_id_fails_closed() {
        let raw = raw_with(Some("https://gateway.internal"), None);
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingTenantId);
    }

    #[test]
    fn empty_tenant_id_fails_closed() {
        let raw = raw_with(Some("https://gateway.internal"), Some("   "));
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::EmptyTenantId);
    }

    #[test]
    fn missing_api_token_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.api_token = None;
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::MissingApiToken);
    }

    #[test]
    fn empty_api_token_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.api_token = Some("   ".to_string());
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::EmptyApiToken);
    }

    #[test]
    fn malformed_gateway_url_fails_closed() {
        let raw = raw_with(Some("not a url"), Some("tenant_a"));
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGatewayUrl(_, _)));
    }

    #[test]
    fn non_http_gateway_url_scheme_fails_closed() {
        let raw = raw_with(Some("ftp://gateway.internal"), Some("tenant_a"));
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(
            err,
            ConfigError::UnsupportedGatewayUrlScheme("ftp".to_string())
        );
    }

    #[test]
    fn invalid_mode_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.mode = Some("yolo".to_string());
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::InvalidMode("yolo".to_string()));
    }

    #[test]
    fn zero_heartbeat_interval_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.heartbeat_interval_secs = Some(0);
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::ZeroHeartbeatInterval);
    }

    #[test]
    fn zero_spool_max_bytes_per_lane_fails_closed() {
        let mut raw = raw_with(Some("https://gateway.internal"), Some("tenant_a"));
        raw.spool_max_bytes_per_lane = Some(0);
        let err = SensorConfig::resolve(raw, CliOverrides::default()).unwrap_err();
        assert_eq!(err, ConfigError::ZeroSpoolMaxBytesPerLane);
    }
}
