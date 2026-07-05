//! SSRF guard for tenant-supplied outbound URLs (#1605).
//!
//! Validates callback URLs at registration time so a future dispatcher cannot
//! be aimed at loopback, link-local, private, or cloud-metadata targets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CallbackUrlError {
    #[error("callback URL must not be empty")]
    Empty,
    #[error("callback URL must use the https scheme")]
    HttpsRequired,
    #[error("callback URL must not embed credentials")]
    UserinfoForbidden,
    #[error("callback URL is missing a host")]
    MissingHost,
    #[error("callback URL host is blocked: {0}")]
    BlockedHost(String),
    #[error("callback URL resolves to a blocked address: {0}")]
    BlockedAddress(IpAddr),
    #[error("callback URL could not be resolved")]
    Unresolvable,
    #[error("invalid callback URL: {0}")]
    InvalidUrl(String),
}

/// Validate a tenant-supplied approval `callback_url` before persistence.
///
/// Enforces `https` only, rejects embedded credentials, blocks literal private
/// targets, and resolves hostnames to ensure they do not map to blocked ranges
/// (defense-in-depth for DNS rebinding ahead of any dispatcher).
pub fn validate_callback_url(raw: &str) -> Result<(), CallbackUrlError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CallbackUrlError::Empty);
    }

    let parsed = Url::parse(trimmed).map_err(|e| CallbackUrlError::InvalidUrl(e.to_string()))?;

    if parsed.scheme() != "https" {
        return Err(CallbackUrlError::HttpsRequired);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CallbackUrlError::UserinfoForbidden);
    }

    let host = parsed.host_str().ok_or(CallbackUrlError::MissingHost)?;

    if is_blocked_hostname(host) {
        return Err(CallbackUrlError::BlockedHost(host.to_string()));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return check_ip(ip);
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| CallbackUrlError::Unresolvable)?
        .map(|socket| socket.ip())
        .collect();

    if addrs.is_empty() {
        return Err(CallbackUrlError::Unresolvable);
    }

    for ip in addrs {
        check_ip(ip)?;
    }

    Ok(())
}

fn check_ip(ip: IpAddr) -> Result<(), CallbackUrlError> {
    if is_blocked_ip(ip) {
        Err(CallbackUrlError::BlockedAddress(ip))
    } else {
        Ok(())
    }
}

fn is_blocked_hostname(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    matches!(
        h.as_str(),
        "localhost" | "metadata" | "metadata.google.internal" | "instance-data"
    ) || h.ends_with(".localhost")
        || h.ends_with(".local")
}

/// Returns `true` when `ip` must not be contacted by tenant-supplied callbacks.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ipv4(v4);
            }
            is_blocked_ipv6(v6)
        }
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || is_carrier_grade_nat(ip)
}

fn is_carrier_grade_nat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    // Unique local (fc00::/7)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_https_url() {
        assert!(validate_callback_url("https://example.com/aegis-callback").is_ok());
    }

    #[test]
    fn rejects_http_scheme() {
        assert_eq!(
            validate_callback_url("http://example.com/cb"),
            Err(CallbackUrlError::HttpsRequired)
        );
    }

    #[test]
    fn rejects_loopback_literal() {
        assert_eq!(
            validate_callback_url("https://127.0.0.1/cb"),
            Err(CallbackUrlError::BlockedAddress(
                "127.0.0.1".parse().unwrap()
            ))
        );
    }

    #[test]
    fn rejects_aws_metadata_literal() {
        assert_eq!(
            validate_callback_url("https://169.254.169.254/latest/meta-data"),
            Err(CallbackUrlError::BlockedAddress(
                "169.254.169.254".parse().unwrap()
            ))
        );
    }

    #[test]
    fn rejects_private_rfc1918_literal() {
        assert_eq!(
            validate_callback_url("https://10.0.0.1/hook"),
            Err(CallbackUrlError::BlockedAddress(
                "10.0.0.1".parse().unwrap()
            ))
        );
        assert_eq!(
            validate_callback_url("https://192.168.1.50/hook"),
            Err(CallbackUrlError::BlockedAddress(
                "192.168.1.50".parse().unwrap()
            ))
        );
    }

    #[test]
    fn rejects_localhost_hostname() {
        assert_eq!(
            validate_callback_url("https://localhost/cb"),
            Err(CallbackUrlError::BlockedHost("localhost".to_string()))
        );
    }

    #[test]
    fn rejects_metadata_hostname() {
        assert_eq!(
            validate_callback_url("https://metadata.google.internal/computeMetadata/v1/"),
            Err(CallbackUrlError::BlockedHost(
                "metadata.google.internal".to_string()
            ))
        );
    }

    #[test]
    fn rejects_embedded_credentials() {
        assert_eq!(
            validate_callback_url("https://user:pass@example.com/cb"),
            Err(CallbackUrlError::UserinfoForbidden)
        );
    }

    #[test]
    fn is_blocked_ip_flags_common_ssrf_targets() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("10.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
    }
}
