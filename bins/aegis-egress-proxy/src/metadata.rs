//! Destination metadata extraction — the "DNS/HTTP/SNI metadata where
//! possible" part of the Phase 5.3 acceptance. For an explicit proxy the
//! destination is stated up front (CONNECT authority or absolute-form
//! URI); the TLS SNI inside a CONNECT tunnel is parsed opportunistically
//! from the first client bytes so it can be cross-checked against the
//! CONNECT host.

use crate::error::ProxyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    /// `CONNECT host:port` — an opaque tunnel (normally TLS).
    Connect,
    /// Absolute-form plaintext HTTP, e.g. `GET http://host/path HTTP/1.1`.
    HttpForward,
}

/// Where the client asked to go, parsed from the proxy request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
    pub protocol: ProxyProtocol,
    /// For [`ProxyProtocol::HttpForward`], the origin-form path (`/path?q`)
    /// to rewrite the request line with. Always `/` at minimum.
    pub origin_form_path: String,
}

fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), ProxyError> {
    let (host, port) = match authority.rsplit_once(':') {
        // An IPv6 literal like `[::1]:443` also lands here; a bare `::1`
        // without a port would mis-split, so require brackets for v6.
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| ProxyError::MalformedRequest(format!("bad port in {authority:?}")))?;
            (host, port)
        }
        _ => (authority, default_port),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(ProxyError::MalformedRequest(
            "empty host in request target".to_string(),
        ));
    }
    Ok((host.to_ascii_lowercase(), port))
}

/// Parses the first line of a proxy request. Origin-form requests
/// (`GET /path HTTP/1.1`) are rejected: this is an explicit proxy, and a
/// request without a stated destination has nothing to authorize —
/// fail closed.
pub fn parse_request_target(request_line: &str) -> Result<ConnectTarget, ProxyError> {
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ProxyError::MalformedRequest("empty request line".to_string()))?;
    let target = parts
        .next()
        .ok_or_else(|| ProxyError::MalformedRequest("missing request target".to_string()))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(target, 443)?;
        return Ok(ConnectTarget {
            host,
            port,
            protocol: ProxyProtocol::Connect,
            origin_form_path: String::new(),
        });
    }

    let rest = target.strip_prefix("http://").ok_or_else(|| {
        ProxyError::MalformedRequest(format!(
            "expected CONNECT or an absolute http:// URI, got {target:?}"
        ))
    })?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, 80)?;
    Ok(ConnectTarget {
        host,
        port,
        protocol: ProxyProtocol::HttpForward,
        origin_form_path: path.to_string(),
    })
}

/// Best-effort SNI extraction from the first client bytes of a tunnel.
/// Returns `None` for anything that isn't a complete, well-formed TLS
/// ClientHello in this buffer — non-TLS traffic through CONNECT is legal,
/// so absence of an SNI is not itself a violation.
pub fn parse_sni(client_bytes: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) version(2) length(2).
    if client_bytes.len() < 5 || client_bytes[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([client_bytes[3], client_bytes[4]]) as usize;
    let record = client_bytes.get(5..5 + record_len)?;

    // Handshake header: msg_type(1) length(3); ClientHello is type 1.
    if record.len() < 4 || record[0] != 0x01 {
        return None;
    }
    let hs_len = u32::from_be_bytes([0, record[1], record[2], record[3]]) as usize;
    let hello = record.get(4..4 + hs_len)?;

    // client_version(2) random(32).
    let mut pos = 34;
    // session_id: u8-prefixed.
    let session_len = *hello.get(pos)? as usize;
    pos += 1 + session_len;
    // cipher_suites: u16-prefixed.
    let cipher_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2 + cipher_len;
    // compression_methods: u8-prefixed.
    let compression_len = *hello.get(pos)? as usize;
    pos += 1 + compression_len;
    // extensions: u16-prefixed block of (type u16, len u16, data).
    let ext_total = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2;
    let mut ext = hello.get(pos..pos + ext_total)?;

    while ext.len() >= 4 {
        let ext_type = u16::from_be_bytes([ext[0], ext[1]]);
        let ext_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
        let ext_data = ext.get(4..4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name list: list_len(2) name_type(1) name_len(2) name.
            if ext_data.len() < 5 || ext_data[2] != 0x00 {
                return None;
            }
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            let name = ext_data.get(5..5 + name_len)?;
            return String::from_utf8(name.to_vec())
                .ok()
                .map(|s| s.to_ascii_lowercase());
        }
        ext = ext.get(4 + ext_len..)?;
    }
    None
}

/// Builds a minimal, well-formed TLS ClientHello carrying `sni`, for tests
/// that need to exercise the tunnel-side SNI cross-check.
#[cfg(test)]
pub(crate) fn build_client_hello_with_sni(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut ext_data = Vec::new();
    ext_data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // server_name_list len
    ext_data.push(0x00); // name_type: host_name
    ext_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
    ext_data.extend_from_slice(name);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type: server_name
    extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ext_data);

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]); // client_version
    hello.extend_from_slice(&[0u8; 32]); // random
    hello.push(0); // session_id len
    hello.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
    hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    hello.push(1); // compression_methods len
    hello.push(0); // null compression
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = vec![0x01]; // ClientHello
    let hs_len = (hello.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&hs_len[1..]);
    handshake.extend_from_slice(&hello);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake record, TLS 1.0 compat version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_line_yields_the_stated_authority() {
        let target = parse_request_target("CONNECT api.example.com:443 HTTP/1.1")
            .expect("valid CONNECT line");
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.protocol, ProxyProtocol::Connect);
    }

    #[test]
    fn connect_without_a_port_defaults_to_443() {
        let target =
            parse_request_target("CONNECT api.example.com HTTP/1.1").expect("valid CONNECT line");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn absolute_form_http_uri_yields_host_port_and_origin_path() {
        let target = parse_request_target("GET http://api.example.com:8080/v1/data?x=1 HTTP/1.1")
            .expect("valid absolute-form line");
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 8080);
        assert_eq!(target.protocol, ProxyProtocol::HttpForward);
        assert_eq!(target.origin_form_path, "/v1/data?x=1");
    }

    #[test]
    fn absolute_form_without_a_port_defaults_to_80() {
        let target =
            parse_request_target("GET http://api.example.com HTTP/1.1").expect("valid line");
        assert_eq!(target.port, 80);
        assert_eq!(target.origin_form_path, "/");
    }

    #[test]
    fn origin_form_requests_are_rejected_because_there_is_no_destination_to_authorize() {
        assert!(parse_request_target("GET /path HTTP/1.1").is_err());
    }

    #[test]
    fn https_absolute_form_is_rejected_rather_than_silently_tunneled() {
        assert!(parse_request_target("GET https://api.example.com/ HTTP/1.1").is_err());
    }

    #[test]
    fn sni_round_trips_through_the_parser() {
        let hello = build_client_hello_with_sni("API.Example.COM");
        assert_eq!(parse_sni(&hello).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn non_tls_bytes_have_no_sni() {
        assert_eq!(parse_sni(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(parse_sni(&[]), None);
        assert_eq!(parse_sni(&[0x16, 0x03]), None);
    }

    #[test]
    fn truncated_client_hello_is_rejected_without_panicking() {
        let hello = build_client_hello_with_sni("api.example.com");
        for cut in 0..hello.len() {
            // Every truncation must be a clean None, never a panic.
            let _ = parse_sni(&hello[..cut]);
        }
    }
}
