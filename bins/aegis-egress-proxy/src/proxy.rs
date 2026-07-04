//! The proxy loop itself: accept a client, read the proxy request head,
//! ask the decider, and only then touch the network toward the
//! destination. A deny — from policy, from a malformed request, or from a
//! decider failure — never opens an upstream connection.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::decider::EgressDecider;
use crate::error::ProxyError;
use crate::events::{ProxyEvent, ProxyEventSink, ProxyEventType};
use crate::metadata::{parse_request_target, parse_sni, ConnectTarget, ProxyProtocol};

const MAX_HEAD_BYTES: usize = 16 * 1024;
const HEAD_READ_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const COPY_BUF_SIZE: usize = 16 * 1024;

const DEFAULT_LARGE_UPLOAD_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Client-to-destination bytes in a single connection beyond which a
    /// `egress_large_upload` event is emitted (once). The exfiltration
    /// detection hook of the Phase 5.3 acceptance — detection, not a cap.
    pub large_upload_threshold_bytes: u64,
    /// When the first bytes of a CONNECT tunnel carry a TLS SNI that
    /// differs from the CONNECT host, close the tunnel. The authorized
    /// destination and the actually-dialed TLS name must agree.
    pub enforce_sni_match: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            large_upload_threshold_bytes: DEFAULT_LARGE_UPLOAD_THRESHOLD_BYTES,
            enforce_sni_match: true,
        }
    }
}

pub struct ProxyServer {
    listener: TcpListener,
    decider: Arc<dyn EgressDecider>,
    sink: Arc<dyn ProxyEventSink>,
    config: ProxyConfig,
}

impl ProxyServer {
    pub async fn bind(
        addr: &str,
        decider: Arc<dyn EgressDecider>,
        sink: Arc<dyn ProxyEventSink>,
        config: ProxyConfig,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            decider,
            sink,
            config,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept loop; one task per client connection. Runs until the
    /// listener errors.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (client, peer) = self.listener.accept().await?;
            let decider = Arc::clone(&self.decider);
            let sink = Arc::clone(&self.sink);
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_connection(client, decider, sink, config).await {
                    debug!(%peer, error = %err, "proxy connection ended with error");
                }
            });
        }
    }
}

/// Reads the request head (through the blank line). Returns the head and
/// any body/tunnel bytes that arrived in the same reads.
async fn read_head(client: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>), ProxyError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(HEAD_READ_TIMEOUT, client.read(&mut chunk))
            .await
            .map_err(|_| ProxyError::MalformedRequest("request head read timed out".into()))??;
        if n == 0 {
            return Err(ProxyError::MalformedRequest(
                "connection closed before request head completed".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_head_end(&buf) {
            let leftover = buf.split_off(end);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(ProxyError::MalformedRequest(format!(
                "request head exceeds {MAX_HEAD_BYTES} bytes"
            )));
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

async fn write_simple_response(
    client: &mut TcpStream,
    status_line: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "{status_line}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes()).await?;
    client.shutdown().await
}

async fn handle_connection(
    mut client: TcpStream,
    decider: Arc<dyn EgressDecider>,
    sink: Arc<dyn ProxyEventSink>,
    config: ProxyConfig,
) -> Result<(), ProxyError> {
    let (head, leftover) = match read_head(&mut client).await {
        Ok(parts) => parts,
        Err(err) => {
            let _ = write_simple_response(&mut client, "HTTP/1.1 400 Bad Request", "").await;
            return Err(err);
        }
    };
    let head_text = String::from_utf8_lossy(&head);
    let request_line = head_text.lines().next().unwrap_or_default();
    let target = match parse_request_target(request_line) {
        Ok(target) => target,
        Err(err) => {
            let _ = write_simple_response(&mut client, "HTTP/1.1 400 Bad Request", "").await;
            return Err(err);
        }
    };

    let outcome = decider.check(&target.host, target.port).await;
    if !outcome.is_allowed() {
        sink.record(
            ProxyEvent::new(ProxyEventType::EgressBlocked, &target.host, target.port)
                .with_detail(outcome.reason.clone()),
        );
        warn!(host = %target.host, port = target.port, reason = %outcome.reason, "egress blocked");
        write_simple_response(&mut client, "HTTP/1.1 403 Forbidden", &outcome.reason).await?;
        return Ok(());
    }

    let upstream = tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await;
    let mut upstream = match upstream {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(err)) => {
            write_simple_response(&mut client, "HTTP/1.1 502 Bad Gateway", "").await?;
            return Err(err.into());
        }
        Err(_) => {
            write_simple_response(&mut client, "HTTP/1.1 504 Gateway Timeout", "").await?;
            return Err(ProxyError::MalformedRequest(format!(
                "upstream connect to {}:{} timed out",
                target.host, target.port
            )));
        }
    };

    sink.record(
        ProxyEvent::new(ProxyEventType::EgressAllowed, &target.host, target.port)
            .with_detail(outcome.reason),
    );

    match target.protocol {
        ProxyProtocol::Connect => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            if !leftover.is_empty() {
                upstream.write_all(&leftover).await?;
            }
            // Only inspect for SNI if the tunnel's first client bytes
            // haven't already flowed.
            let check_sni = config.enforce_sni_match && leftover.is_empty();
            tunnel(client, upstream, &target, sink, &config, check_sni).await?;
        }
        ProxyProtocol::HttpForward => {
            let rewritten = rewrite_forward_head(&head_text, &target);
            upstream.write_all(rewritten.as_bytes()).await?;
            if !leftover.is_empty() {
                upstream.write_all(&leftover).await?;
            }
            tunnel(client, upstream, &target, sink, &config, false).await?;
        }
    }
    Ok(())
}

/// Turns the absolute-form proxy head into an origin-form head for the
/// destination: rewritten request line, hop-by-hop proxy headers dropped,
/// and `Connection: close` forced (the skeleton doesn't do keep-alive).
fn rewrite_forward_head(head_text: &str, target: &ConnectTarget) -> String {
    let mut lines = head_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let method = request_line.split_whitespace().next().unwrap_or("GET");
    let mut head = format!("{method} {} HTTP/1.1\r\n", target.origin_form_path);
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-") || lower.starts_with("connection:") {
            continue;
        }
        head.push_str(line);
        head.push_str("\r\n");
    }
    head.push_str("connection: close\r\n\r\n");
    head
}

/// Bidirectional byte pump with the two tunnel-time observations the
/// gateway can't see at check time: cumulative upload volume (the large
/// upload detection hook) and the TLS SNI in the first client bytes.
async fn tunnel(
    client: TcpStream,
    upstream: TcpStream,
    target: &ConnectTarget,
    sink: Arc<dyn ProxyEventSink>,
    config: &ProxyConfig,
    check_sni: bool,
) -> std::io::Result<()> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let mut client_buf = vec![0u8; COPY_BUF_SIZE];
    let mut upstream_buf = vec![0u8; COPY_BUF_SIZE];
    let mut uploaded: u64 = 0;
    let mut large_upload_reported = false;
    let mut awaiting_first_client_bytes = check_sni;

    loop {
        tokio::select! {
            read = client_read.read(&mut client_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                if awaiting_first_client_bytes {
                    awaiting_first_client_bytes = false;
                    if let Some(sni) = parse_sni(&client_buf[..n]) {
                        if sni != target.host {
                            sink.record(
                                ProxyEvent::new(
                                    ProxyEventType::SniMismatch,
                                    &target.host,
                                    target.port,
                                )
                                .with_detail(format!(
                                    "CONNECT host {} but TLS SNI {sni}",
                                    target.host
                                )),
                            );
                            warn!(
                                connect_host = %target.host,
                                sni = %sni,
                                "SNI mismatch — closing tunnel"
                            );
                            break;
                        }
                    }
                }
                uploaded += n as u64;
                if !large_upload_reported && uploaded > config.large_upload_threshold_bytes {
                    large_upload_reported = true;
                    sink.record(
                        ProxyEvent::new(ProxyEventType::LargeUpload, &target.host, target.port)
                            .with_detail(format!(
                                "{uploaded} bytes uploaded (threshold {})",
                                config.large_upload_threshold_bytes
                            )),
                    );
                }
                upstream_write.write_all(&client_buf[..n]).await?;
            }
            read = upstream_read.read(&mut upstream_buf) => {
                let n = read?;
                if n == 0 {
                    break;
                }
                client_write.write_all(&upstream_buf[..n]).await?;
            }
        }
    }
    let _ = upstream_write.shutdown().await;
    let _ = client_write.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decider::PolicyDecider;
    use crate::events::RecordingEventSink;
    use crate::metadata::build_client_hello_with_sni;
    use aegis_egress::EgressRule;
    use ipnet::IpNet;

    fn loopback_allow_rules() -> Vec<EgressRule> {
        let net: IpNet = "127.0.0.0/8".parse().expect("valid CIDR literal");
        vec![EgressRule::allow_cidr(net)]
    }

    async fn spawn_proxy(
        deny_by_default: bool,
        tenant_rules: Vec<EgressRule>,
        config: ProxyConfig,
    ) -> (std::net::SocketAddr, Arc<RecordingEventSink>) {
        let sink = Arc::new(RecordingEventSink::default());
        let decider = Arc::new(PolicyDecider::new(deny_by_default, &tenant_rules, &[]));
        let server = ProxyServer::bind("127.0.0.1:0", decider, sink.clone(), config)
            .await
            .expect("bind proxy");
        let addr = server.local_addr().expect("proxy addr");
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        (addr, sink)
    }

    /// One-shot plaintext HTTP origin: accepts a single connection, reads
    /// the request head, answers with a fixed body.
    async fn spawn_http_origin() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
                    )
                    .await;
            }
        });
        addr
    }

    /// One-shot echo origin: whatever arrives goes straight back.
    async fn spawn_echo_origin() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let addr = listener.local_addr().expect("origin addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
        addr
    }

    async fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            }
        }
        out
    }

    #[tokio::test]
    async fn an_allowed_absolute_form_request_forwards_to_the_origin() {
        let origin = spawn_http_origin().await;
        let (proxy, sink) = spawn_proxy(true, loopback_allow_rules(), ProxyConfig::default()).await;

        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        let request = format!(
            "GET http://{origin}/hello HTTP/1.1\r\nhost: {origin}\r\nproxy-connection: keep-alive\r\n\r\n"
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("send request");
        let response = String::from_utf8_lossy(&read_to_end(&mut client).await).to_string();

        assert!(response.starts_with("HTTP/1.1 200 OK"), "got: {response}");
        assert!(response.ends_with("hello"), "got: {response}");
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, ProxyEventType::EgressAllowed);
        assert_eq!(events[0].host, "127.0.0.1");
    }

    #[tokio::test]
    async fn a_blocked_request_is_denied_with_403_and_an_event() {
        // Deny-by-default with no rules: nothing may leave.
        let (proxy, sink) = spawn_proxy(true, vec![], ProxyConfig::default()).await;

        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(b"CONNECT blocked.example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .expect("send request");
        let response = String::from_utf8_lossy(&read_to_end(&mut client).await).to_string();

        assert!(
            response.starts_with("HTTP/1.1 403 Forbidden"),
            "got: {response}"
        );
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, ProxyEventType::EgressBlocked);
        assert_eq!(events[0].host, "blocked.example.com");
        assert_eq!(events[0].port, 443);
    }

    #[tokio::test]
    async fn an_allowed_connect_request_tunnels_bytes_both_ways() {
        let origin = spawn_echo_origin().await;
        let (proxy, sink) = spawn_proxy(true, loopback_allow_rules(), ProxyConfig::default()).await;

        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(format!("CONNECT {origin} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("send CONNECT");
        let mut buf = [0u8; 256];
        let n = client.read(&mut buf).await.expect("read CONNECT response");
        assert!(
            String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"),
            "CONNECT was refused"
        );

        client
            .write_all(b"ping")
            .await
            .expect("send through tunnel");
        let mut echo = [0u8; 4];
        client
            .read_exact(&mut echo)
            .await
            .expect("read echo through tunnel");
        assert_eq!(&echo, b"ping");
        assert_eq!(sink.events().len(), 1);
        assert_eq!(sink.events()[0].event_type, ProxyEventType::EgressAllowed);
    }

    #[tokio::test]
    async fn an_upload_over_the_threshold_emits_a_large_upload_event_once() {
        let origin = spawn_echo_origin().await;
        let config = ProxyConfig {
            large_upload_threshold_bytes: 16,
            enforce_sni_match: true,
        };
        let (proxy, sink) = spawn_proxy(true, loopback_allow_rules(), config).await;

        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(format!("CONNECT {origin} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("send CONNECT");
        let mut buf = [0u8; 256];
        let _ = client.read(&mut buf).await.expect("read CONNECT response");

        // Two writes past the threshold; the echo read synchronizes so the
        // proxy has definitely pumped the bytes before we assert.
        for _ in 0..2 {
            client.write_all(&[0x41u8; 32]).await.expect("upload");
            let mut echo = [0u8; 32];
            client.read_exact(&mut echo).await.expect("echo back");
        }

        let large: Vec<_> = sink
            .events()
            .into_iter()
            .filter(|e| e.event_type == ProxyEventType::LargeUpload)
            .collect();
        assert_eq!(large.len(), 1, "threshold event must fire exactly once");
        assert_eq!(large[0].host, "127.0.0.1");
    }

    #[tokio::test]
    async fn a_tls_sni_that_contradicts_the_connect_host_closes_the_tunnel() {
        let origin = spawn_echo_origin().await;
        let (proxy, sink) = spawn_proxy(true, loopback_allow_rules(), ProxyConfig::default()).await;

        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(format!("CONNECT {origin} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .expect("send CONNECT");
        let mut buf = [0u8; 256];
        let _ = client.read(&mut buf).await.expect("read CONNECT response");

        client
            .write_all(&build_client_hello_with_sni("evil.example"))
            .await
            .expect("send ClientHello");
        // The tunnel must close without echoing the hello back.
        let leftover = read_to_end(&mut client).await;
        assert!(
            leftover.is_empty(),
            "tunnel leaked bytes after SNI mismatch"
        );
        let mismatches: Vec<_> = sink
            .events()
            .into_iter()
            .filter(|e| e.event_type == ProxyEventType::SniMismatch)
            .collect();
        assert_eq!(mismatches.len(), 1);
        assert!(
            mismatches[0]
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("evil.example"),
            "mismatch detail must name the offending SNI"
        );
    }

    #[tokio::test]
    async fn a_malformed_request_line_gets_a_400_and_no_upstream_contact() {
        let (proxy, sink) = spawn_proxy(false, vec![], ProxyConfig::default()).await;
        let mut client = TcpStream::connect(proxy).await.expect("connect proxy");
        client
            .write_all(b"GET /origin-form-not-allowed HTTP/1.1\r\n\r\n")
            .await
            .expect("send request");
        let response = String::from_utf8_lossy(&read_to_end(&mut client).await).to_string();
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "got: {response}"
        );
        assert!(sink.events().is_empty());
    }
}
