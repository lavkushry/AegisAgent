//! Minimal host network collector (Wave A).
//!
//! For processes already discovered via `AEGIS_RUN_ID` (see
//! [`crate::process_collector`]), inspect established TCP sockets and
//! emit `network_connection` runtime events with **remote endpoint only**
//! (ip:port). No payloads, no local bind noise flood (only ESTABLISHED).
//!
//! Linux: `/proc/net/tcp{,6}` + `/proc/<pid>/fd` socket inode correlation.
//! Other OSes: no-op.
//!
//! Fail-closed privacy: never logs full `/proc` dumps; events carry
//! identifiers + remote endpoint string only.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;

use crate::gateway_client::RuntimeEventPayload;
use crate::process_collector::{scan_host_aegis_processes, DiscoveredProcess};
use crate::spool::{Lane, SpoolQueue};

/// TCP state ESTABLISHED in `/proc/net/tcp` (hex).
const TCP_ESTABLISHED: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnKey {
    run_id: String,
    remote: String,
}

/// Emits first-seen established TCP remotes for Aegis-marked processes.
pub struct NetCollector {
    /// Connections already announced this process lifetime.
    seen: Mutex<HashSet<ConnKey>>,
}

impl NetCollector {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Scan sockets for Aegis-marked processes and spool new connection events.
    pub fn poll(&self, spool: &SpoolQueue) {
        let processes = scan_host_aegis_processes();
        if processes.is_empty() {
            return;
        }
        let table = load_tcp_tables();
        if table.is_empty() {
            return;
        }

        for proc in &processes {
            let inodes = socket_inodes_for_pid(proc.pid);
            for inode in inodes {
                let Some(remote) = table.get(&inode) else {
                    continue;
                };
                let key = ConnKey {
                    run_id: proc.run_id.clone(),
                    remote: remote.clone(),
                };
                let mut seen = self.seen.lock().expect("net collector lock");
                if !seen.insert(key) {
                    continue;
                }
                drop(seen);
                enqueue_connection_event(spool, proc, remote);
            }
        }
    }
}

impl Default for NetCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn enqueue_connection_event(spool: &SpoolQueue, proc: &DiscoveredProcess, remote: &str) {
    let payload = RuntimeEventPayload {
        event_id: format!(
            "sensor-net-{}-{}-{}",
            proc.run_id,
            remote.replace([':', '.'], "-"),
            Utc::now().timestamp_millis()
        ),
        event_type: "network_connection".to_string(),
        severity: Some("info".to_string()),
        run_id: Some(proc.run_id.clone()),
        sandbox_id: proc.sandbox_id.clone(),
        source_component: "aegis-node-sensor".to_string(),
        reason: Some(format!("pid={} remote={}", proc.pid, remote)),
        observed_at: Some(Utc::now()),
        ..Default::default()
    };
    match serde_json::to_vec(&payload) {
        Ok(bytes) => {
            if let Err(e) = spool.enqueue(Lane::Normal, &bytes) {
                tracing::warn!(error = %e, "failed to spool network_connection event");
            }
        }
        Err(e) => tracing::warn!(error = %e, "failed to serialize network_connection event"),
    }
}

/// inode → remote "ip:port" for ESTABLISHED TCP sockets.
fn load_tcp_tables() -> HashMap<u64, String> {
    #[cfg(target_os = "linux")]
    {
        let mut map = HashMap::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = fs::read_to_string(path) {
                parse_proc_net_tcp(&text, path.ends_with("tcp6"), &mut map);
            }
        }
        map
    }
    #[cfg(not(target_os = "linux"))]
    {
        HashMap::new()
    }
}

/// Parse `/proc/net/tcp` or `tcp6` body into inode → remote endpoint.
pub fn parse_proc_net_tcp(text: &str, is_v6: bool, out: &mut HashMap<u64, String>) {
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue; // header
        }
        if let Some((inode, remote)) = parse_tcp_line(line, is_v6) {
            out.insert(inode, remote);
        }
    }
}

/// One data line of `/proc/net/tcp[6]`.
pub fn parse_tcp_line(line: &str, is_v6: bool) -> Option<(u64, String)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    // local rem st ... inode (inode is typically column 9, 0-based index 9)
    if cols.len() < 10 {
        return None;
    }
    let st = u8::from_str_radix(cols[3], 16).ok()?;
    if st != TCP_ESTABLISHED {
        return None;
    }
    let remote = parse_proc_addr(cols[2], is_v6)?;
    let inode: u64 = cols[9].parse().ok()?;
    if inode == 0 {
        return None;
    }
    Some((inode, remote))
}

/// `hexIP:hexPort` from /proc (little-endian words for IPv4).
pub fn parse_proc_addr(field: &str, is_v6: bool) -> Option<String> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if is_v6 {
        let ip = parse_hex_ipv6(ip_hex)?;
        Some(format!("[{ip}]:{port}"))
    } else {
        let ip = parse_hex_ipv4(ip_hex)?;
        Some(format!("{ip}:{port}"))
    }
}

pub fn parse_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    // /proc stores little-endian
    Some(Ipv4Addr::from(n.to_le_bytes()))
}

pub fn parse_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    // Four little-endian 32-bit words concatenated.
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        let n = u32::from_str_radix(s, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&n.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn socket_inodes_for_pid(pid: i32) -> HashSet<u64> {
    #[cfg(target_os = "linux")]
    {
        socket_inodes_for_pid_in(Path::new("/proc"), pid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        HashSet::new()
    }
}

/// Testable fd walk: `proc_root/<pid>/fd/*` → socket inodes.
pub fn socket_inodes_for_pid_in(proc_root: &Path, pid: i32) -> HashSet<u64> {
    let mut out = HashSet::new();
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let Ok(entries) = fs::read_dir(fd_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        if let Some(inode) = parse_socket_inode_link(&link) {
            out.insert(inode);
        }
    }
    out
}

pub fn parse_socket_inode_link(path: &Path) -> Option<u64> {
    let s = path.to_str()?;
    // "socket:[12345]"
    let rest = s.strip_prefix("socket:[")?.strip_suffix(']')?;
    rest.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_hex_ipv4_loopback() {
        // 0100007F = 127.0.0.1 little-endian
        assert_eq!(
            parse_hex_ipv4("0100007F").unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
    }

    #[test]
    fn parse_tcp_line_established() {
        // Synthetic /proc/net/tcp line (whitespace-separated).
        let line = "   0: 0100007F:0035 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 20 0 0 10 0";
        let (inode, remote) = parse_tcp_line(line, false).unwrap();
        assert_eq!(inode, 123456);
        assert_eq!(remote, "127.0.0.1:8080");
    }

    #[test]
    fn parse_tcp_line_skips_non_established() {
        let line = "   0: 0100007F:0035 0100007F:1F90 0A 00000000:00000000 00:00000000 00000000  1000        0 123456 1 0000000000000000 20 0 0 10 0";
        assert!(parse_tcp_line(line, false).is_none()); // 0A = LISTEN
    }

    #[test]
    fn parse_proc_net_tcp_table() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n\
   1: 0100007F:AB12 0A00020A:0050 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 20 0 0 10 0\n";
        let mut map = HashMap::new();
        parse_proc_net_tcp(text, false, &mut map);
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&999).map(String::as_str), Some("10.2.0.10:80"));
    }

    #[test]
    fn parse_socket_inode_link_ok() {
        assert_eq!(
            parse_socket_inode_link(Path::new("socket:[4242]")),
            Some(4242)
        );
        assert!(parse_socket_inode_link(Path::new("/dev/null")).is_none());
    }

    #[test]
    fn socket_inodes_for_pid_in_fake_proc() {
        let root = tempdir().unwrap();
        let fd = root.path().join("7").join("fd");
        fs::create_dir_all(&fd).unwrap();
        // Symlink names don't matter; target string is what we parse.
        // On platforms that support it:
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let _ = symlink("socket:[777]", fd.join("3"));
            let _ = symlink("/dev/null", fd.join("1"));
            let set = socket_inodes_for_pid_in(root.path(), 7);
            assert!(set.contains(&777));
            assert_eq!(set.len(), 1);
        }
    }

    #[test]
    fn poll_with_no_aegis_processes_is_harmless() {
        let collector = NetCollector::new();
        let spool_dir = tempdir().unwrap();
        let spool = SpoolQueue::open(spool_dir.path(), 1_000_000).unwrap();
        collector.poll(&spool);
    }
}
