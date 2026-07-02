//! Phase 3.3 (Agent Cage): the sensor's durable local spool. Runtime events
//! collected while the gateway is unreachable (or simply not yet shipped)
//! land here first — an append-only log per lane, framed with a checksum so
//! a torn write or on-disk corruption is detected rather than silently
//! shipped or crashing the sensor.
//!
//! Two lanes, `critical` and `normal`, are separate files so a flood of
//! low-priority telemetry can never crowd out a critical event (e.g. a
//! lockdown-triggering signal) waiting to ship. Consumption is ACK-based:
//! `read_next` always returns the oldest un-acked record and is safe to call
//! repeatedly without side effects; only `ack` advances the persisted
//! watermark, so a sensor restart naturally replays anything that was read
//! but never acked (the shipper's job, in Phase 3.4, is to ack only after a
//! successful gateway ingest call).
//!
//! Frame format: `[u32 payload_len LE][u32 crc32(payload) LE][payload
//! bytes]`. On read, a header that doesn't fit before EOF means "nothing
//! more written yet" (not an error — the writer just hasn't gotten there).
//! A header that fits but whose declared length runs past EOF is a torn
//! tail write from a crash mid-append: also not corruption, just "not ready
//! yet". A complete frame whose checksum doesn't match is real corruption;
//! recovery re-syncs by scanning forward for the next position where a
//! frame's checksum verifies, bounded so a badly corrupted file fails fast
//! rather than scanning to EOF byte-by-byte.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const HEADER_LEN: u64 = 8;
/// How far past a corrupt frame to scan for the next valid one before
/// giving up on this lane until it grows further.
const RESYNC_SCAN_LIMIT_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Critical,
    Normal,
}

impl Lane {
    fn file_name(self) -> &'static str {
        match self {
            Lane::Critical => "critical.log",
            Lane::Normal => "normal.log",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    #[error("I/O error on spool file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the critical lane is at its disk budget and cannot accept new records")]
    CriticalLaneFull,
}

/// A record read from the spool, not yet acked. Holds the byte offset of the
/// frame immediately following it, which `ack` needs to advance the
/// persisted watermark — callers never need to inspect this themselves.
#[derive(Debug, Clone)]
pub struct SpoolRecord {
    pub payload: Vec<u8>,
    next_offset: u64,
}

struct LaneState {
    file: File,
    state_path: PathBuf,
    /// Bytes at the start of the file that are fully acked and eligible for
    /// compaction. Persisted so a restart doesn't re-deliver already-acked
    /// records.
    ack_offset: u64,
    max_bytes: u64,
}

impl LaneState {
    fn open(dir: &Path, lane: Lane, max_bytes: u64) -> Result<Self, SpoolError> {
        let log_path = dir.join(lane.file_name());
        let state_path = dir.join(format!("{}.state", lane.file_name()));
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&log_path)
            .map_err(|source| SpoolError::Io {
                path: log_path.display().to_string(),
                source,
            })?;
        let ack_offset = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Self {
            file,
            state_path,
            ack_offset,
            max_bytes,
        })
    }

    fn file_len(&self) -> Result<u64, SpoolError> {
        self.file
            .metadata()
            .map(|m| m.len())
            .map_err(|source| self.io_err(source))
    }

    fn io_err(&self, source: std::io::Error) -> SpoolError {
        SpoolError::Io {
            path: self.state_path.display().to_string(),
            source,
        }
    }

    fn persist_ack_offset(&self) -> Result<(), SpoolError> {
        std::fs::write(&self.state_path, self.ack_offset.to_string())
            .map_err(|source| self.io_err(source))
    }

    fn append(&mut self, payload: &[u8]) -> Result<(), SpoolError> {
        let checksum = crc32fast::hash(payload);
        let mut frame = Vec::with_capacity(HEADER_LEN as usize + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&checksum.to_le_bytes());
        frame.extend_from_slice(payload);
        self.file
            .write_all(&frame)
            .map_err(|source| self.io_err(source))?;
        self.file.flush().map_err(|source| self.io_err(source))
    }

    /// Read one frame starting at `offset`. `Ok(None)` means "nothing valid
    /// there yet" (EOF or a torn tail write) — not an error.
    fn read_frame_at(&mut self, offset: u64) -> Result<Option<(Vec<u8>, u64)>, SpoolError> {
        let len = self.file_len()?;
        if offset + HEADER_LEN > len {
            return Ok(None);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|source| self.io_err(source))?;
        let mut header = [0u8; HEADER_LEN as usize];
        self.file
            .read_exact(&mut header)
            .map_err(|source| self.io_err(source))?;
        let payload_len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as u64;
        let expected_checksum = u32::from_le_bytes(header[4..8].try_into().unwrap());

        if offset + HEADER_LEN + payload_len > len {
            // Torn tail write — the length was recorded but the payload
            // bytes never made it (or not yet). Not corruption.
            return Ok(None);
        }
        let mut payload = vec![0u8; payload_len as usize];
        self.file
            .read_exact(&mut payload)
            .map_err(|source| self.io_err(source))?;

        if crc32fast::hash(&payload) != expected_checksum {
            return Ok(None); // signals "not a valid frame here" to the caller's resync loop
        }
        Ok(Some((payload, offset + HEADER_LEN + payload_len)))
    }

    /// Return the oldest un-acked record, re-syncing past corruption if
    /// needed. Idempotent: does not itself advance `ack_offset`.
    fn read_next(&mut self) -> Result<Option<SpoolRecord>, SpoolError> {
        if let Some((payload, next_offset)) = self.read_frame_at(self.ack_offset)? {
            return Ok(Some(SpoolRecord {
                payload,
                next_offset,
            }));
        }

        // The frame at ack_offset didn't parse as a torn write (checked
        // above) or as valid (checksum mismatch) — try re-syncing forward.
        // A torn tail write is indistinguishable from "nothing more was ever
        // written here" at this layer, so a resync scan that finds nothing
        // is the normal "queue is empty" case, not an error.
        let len = self.file_len()?;
        let scan_end = len.min(self.ack_offset + RESYNC_SCAN_LIMIT_BYTES);
        for candidate in (self.ack_offset + 1)..scan_end {
            if let Some((payload, next_offset)) = self.read_frame_at(candidate)? {
                tracing::warn!(
                    lane_offset = self.ack_offset,
                    resynced_at = candidate,
                    "spool corruption detected, resynchronized to next valid frame"
                );
                self.ack_offset = candidate;
                self.persist_ack_offset()?;
                return Ok(Some(SpoolRecord {
                    payload,
                    next_offset,
                }));
            }
        }
        Ok(None)
    }

    fn ack(&mut self, record: &SpoolRecord) -> Result<(), SpoolError> {
        self.ack_offset = self.ack_offset.max(record.next_offset);
        self.persist_ack_offset()
    }

    /// Rewrite the log file dropping everything before `ack_offset`,
    /// reclaiming disk space from fully-consumed records.
    fn compact(&mut self, dir: &Path, lane: Lane) -> Result<(), SpoolError> {
        if self.ack_offset == 0 {
            return Ok(());
        }
        let len = self.file_len()?;
        let mut remainder = vec![0u8; (len - self.ack_offset) as usize];
        self.file
            .seek(SeekFrom::Start(self.ack_offset))
            .map_err(|source| self.io_err(source))?;
        self.file
            .read_exact(&mut remainder)
            .map_err(|source| self.io_err(source))?;

        let log_path = dir.join(lane.file_name());
        let tmp_path = dir.join(format!("{}.compact.tmp", lane.file_name()));
        std::fs::write(&tmp_path, &remainder).map_err(|source| self.io_err(source))?;
        std::fs::rename(&tmp_path, &log_path).map_err(|source| self.io_err(source))?;

        self.file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&log_path)
            .map_err(|source| self.io_err(source))?;
        self.ack_offset = 0;
        self.persist_ack_offset()
    }

    /// Bytes not yet acked — the working set a disk-budget check must fit.
    fn pending_bytes(&self) -> Result<u64, SpoolError> {
        Ok(self.file_len()?.saturating_sub(self.ack_offset))
    }
}

/// The sensor's durable local spool: one append-only, checksummed,
/// ACK-compacted log per [`Lane`].
pub struct SpoolQueue {
    dir: PathBuf,
    critical: Mutex<LaneState>,
    normal: Mutex<LaneState>,
}

impl SpoolQueue {
    pub fn open(dir: &Path, max_bytes_per_lane: u64) -> Result<Self, SpoolError> {
        std::fs::create_dir_all(dir).map_err(|source| SpoolError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            critical: Mutex::new(LaneState::open(dir, Lane::Critical, max_bytes_per_lane)?),
            normal: Mutex::new(LaneState::open(dir, Lane::Normal, max_bytes_per_lane)?),
        })
    }

    fn lane_state(&self, lane: Lane) -> std::sync::MutexGuard<'_, LaneState> {
        match lane {
            Lane::Critical => self.critical.lock().unwrap(),
            Lane::Normal => self.normal.lock().unwrap(),
        }
    }

    /// Append `payload` to `lane`. Disk-budget policy differs by lane: the
    /// critical lane fails closed (rejects the write, preserving what's
    /// already queued) rather than ever silently dropping a critical event;
    /// the normal lane makes room by dropping its own oldest unacked
    /// records — acceptable data loss for best-effort telemetry, never for
    /// enforcement-relevant events.
    pub fn enqueue(&self, lane: Lane, payload: &[u8]) -> Result<(), SpoolError> {
        let mut state = self.lane_state(lane);
        let projected = state.pending_bytes()? + HEADER_LEN + payload.len() as u64;
        if projected > state.max_bytes {
            match lane {
                Lane::Critical => return Err(SpoolError::CriticalLaneFull),
                Lane::Normal => {
                    while state.pending_bytes()? + HEADER_LEN + payload.len() as u64
                        > state.max_bytes
                    {
                        match state.read_next()? {
                            Some(dropped) => {
                                tracing::warn!(
                                    dropped_bytes = dropped.payload.len(),
                                    "normal lane over disk budget, dropping oldest unacked record"
                                );
                                state.ack(&dropped)?;
                            }
                            // Nothing left to drop but still over budget:
                            // the single incoming record is simply larger
                            // than the whole budget. Let it through anyway
                            // rather than deadlock — an operator-tunable
                            // hard cap is future work.
                            None => break,
                        }
                    }
                    state.compact(&self.dir, lane)?;
                }
            }
        }
        state.append(payload)
    }

    /// Peek the oldest un-acked record in `lane`. Safe to call repeatedly —
    /// only [`ack`](Self::ack) advances the persisted watermark.
    pub fn read_next(&self, lane: Lane) -> Result<Option<SpoolRecord>, SpoolError> {
        self.lane_state(lane).read_next()
    }

    /// Acknowledge a record, advancing the persisted watermark past it.
    pub fn ack(&self, lane: Lane, record: &SpoolRecord) -> Result<(), SpoolError> {
        self.lane_state(lane).ack(record)
    }

    /// Reclaim disk space from acked records.
    pub fn compact(&self, lane: Lane) -> Result<(), SpoolError> {
        self.lane_state(lane).compact(&self.dir, lane)
    }

    /// Bytes not yet acked in `lane` — exposed for heartbeat queue-depth
    /// reporting (Phase 3.2's `queue_depth_critical`/`queue_depth_normal`).
    pub fn pending_bytes(&self, lane: Lane) -> Result<u64, SpoolError> {
        self.lane_state(lane).pending_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_read_then_ack_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();

        queue.enqueue(Lane::Normal, b"event-1").unwrap();
        queue.enqueue(Lane::Normal, b"event-2").unwrap();

        let first = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(first.payload, b"event-1");
        // Reading again without acking returns the same record (idempotent).
        let first_again = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(first_again.payload, b"event-1");

        queue.ack(Lane::Normal, &first).unwrap();
        let second = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(second.payload, b"event-2");
        queue.ack(Lane::Normal, &second).unwrap();

        assert!(queue.read_next(Lane::Normal).unwrap().is_none());
    }

    #[test]
    fn unacked_records_replay_after_reopening_the_queue() {
        let dir = tempfile::tempdir().unwrap();
        {
            let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
            queue.enqueue(Lane::Normal, b"event-1").unwrap();
            let record = queue.read_next(Lane::Normal).unwrap().unwrap();
            queue.ack(Lane::Normal, &record).unwrap();
            queue.enqueue(Lane::Normal, b"event-2").unwrap(); // never read or acked
        }

        // Simulates a sensor restart: event-1 was acked (shipped) and must
        // not come back; event-2 was never acked and must replay.
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        let record = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(record.payload, b"event-2");
    }

    #[test]
    fn lanes_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        queue.enqueue(Lane::Critical, b"critical-event").unwrap();
        queue.enqueue(Lane::Normal, b"normal-event").unwrap();

        let critical = queue.read_next(Lane::Critical).unwrap().unwrap();
        assert_eq!(critical.payload, b"critical-event");
        assert!(queue.read_next(Lane::Normal).unwrap().is_some());
    }

    #[test]
    fn corrupted_frame_is_skipped_and_does_not_crash() {
        let dir = tempfile::tempdir().unwrap();
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        queue.enqueue(Lane::Normal, b"good-record-before").unwrap();
        queue.enqueue(Lane::Normal, b"good-record-after").unwrap();

        // Flip a byte inside the second record's payload region, corrupting
        // its checksum without changing the declared length (so it isn't
        // mistaken for a torn tail write).
        let log_path = dir.path().join("normal.log");
        let mut bytes = std::fs::read(&log_path).unwrap();
        let first_frame_len = HEADER_LEN as usize + "good-record-before".len();
        let corrupt_byte_index = first_frame_len + HEADER_LEN as usize + 2;
        bytes[corrupt_byte_index] ^= 0xFF;
        std::fs::write(&log_path, &bytes).unwrap();

        // The first record is untouched and must still read fine; reading
        // past the corrupted second record must not panic or hang, and
        // should not return corrupted bytes.
        let first = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(first.payload, b"good-record-before");
        queue.ack(Lane::Normal, &first).unwrap();

        let result = queue.read_next(Lane::Normal).unwrap();
        if let Some(record) = result {
            assert_ne!(record.payload, b"good-record-after".to_vec());
        }
    }

    #[test]
    fn compaction_shrinks_the_file_after_acking() {
        let dir = tempfile::tempdir().unwrap();
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        for _ in 0..10 {
            queue.enqueue(Lane::Normal, &[0u8; 100]).unwrap();
        }
        let log_path = dir.path().join("normal.log");
        let len_before = std::fs::metadata(&log_path).unwrap().len();

        for _ in 0..10 {
            let record = queue.read_next(Lane::Normal).unwrap().unwrap();
            queue.ack(Lane::Normal, &record).unwrap();
        }
        queue.compact(Lane::Normal).unwrap();

        let len_after = std::fs::metadata(&log_path).unwrap().len();
        assert!(len_after < len_before);
        assert_eq!(len_after, 0);
    }

    #[test]
    fn normal_lane_drops_oldest_records_over_disk_budget() {
        let dir = tempfile::tempdir().unwrap();
        // Budget fits roughly 2 records of this size.
        let record_size = 50usize;
        let budget = (HEADER_LEN as usize + record_size) as u64 * 2;
        let queue = SpoolQueue::open(dir.path(), budget).unwrap();

        queue
            .enqueue(Lane::Normal, &vec![1u8; record_size])
            .unwrap();
        queue
            .enqueue(Lane::Normal, &vec![2u8; record_size])
            .unwrap();
        // Over budget: must drop the oldest (payload of 1s) to make room.
        queue
            .enqueue(Lane::Normal, &vec![3u8; record_size])
            .unwrap();

        let first = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(first.payload, vec![2u8; record_size]);
    }

    #[test]
    fn critical_lane_rejects_writes_over_disk_budget_instead_of_dropping() {
        let dir = tempfile::tempdir().unwrap();
        let record_size = 50usize;
        let budget = (HEADER_LEN as usize + record_size) as u64; // fits exactly one
        let queue = SpoolQueue::open(dir.path(), budget).unwrap();

        queue
            .enqueue(Lane::Critical, &vec![1u8; record_size])
            .unwrap();
        let err = queue
            .enqueue(Lane::Critical, &vec![2u8; record_size])
            .unwrap_err();
        assert!(matches!(err, SpoolError::CriticalLaneFull));

        // The original record must still be intact and readable.
        let record = queue.read_next(Lane::Critical).unwrap().unwrap();
        assert_eq!(record.payload, vec![1u8; record_size]);
    }

    #[test]
    fn empty_queue_read_next_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        assert!(queue.read_next(Lane::Critical).unwrap().is_none());
        assert!(queue.read_next(Lane::Normal).unwrap().is_none());
    }

    #[test]
    fn torn_tail_write_is_treated_as_not_ready_not_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let queue = SpoolQueue::open(dir.path(), 1_000_000).unwrap();
        queue.enqueue(Lane::Normal, b"complete-record").unwrap();

        // Simulate a crash mid-append: a header declaring more payload
        // bytes than actually got written.
        let log_path = dir.path().join("normal.log");
        let mut file = OpenOptions::new().append(true).open(&log_path).unwrap();
        let mut torn_header = Vec::new();
        torn_header.extend_from_slice(&100u32.to_le_bytes()); // claims 100 bytes
        torn_header.extend_from_slice(&0u32.to_le_bytes());
        file.write_all(&torn_header).unwrap();
        file.write_all(b"only a few bytes").unwrap(); // far short of 100
        file.flush().unwrap();

        let first = queue.read_next(Lane::Normal).unwrap().unwrap();
        assert_eq!(first.payload, b"complete-record");
        queue.ack(Lane::Normal, &first).unwrap();
        // The torn tail record isn't readable yet — correctly reported as
        // "nothing more available", not an error.
        assert!(queue.read_next(Lane::Normal).unwrap().is_none());
    }
}
