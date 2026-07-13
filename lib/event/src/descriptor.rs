use std::{error::Error, fmt, ops::Range};

/// Maximum payload length addressable by one telemetry descriptor.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// Fixed descriptor passed through the SPSC event fabric.
///
/// Payload bytes remain in an independently owned arena page. This structure is
/// an in-memory prototype ABI; it is not yet a stable wire or disk format.
#[repr(C, align(32))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TelemetryDescriptor {
    pub sequence: u64,
    pub arena_generation: u32,
    pub arena_id: u16,
    pub flags: u16,
    pub offset: u32,
    pub len: u32,
    pub crc32c: u32,
    pub schema_id: u32,
}

impl TelemetryDescriptor {
    /// Validates the bounded payload range before an arena page is sliced.
    pub fn checked_payload_range(&self, page_len: usize) -> Result<Range<usize>, DescriptorError> {
        let len = self.len as usize;
        if len > MAX_FRAME_BYTES {
            return Err(DescriptorError::FrameTooLarge {
                len,
                max: MAX_FRAME_BYTES,
            });
        }

        let end =
            self.offset
                .checked_add(self.len)
                .ok_or(DescriptorError::OffsetLengthOverflow {
                    offset: self.offset,
                    len: self.len,
                })? as usize;
        if end > page_len {
            return Err(DescriptorError::OutOfBounds { end, page_len });
        }

        Ok(self.offset as usize..end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    FrameTooLarge { len: usize, max: usize },
    OffsetLengthOverflow { offset: u32, len: u32 },
    OutOfBounds { end: usize, page_len: usize },
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooLarge { len, max } => {
                write!(f, "telemetry frame length {len} exceeds limit {max}")
            }
            Self::OffsetLengthOverflow { offset, len } => {
                write!(
                    f,
                    "telemetry descriptor offset {offset} + length {len} overflows"
                )
            }
            Self::OutOfBounds { end, page_len } => {
                write!(
                    f,
                    "telemetry descriptor ends at {end}, beyond page length {page_len}"
                )
            }
        }
    }
}

impl Error for DescriptorError {}
