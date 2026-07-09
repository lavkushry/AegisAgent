//! Secret-shaped substring scrubbing for previews and failure details.
//!
//! Marker list is kept in sync with the gateway's `UNREDACTED_MARKERS`
//! (`src/src/routes/prompt_capture.rs`) and the Python SDK's
//! `prompt_capture._SECRET_PATTERNS` so a body that would be rejected by
//! ingest never ships from this adapter either.

/// Deliberately narrow (well-known token prefixes) to avoid false positives
/// on ordinary prose. Compared case-insensitively via lowercase scan.
const UNREDACTED_MARKERS: &[&str] = &[
    "bearer ",
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "akia",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "-----begin",
];

const REDACTED: &str = "[REDACTED]";

/// Default max length for a redacted prompt preview (matches SDK).
pub const DEFAULT_MAX_PREVIEW_LEN: usize = 500;

/// True if `text` still contains an obvious secret-shaped substring.
pub fn looks_unredacted(text: &str) -> bool {
    let lower = text.to_lowercase();
    UNREDACTED_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Scrub secret-shaped substrings, then truncate to `max_len`.
///
/// Truncation happens after scrubbing so a secret straddling the truncation
/// boundary is still caught. Case-insensitive replacement keeps the
/// surrounding text intact.
pub fn redact_text(text: &str, max_len: usize) -> String {
    let mut out = text.to_string();
    // Walk markers against a lowercased view, replace in the original by
    // index ranges discovered via lowercase search (ASCII prefixes only).
    let lower = out.to_lowercase();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for marker in UNREDACTED_MARKERS {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(marker) {
            let abs = start + pos;
            // Extend the redaction through the following non-whitespace run
            // so `sk-abc123` becomes a single [REDACTED], not ` [REDACTED]abc123`.
            let mut end = abs + marker.len();
            let bytes = out.as_bytes();
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() && bytes[end] != b'"' {
                end += 1;
            }
            // For "bearer " the marker already includes a trailing space; the
            // token follows. Consume the token as well.
            if marker.ends_with(' ') {
                while end < bytes.len() && !bytes[end].is_ascii_whitespace() && bytes[end] != b'"'
                {
                    end += 1;
                }
            }
            ranges.push((abs, end));
            start = end;
            if start >= lower.len() {
                break;
            }
        }
    }
    ranges.sort_by_key(|(s, _)| *s);
    // Merge overlapping ranges, then replace from the end so indices stay valid.
    let merged = merge_ranges(ranges);
    for (start, end) in merged.into_iter().rev() {
        if start < out.len() && end <= out.len() && start < end {
            out.replace_range(start..end, REDACTED);
        }
    }
    if out.len() > max_len {
        out.truncate(max_len);
    }
    out
}

fn merge_ranges(ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    if ranges.is_empty() {
        return ranges;
    }
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0];
    for r in ranges.into_iter().skip(1) {
        if r.0 <= cur.1 {
            cur.1 = cur.1.max(r.1);
        } else {
            merged.push(cur);
            cur = r;
        }
    }
    merged.push(cur);
    merged
}

/// Convenience: scrub with the default preview length.
pub fn redact_preview(text: &str) -> String {
    redact_text(text, DEFAULT_MAX_PREVIEW_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_unredacted_detects_openai_and_github_tokens() {
        assert!(looks_unredacted("key=sk-abc123DEF"));
        assert!(looks_unredacted("Authorization: Bearer tok_xyz"));
        assert!(looks_unredacted("ghp_deadbeef"));
        assert!(!looks_unredacted("Summarize the attached file please"));
    }

    #[test]
    fn redact_text_scrubs_secrets_and_bounds_length() {
        let raw = format!("Use token sk-{} and continue", "a".repeat(80));
        let redacted = redact_text(&raw, 40);
        assert!(!looks_unredacted(&redacted));
        assert!(redacted.contains(REDACTED));
        assert!(redacted.len() <= 40);
    }

    #[test]
    fn redact_text_scrubs_pem_and_slack_tokens() {
        let raw = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\nxoxb-1234-secret";
        let redacted = redact_preview(raw);
        assert!(!looks_unredacted(&redacted));
        assert!(redacted.contains(REDACTED));
    }
}
