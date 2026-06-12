#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz `aegis_canon::canonicalize_json` (TEST-002, #1162): feed arbitrary
// bytes through `serde_json::from_slice` and canonicalize whatever valid
// JSON results. Must never panic for any input that parses as JSON.
fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = aegis_canon::canonicalize_json(value);
    }
});
