//! Standalone exporter for the gateway's OpenAPI 3.0 spec (#1198, DOC-003).
//!
//! `ApiDoc::openapi()` is pure compile-time route metadata (utoipa derive
//! macros) — no database, no running server, no network I/O — so this binary
//! can run in CI to produce a static `openapi.json` snapshot for the
//! Redoc-rendered API reference published to GitHub Pages, without spinning
//! up the gateway itself. Mirrors the live `GET /v1/openapi.json` handler
//! (`gateway::routes::get_openapi_spec`) byte-for-byte, since both serialize
//! the same `ApiDoc::openapi()` value.
//!
//! Usage: `cargo run --release --bin export_openapi > docs/api/openapi.json`

use gateway::routes::openapi::ApiDoc;
use utoipa::OpenApi;

/// Pulled out of `main` so the test below exercises the exact serialization
/// path this binary's stdout depends on, without needing to spawn a process.
fn render() -> String {
    let spec = ApiDoc::openapi();
    serde_json::to_string_pretty(&spec).expect("ApiDoc::openapi() must serialize")
}

fn main() {
    println!("{}", render());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1198: the exported snapshot must be valid, non-trivial OpenAPI JSON —
    /// guards against `ApiDoc::openapi()` ever becoming unserializable or the
    /// path list silently dropping to empty, which would publish a broken or
    /// empty Redoc page with no useful error at deploy time.
    #[test]
    fn render_produces_valid_openapi_json_with_documented_paths() {
        let json = render();
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("output must be valid JSON");
        assert_eq!(parsed["openapi"], "3.0.3");
        assert_eq!(parsed["info"]["title"], "AegisAgent Control Plane API");
        let paths = parsed["paths"]
            .as_object()
            .expect("paths must be a JSON object");
        assert!(
            !paths.is_empty(),
            "exported spec must document at least one path"
        );
    }
}
