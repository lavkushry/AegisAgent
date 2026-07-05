//! OpenAPI ↔ Axum route parity helpers (#1607).
//!
//! Compares path templates registered on the `/v1` API router (see `api_routes`
//! in `main.rs`) plus top-level health probes against `ApiDoc::openapi()` paths.

use std::collections::BTreeSet;

use utoipa::OpenApi;

use super::openapi::ApiDoc;

/// Health/probe routes registered outside the `/v1` nest but documented in OpenAPI.
const TOP_LEVEL_DOCUMENTED_PATHS: &[&str] = &["/health", "/livez", "/readyz", "/startupz"];

/// Path templates from `api_routes()` in `main.rs`, parsed at compile time so
/// the parity test always diffs against the same source the binary uses.
fn api_routes_source() -> &'static str {
    let main_rs = include_str!("../main.rs");
    let start = main_rs
        .find("fn api_routes()")
        .expect("api_routes() must exist in main.rs");
    let end = main_rs[start..]
        .find("fn load_certs")
        .expect("load_certs() must follow api_routes() in main.rs");
    &main_rs[start..start + end]
}

/// Extract quoted path literals from `.route("...", ...)` registrations.
pub(crate) fn parse_route_path_templates(source: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let mut rest = source;
    while let Some(idx) = rest.find(".route(") {
        rest = &rest[idx + ".route(".len()..];
        rest = rest.trim_start();
        let Some(close_quote) = rest[1..].find('"') else {
            break;
        };
        let template = &rest[1..1 + close_quote];
        paths.insert(normalize_axum_template(template));
        rest = &rest[1 + close_quote + 1..];
    }
    paths
}

/// Convert Axum `:param` segments to OpenAPI `{param}` form.
fn normalize_axum_template(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    let mut chars = path.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == ':' {
            out.push('{');
            while let Some(&next) = chars.peek() {
                if next.is_ascii_alphanumeric() || next == '_' {
                    out.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            out.push('}');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Full path templates served by the gateway and expected in OpenAPI.
pub(crate) fn registered_axum_path_templates() -> BTreeSet<String> {
    let mut paths = parse_route_path_templates(api_routes_source())
        .into_iter()
        .map(|p| format!("/v1{p}"))
        .collect::<BTreeSet<_>>();
    paths.extend(TOP_LEVEL_DOCUMENTED_PATHS.iter().map(|p| (*p).to_string()));
    paths
}

/// Path templates declared in `ApiDoc::openapi()`.
pub(crate) fn openapi_path_templates() -> BTreeSet<String> {
    ApiDoc::openapi().paths.paths.keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openapi_path_templates_match_registered_axum_routes() {
        let axum_paths = registered_axum_path_templates();
        let openapi_paths = openapi_path_templates();

        let only_axum: Vec<_> = axum_paths.difference(&openapi_paths).collect();
        let only_openapi: Vec<_> = openapi_paths.difference(&axum_paths).collect();

        assert!(
            only_axum.is_empty(),
            "Axum routes missing from OpenAPI spec: {only_axum:?}"
        );
        assert!(
            only_openapi.is_empty(),
            "OpenAPI paths with no matching Axum route: {only_openapi:?}"
        );
    }
}
