use crate::error::StatusError;
use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use std::path::{Path, PathBuf};

/// Middleware: CSRF protection for all state-changing endpoints (POST/PUT/PATCH/DELETE) (#1308).
/// Enforces Double-Submit Cookie validation if the `aegis_csrf` cookie is present on the request.
pub async fn csrf_validation_middleware(request: Request<Body>, next: Next) -> impl IntoResponse {
    let method = request.method().clone();
    let is_state_changing = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );

    if is_state_changing {
        let mut csrf_cookie_val = None;
        if let Some(cookie_header) = request.headers().get(header::COOKIE) {
            if let Ok(cookie_str) = cookie_header.to_str() {
                for cookie in cookie_str.split(';') {
                    let parts: Vec<&str> = cookie.split('=').map(|s| s.trim()).collect();
                    if parts.len() == 2 && parts[0] == "aegis_csrf" {
                        csrf_cookie_val = Some(parts[1].to_string());
                        break;
                    }
                }
            }
        }

        if let Some(cookie_val) = csrf_cookie_val {
            let csrf_header_val = request
                .headers()
                .get("X-CSRF-Token")
                .and_then(|v| v.to_str().ok());

            match csrf_header_val {
                Some(header_val) if header_val == cookie_val => {
                    // Valid CSRF token, allow request to proceed
                }
                _ => {
                    return StatusError::forbidden("Invalid or missing CSRF token").into_response();
                }
            }
        }
    }

    next.run(request).await.into_response()
}

const CSP_VALUE: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss: http: https:; img-src 'self' data: blob:; frame-ancestors 'none'";

/// Resolve the on-disk directory of the dashboard SPA static export.
///
/// Precedence (Phase E — Bun SPA only; `ui/dist` is a path alias used by the
/// Docker image which copies `ui-next/dist` to both locations):
/// 1. `AEGIS_UI_DIST` — absolute or relative path override
/// 2. `AEGIS_UI_BUNDLE=legacy` → `ui/dist` (image path alias)
/// 3. `AEGIS_UI_BUNDLE=next` → `ui-next/dist` (Bun SPA)
/// 4. Default: prefer `ui-next/dist` if `index.html` exists, else `ui/dist`
pub fn dashboard_dist_dir() -> PathBuf {
    dashboard_dist_dir_from_env(
        std::env::var("AEGIS_UI_DIST").ok(),
        std::env::var("AEGIS_UI_BUNDLE").ok(),
        |p| Path::new(p).join("index.html").is_file(),
    )
}

/// Pure resolver for tests (inject existence check).
pub fn dashboard_dist_dir_from_env(
    dist_override: Option<String>,
    bundle: Option<String>,
    index_exists: impl Fn(&str) -> bool,
) -> PathBuf {
    if let Some(path) = dist_override {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    match bundle.as_deref().map(str::trim).unwrap_or("") {
        "legacy" => PathBuf::from("ui/dist"),
        "next" => PathBuf::from("ui-next/dist"),
        _ => {
            if index_exists("ui-next/dist") {
                PathBuf::from("ui-next/dist")
            } else {
                PathBuf::from("ui/dist")
            }
        }
    }
}

/// GET /dashboard/ — serves the index.html page
pub async fn serve_dashboard_index() -> impl IntoResponse {
    let token = uuid::Uuid::new_v4().to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        CSP_VALUE.parse().unwrap(),
    );
    let cookie_val = format!("aegis_csrf={}; Path=/; SameSite=Strict; HttpOnly", token);
    headers.insert(header::SET_COOKIE, cookie_val.parse().unwrap());

    let index_path = dashboard_dist_dir().join("index.html");
    match tokio::fs::read_to_string(&index_path).await {
        Ok(html) => {
            let html_with_csrf = html.replace(
                "<head>",
                &format!("<head>\n  <meta name=\"csrf-token\" content=\"{}\">", token),
            );
            (headers, html_with_csrf).into_response()
        }
        Err(e) => {
            tracing::error!(
                "Failed to read dashboard index.html at {}: {:?}",
                index_path.display(),
                e
            );
            StatusError::not_found(
                "Dashboard assets not found. Build ui-next (`bun run build`) or set AEGIS_UI_DIST / AEGIS_UI_BUNDLE.",
            )
            .into_response()
        }
    }
}

/// GET /dashboard/*path — serves static assets or falls back to index.html for SPA routing
pub async fn serve_dashboard_static(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl IntoResponse {
    let path = path.trim_start_matches('/');
    if path.contains("..") {
        return StatusError::forbidden("Access denied").into_response();
    }

    let file_path = dashboard_dist_dir().join(path);

    if file_path.is_file() {
        match tokio::fs::read(&file_path).await {
            Ok(bytes) => {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::HeaderName::from_static("content-security-policy"),
                    CSP_VALUE.parse().unwrap(),
                );

                // Detect Content-Type
                let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                let content_type = match ext {
                    "html" => "text/html; charset=utf-8",
                    "js" | "mjs" => "application/javascript; charset=utf-8",
                    "css" => "text/css; charset=utf-8",
                    "svg" => "image/svg+xml",
                    "ico" => "image/x-icon",
                    "png" => "image/png",
                    "jpg" | "jpeg" => "image/jpeg",
                    "map" => "application/json; charset=utf-8",
                    "json" => "application/json; charset=utf-8",
                    _ => "application/octet-stream",
                };
                headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());

                (headers, bytes).into_response()
            }
            Err(e) => {
                tracing::error!("Failed to read static file {}: {:?}", path, e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        // Fallback to index.html for SPA client-side routing
        serve_dashboard_index().await.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn dist_override_wins() {
        let dir =
            dashboard_dist_dir_from_env(Some("/custom/out".into()), Some("legacy".into()), |_| {
                true
            });
        assert_eq!(dir, PathBuf::from("/custom/out"));
    }

    #[test]
    fn bundle_legacy_and_next() {
        assert_eq!(
            dashboard_dist_dir_from_env(None, Some("legacy".into()), |_| true),
            PathBuf::from("ui/dist")
        );
        assert_eq!(
            dashboard_dist_dir_from_env(None, Some("next".into()), |_| false),
            PathBuf::from("ui-next/dist")
        );
    }

    #[test]
    fn default_prefers_next_when_index_exists() {
        assert_eq!(
            dashboard_dist_dir_from_env(None, None, |p| p == "ui-next/dist"),
            PathBuf::from("ui-next/dist")
        );
        assert_eq!(
            dashboard_dist_dir_from_env(None, None, |_| false),
            PathBuf::from("ui/dist")
        );
    }

    #[tokio::test]
    async fn test_dashboard_index_csrf_and_csp() {
        // Prefer ui/dist so the existing test fixture path still works even if
        // a local ui-next/dist is present on the developer machine.
        // Safety: setenv is process-global; only this test file touches these keys.
        std::env::set_var("AEGIS_UI_BUNDLE", "legacy");
        let _ = tokio::fs::create_dir_all("ui/dist").await;
        let _ = tokio::fs::write(
            "ui/dist/index.html",
            "<html><head></head><body></body></html>",
        )
        .await;

        let response = serve_dashboard_index().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Check CSP header presence
        let csp = response
            .headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));

        // Check aegis_csrf cookie presence
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.contains("aegis_csrf="));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("HttpOnly"));

        // Check meta tag injection
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains("<meta name=\"csrf-token\""));

        std::env::remove_var("AEGIS_UI_BUNDLE");
    }

    #[tokio::test]
    async fn test_csrf_middleware_behavior() {
        use axum::middleware;
        use axum::routing::post;

        async fn test_post_handler() -> impl IntoResponse {
            (StatusCode::OK, "success")
        }

        let app = axum::Router::new()
            .route("/test-post", post(test_post_handler))
            .layer(middleware::from_fn(csrf_validation_middleware));

        // Case 1: Post request WITHOUT csrf cookie -> should succeed (backwards compatibility for SDKs)
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test-post")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Case 2: Post request WITH csrf cookie but WITHOUT X-CSRF-Token header -> should fail with 403
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test-post")
            .header(header::COOKIE, "aegis_csrf=some_token_123")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Case 3: Post request WITH csrf cookie and MISMATCHING X-CSRF-Token header -> should fail with 403
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test-post")
            .header(header::COOKIE, "aegis_csrf=some_token_123")
            .header("X-CSRF-Token", "wrong_token_456")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Case 4: Post request WITH csrf cookie and MATCHING X-CSRF-Token header -> should succeed
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test-post")
            .header(header::COOKIE, "aegis_csrf=some_token_123")
            .header("X-CSRF-Token", "some_token_123")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
