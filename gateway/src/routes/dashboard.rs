use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use serde_json::json;

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
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": "Invalid or missing CSRF token"})),
                    )
                        .into_response();
                }
            }
        }
    }

    next.run(request).await.into_response()
}

// Embed static files at compile time using std::include_str!
const INDEX_HTML: &str = include_str!("../../dashboard/index.html");
const APP_JS: &str = include_str!("../../dashboard/app.js");
const AEGIS_CSS: &str = include_str!("../../dashboard/aegis.css");

const CSP_VALUE: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss:; frame-ancestors 'none'";

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

    let html = INDEX_HTML.replace(
        "<head>",
        &format!("<head>\n  <meta name=\"csrf-token\" content=\"{}\">", token),
    );

    (headers, html)
}

/// GET /dashboard/app.js — serves the app.js script
pub async fn serve_dashboard_js() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/javascript; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        CSP_VALUE.parse().unwrap(),
    );
    (headers, APP_JS)
}

/// GET /dashboard/aegis.css — serves the aegis.css styling sheet
pub async fn serve_dashboard_css() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/css; charset=utf-8".parse().unwrap(),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        CSP_VALUE.parse().unwrap(),
    );
    (headers, AEGIS_CSS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_dashboard_index_csrf_and_csp() {
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
    }

    #[tokio::test]
    async fn test_csrf_middleware_behavior() {
        use axum::middleware;
        use axum::routing::post;
        use serde_json::json;

        async fn test_post_handler() -> impl IntoResponse {
            (StatusCode::OK, "success")
        }

        let app = axum::Router::new()
            .route("/test-post", post(test_post_handler))
            .layer(middleware::from_fn(super::csrf_validation_middleware));

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
