use axum::{
    http::{header, HeaderMap},
    response::IntoResponse,
};

// Embed static files at compile time using std::include_str!
const INDEX_HTML: &str = include_str!("../../dashboard/index.html");
const APP_JS: &str = include_str!("../../dashboard/app.js");
const AEGIS_CSS: &str = include_str!("../../dashboard/aegis.css");

/// GET /dashboard/ — serves the index.html page
pub async fn serve_dashboard_index() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    // Simple double-submit CSRF cookie setup if needed
    headers.insert(
        header::SET_COOKIE,
        "aegis_csrf=csrf_secret_token_placeholder; Path=/; SameSite=Strict"
            .parse()
            .unwrap(),
    );
    (headers, INDEX_HTML)
}

/// GET /dashboard/app.js — serves the app.js script
pub async fn serve_dashboard_js() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/javascript; charset=utf-8".parse().unwrap(),
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
    (headers, AEGIS_CSS)
}
