# AI Skill: Axum API Patterns & Handlers (`skills/axum_patterns.md`)

This skill defines the HTTP handler structures, routing, state sharing, request extraction, and error response mappings when writing endpoints in Axum.

---

## 1. Routing and State Management

We use Axum's routing model to map endpoints and inject state (such as SQLite connections or Cedar Policy engines).

### Guidelines:
- **State Injection:** Inject the database connection pool or configuration state using Axum's `State`:
  ```rust
  use axum::{Router, routing::post, extract::State};

  pub fn app_router(pool: SqlitePool) -> Router {
      Router::new()
          .route("/v1/authorize", post(authorize_handler))
          .with_state(pool)
  }
  ```

---

## 2. Request Extraction

Handlers must extract JSON payloads and header credentials securely.

### Guidelines:
- **JSON Extraction:** Extract structured JSON bodies:
  ```rust
  use axum::Json;

  pub async fn authorize_handler(
      State(pool): State<SqlitePool>,
      Json(payload): Json<AuthRequest>,
  ) -> Result<Json<AuthResponse>, AppError> {
      ...
  }
  ```
- **Custom Header/Auth Extractors:** Create custom extractors to parse out the authenticated `tenant_id` and token from headers, avoiding duplicate authentication logic across endpoints.

---

## 3. Custom Error Response Mapping (`IntoResponse`)

Never return database errors or system error strings directly to the client (CWE-209 / Information Exposure). Map internal errors to standard HTTP status codes.

### Guidelines:
- **IntoResponse Implementation:** Implement `IntoResponse` for the application's error enum:
  ```rust
  use axum::response::{IntoResponse, Response};
  use axum::http::StatusCode;
  use axum::Json;

  pub enum AppError {
      Database(String),
      Unauthorized,
      InvalidPayload(String),
  }

  impl IntoResponse for AppError {
      fn into_response(self) -> Response {
          let (status, err_msg) = match self {
              AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
              AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized access token"),
              AppError::InvalidPayload(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
          };

          let body = Json(serde_json::json!({ "error": err_msg }));
          (status, body).into_response()
      }
  }
  ```

---

## 4. Telemetry and Middleware

Wrap the router with tower middleware to trace requests, handle timeouts, and manage CORS:
```rust
use tower_http::trace::TraceLayer;
use tower_http::cors::CorsLayer;

let app = app_router(pool)
    .layer(TraceLayer::new_for_http())
    .layer(CorsLayer::permissive());
```
Ensure all spans carry the trace context matching the active agent session.
