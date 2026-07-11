//! OIDC console login routes (roadmap: "OIDC/SAML for console/admin").
//!
//! Three routes, all fail closed with 501 when `AppState.oidc` is `None`
//! (i.e. the `AEGIS_OIDC_*` env vars are unset — see `crate::oidc`):
//!
//! - `GET /v1/auth/oidc/login` — start a plain login attempt (no prior auth).
//! - `POST /v1/oidc/link/start` — authenticated; start a "link my identity to
//!   my tenant" flow, returning the IdP URL as JSON so ui-next can carry its
//!   existing bearer token on the initiating request (a plain `<a>` /
//!   redirect can't attach an Authorization header).
//! - `GET /v1/auth/oidc/callback` — the IdP redirects here with `code`/`state`.
//!
//! There is no auto-provisioning anywhere in this file: an unrecognized
//! `(issuer, subject)` at plain login fails closed (redirects to the UI with
//! `#error=identity_not_linked`), it never creates a tenant or guesses one.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::error::StatusError;
use crate::oidc::{OidcFlowState, OIDC_STATE_COOKIE_NAME};
use crate::routes::{jwt_signing_secret, mint_jwt, AppState, TenantId};

/// Login/link tokens are single-use and only need to survive one redirect
/// round trip; five minutes is generous slack for a slow IdP login form
/// without leaving a long-lived stray cookie behind.
const OIDC_FLOW_COOKIE_MAX_AGE_SECS: i64 = 300;

/// The flow-state cookie is HMAC-tagged with this same secret (see
/// `OidcFlowState::encode`/`decode`) — reusing `AEGIS_JWT_SECRET` rather than
/// requiring a second configured secret for OIDC login to work. Returns
/// `None` if `AEGIS_JWT_SECRET` isn't usable, in which case OIDC login must
/// be treated as entirely unavailable: minting the final JWT would fail
/// anyway, and a cookie we can't cryptographically verify must never be
/// trusted (see the cross-tenant-linking finding this key exists to close).
fn flow_state_hmac_key() -> Option<Vec<u8>> {
    jwt_signing_secret().map(|s| s.into_bytes())
}

/// Known limitation (security review, not yet addressed): no `Secure`
/// attribute, matching the pre-existing `aegis_csrf` cookie (`routes::dashboard`)
/// precedent this mirrors. That cookie is a low-value CSRF token; this one
/// carries the PKCE verifier and (HMAC-protected, but still) the
/// `linking_tenant_id`, so it arguably deserves `Secure` even though the
/// existing convention doesn't set it. Left matching precedent rather than
/// diverging silently — adding `Secure` unconditionally would break the
/// documented local/CI development flow (gateway served over plain HTTP on
/// `127.0.0.1`), and conditioning it on scheme would require trusting a
/// reverse-proxy `X-Forwarded-Proto` header, a bigger change than this
/// finding warrants on its own.
fn set_flow_cookie(headers: &mut HeaderMap, flow_state: &OidcFlowState, hmac_key: &[u8]) {
    let cookie_val = format!(
        "{}={}; Path=/; Max-Age={}; SameSite=Lax; HttpOnly",
        OIDC_STATE_COOKIE_NAME,
        flow_state.encode(hmac_key),
        OIDC_FLOW_COOKIE_MAX_AGE_SECS
    );
    if let Ok(v) = cookie_val.parse() {
        headers.insert(header::SET_COOKIE, v);
    }
}

fn clear_flow_cookie(headers: &mut HeaderMap) {
    let cookie_val =
        format!("{OIDC_STATE_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly");
    if let Ok(v) = cookie_val.parse() {
        headers.insert(header::SET_COOKIE, v);
    }
}

fn read_flow_cookie(headers: &HeaderMap, hmac_key: &[u8]) -> Option<OidcFlowState> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name == OIDC_STATE_COOKIE_NAME {
            return OidcFlowState::decode(value, hmac_key);
        }
    }
    None
}

fn redirect_to(url: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, url)
        .body(axum::body::Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// `GET /v1/auth/oidc/login` — plain login attempt against an already-linked
/// identity. No `Authorization` header required (there is none to require:
/// the caller isn't authenticated yet, that's the point of logging in).
pub async fn oidc_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusError::not_implemented(
            "OIDC login is not configured on this gateway (AEGIS_OIDC_* env vars unset)",
        )
        .into_response();
    };
    let Some(hmac_key) = flow_state_hmac_key() else {
        return StatusError::not_implemented(
            "OIDC login is not usable on this gateway (AEGIS_JWT_SECRET unset)",
        )
        .into_response();
    };
    let (auth_url, flow_state) = oidc.authorization_url(None);
    let mut response = redirect_to(&auth_url);
    set_flow_cookie(response.headers_mut(), &flow_state, &hmac_key);
    response
}

/// `POST /v1/oidc/link/start` — authenticated. Returns the IdP authorization
/// URL as JSON (rather than redirecting directly) so the caller's existing
/// bearer token, which only this JSON request can carry, is what determines
/// which tenant the resulting identity link applies to.
pub async fn oidc_link_start(
    State(state): State<Arc<AppState>>,
    TenantId(tenant_id): TenantId,
) -> impl IntoResponse {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusError::not_implemented(
            "OIDC login is not configured on this gateway (AEGIS_OIDC_* env vars unset)",
        )
        .into_response();
    };
    let Some(hmac_key) = flow_state_hmac_key() else {
        return StatusError::not_implemented(
            "OIDC login is not usable on this gateway (AEGIS_JWT_SECRET unset)",
        )
        .into_response();
    };
    let (auth_url, flow_state) = oidc.authorization_url(Some(tenant_id));
    let mut response = Json(serde_json::json!({ "login_url": auth_url })).into_response();
    set_flow_cookie(response.headers_mut(), &flow_state, &hmac_key);
    response
}

#[derive(Debug, serde::Deserialize)]
pub struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /v1/auth/oidc/callback` — the IdP redirects the browser here.
/// Verifies the round-tripped CSRF `state`, exchanges the code, verifies the
/// ID token (issuer/audience/expiry/signature/nonce, all via
/// `openidconnect`), then either links the verified identity to the calling
/// tenant (a "link" flow) or looks up an existing link (a plain "login"
/// flow) — an unrecognized identity at login fails closed, it is never
/// auto-provisioned. On any failure this redirects to the UI with
/// `#error=<reason>` rather than rendering a gateway-side error page, since
/// the browser's next stop is always the console.
pub async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<OidcCallbackQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(oidc) = state.oidc.as_ref() else {
        return StatusError::not_implemented(
            "OIDC login is not configured on this gateway (AEGIS_OIDC_* env vars unset)",
        )
        .into_response();
    };
    let Some(hmac_key) = flow_state_hmac_key() else {
        return StatusError::not_implemented(
            "OIDC login is not usable on this gateway (AEGIS_JWT_SECRET unset)",
        )
        .into_response();
    };

    let Some(flow_state) = read_flow_cookie(&headers, &hmac_key) else {
        return oidc_error_redirect(&oidc.ui_redirect_url, "missing_or_expired_state");
    };

    let mut response_headers = HeaderMap::new();
    clear_flow_cookie(&mut response_headers);

    if let Some(idp_error) = query.error {
        tracing::warn!(error = %idp_error, "OIDC callback: IdP returned an error");
        return with_headers(
            oidc_error_redirect(&oidc.ui_redirect_url, "idp_error"),
            response_headers,
        );
    }

    let (Some(code), Some(returned_state)) = (query.code, query.state) else {
        return with_headers(
            oidc_error_redirect(&oidc.ui_redirect_url, "missing_code_or_state"),
            response_headers,
        );
    };
    if returned_state != flow_state.csrf_state {
        tracing::warn!("OIDC callback: state mismatch (possible CSRF attempt)");
        return with_headers(
            oidc_error_redirect(&oidc.ui_redirect_url, "state_mismatch"),
            response_headers,
        );
    }

    let (issuer, subject) = match oidc
        .exchange_and_verify(code, flow_state.pkce_verifier, flow_state.nonce)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC callback: code exchange or ID token verification failed");
            return with_headers(
                oidc_error_redirect(&oidc.ui_redirect_url, "verification_failed"),
                response_headers,
            );
        }
    };

    let tenant_id = if let Some(linking_tenant_id) = flow_state.linking_tenant_id {
        match state
            .storage
            .link_oidc_identity(&linking_tenant_id, &issuer, &subject)
            .await
        {
            Ok(()) => linking_tenant_id,
            Err(aegis_common::errors::AegisError::Conflict(msg)) => {
                tracing::warn!(error = %msg, "OIDC callback: identity already linked elsewhere");
                return with_headers(
                    oidc_error_redirect(&oidc.ui_redirect_url, "identity_already_linked"),
                    response_headers,
                );
            }
            Err(e) => {
                tracing::error!(error = ?e, "OIDC callback: failed to persist identity link");
                return with_headers(
                    oidc_error_redirect(&oidc.ui_redirect_url, "internal_error"),
                    response_headers,
                );
            }
        }
    } else {
        match state.storage.get_oidc_identity(&issuer, &subject).await {
            Ok(Some(identity)) => identity.tenant_id,
            Ok(None) => {
                return with_headers(
                    oidc_error_redirect(&oidc.ui_redirect_url, "identity_not_linked"),
                    response_headers,
                );
            }
            Err(e) => {
                tracing::error!(error = ?e, "OIDC callback: identity lookup failed");
                return with_headers(
                    oidc_error_redirect(&oidc.ui_redirect_url, "internal_error"),
                    response_headers,
                );
            }
        }
    };

    let jwt = match mint_jwt(&tenant_id, chrono::Duration::hours(12)) {
        Ok(jwt) => jwt,
        Err(e) => {
            tracing::error!(error = %e, "OIDC callback: failed to mint gateway JWT");
            return with_headers(
                oidc_error_redirect(&oidc.ui_redirect_url, "internal_error"),
                response_headers,
            );
        }
    };

    // The fragment (`#access_token=`) is never sent to any server (not this
    // one, not the IdP's) and never appears in access logs, unlike a query
    // parameter.
    let target = format!("{}#access_token={}", oidc.ui_redirect_url, jwt);
    with_headers(redirect_to(&target), response_headers)
}

fn oidc_error_redirect(ui_redirect_url: &str, reason: &str) -> Response {
    redirect_to(&format!("{ui_redirect_url}#error={reason}"))
}

fn with_headers(mut response: Response, extra: HeaderMap) -> Response {
    response.headers_mut().extend(extra);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_helpers::setup_state;
    use axum::body::Body;
    use axum::http::Request;
    use openidconnect::core::{
        CoreClient, CoreJsonWebKey, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreResponseType, CoreSubjectIdentifierType,
    };
    use openidconnect::{
        AuthUrl, ClientId, ClientSecret, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeyId,
        JsonWebKeySet, JsonWebKeySetUrl, RedirectUrl, ResponseTypes, TokenUrl,
    };
    use tower::ServiceExt;

    // A fixed, test-only RSA keypair (generated once via `openssl genrsa`, not
    // a production secret). `n`/`e` back the JWK served for ID-token
    // signature verification; the PEM signs the mock IdP's ID tokens.
    const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCJeiRgsRN9wEut
IBsQSCWSpBuMe1WhwOk8Vh+P+sjFVWVzT+RzRb7+myv+ePBYj3+C+LR/IIwU6OO6
Tg95oOAHLamXIju5FdBNNBm2/Gvk7NOKofx/aKYtD86MM8HVqqRMBfWsqomXqdxL
j5BqJZNEMRr/sRT5GoKoh+jLiZfRFKJxyS5oAgMxJtFGbPoOFldJzlF94L/r0jah
l4gABgqZiMxE2eW3huzd87r2gy+z8cB4gTfnMCXRMyCTyvj/AeBeMT7A7QdDJhAo
MNmTsts88NsTSseNncqlJKmL979sia2cyNirTD80eb/KJPXBG6YBtas5tjW0gsVS
axx7krOvAgMBAAECggEAAjJ3VfhE661g4dgLUEizsp+rm3FcXmTUrwf6IluLgLCr
TQF83cuPXUa7mEPBWGXKthwlcYnioAu5mZoMk0QOVu8HsKIPOrEHjp3p8n7sQ1D2
b71dz+d4DtMbpcMtMnrMr2f0+jJ4V0bGsSQO1pnZ70Z3PDKA6rSqwk8rWePNqL2N
Fiiveodup/ylqEH3tvJj9Z2o/177FTjbCdjiiYBsFpJanRjTgQO0LCy2Eq7t3zTc
gTlenemE2AhAxfSY9tTBiVCj8nP+QSDnuo+xTE2tdH6OTTvqrolZtLQ0JLmn1sWC
DsMzXp7VlFQFWDclRfhSyK7s+6q/NuepHJOXW+qBSQKBgQC+v1QQ4RAa63V59YT+
BDVrS8RPMouskKajDAUaLWvq7jcAdABLyrjsimDKS0oimN4EkhocTlcCRdRubMZv
6l1+YqB0zSJR4ljIKxryq0A9CBVhdCSPN5zLsNNApBS7Dpf/lUQ3SpXVyB+DR1u1
XGfr49Ngf70m6CqgvtKcP3MMAwKBgQC4ga3b+Lekd4cxdHyk8zhY82088jlYhllQ
7oJAqHmR9YN2/dAFHYoCHa87UH7d8w7qj/Wj9eNduiCQeFE0HXXnK94bRUtXl0Rx
nuIFzZFspWIZhTAdb/PvDdtlD7oDVXON/mley0bDYIXSeZL4Q0RVg5UjbSVf7mW6
cU25yvGn5QKBgC1/VX3xMPY603qTpXUxa8x79gct90Lh/d1GMLFdxC/1QglJoghy
Aknpd8zIyJYYAFz2vGOkC/zuywzLxUlMjaBnxf4WL+l4I9Ua8wKO9nOYSgFEwrOm
gC/VrY3tlURI5th/shW+JJ8pbNrTWnyX3fHWFcUesu9k0UYmPfYm7DohAoGAGMnr
duNaoPEiK8XPvUWkK2dBJPASPk+GjnYM7+zysGaA7Cq7mQRX92LPmTN+aAlw1pjS
0t2FV6FbIK3ZkxvmLFHbfGR58+Gx42YKTedJg4RQwsb/KOVSq6p78H8Fac9AQDKP
K5o5/qPoNtf4o/w9oROVpPXUEKhx6HOykqSuhPUCgYAuq7/h5qWnPDeQCJOvF5c7
xZYW9LwfosWW3nY0gYkcwdJ+5j1JshdFI1FBvOFcbEXYhjkaNuDXOiu8g1Aa3i4k
bbA1hKuJ6giqQ0JSgH8uFRe5QVU2wUz9H/udDUnlo7M16fSncYoDfyVedEQFvXIz
k1VaoXnfuP2TC0cxpA0nKg==
-----END PRIVATE KEY-----
";
    const TEST_RSA_MODULUS_HEX: &str = "897A2460B1137DC04BAD201B10482592A41B8C7B55A1C0E93C561F8FFAC8C55565734FE47345BEFE9B2BFE78F0588F7F82F8B47F208C14E8E3BA4E0F79A0E0072DA997223BB915D04D3419B6FC6BE4ECD38AA1FC7F68A62D0FCE8C33C1D5AAA44C05F5ACAA8997A9DC4B8F906A259344311AFFB114F91A82A887E8CB8997D114A271C92E6802033126D1466CFA0E165749CE517DE0BFEBD236A1978800060A9988CC44D9E5B786ECDDF3BAF6832FB3F1C0788137E73025D1332093CAF8FF01E05E313EC0ED074326102830D993B2DB3CF0DB134AC78D9DCAA524A98BF7BF6C89AD9CC8D8AB4C3F3479BFCA24F5C11BA601B5AB39B635B482C5526B1C7B92B3AF";
    const TEST_RSA_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];
    const TEST_KID: &str = "test-key-1";
    const TEST_JWT_SECRET: &str = "test-jwt-secret-for-oidc";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Signs a minimal OIDC ID token (`iss`/`sub`/`aud`/`exp`/`iat`/`nonce`)
    /// with the fixed test RSA key and `TEST_KID`, matching what a real IdP's
    /// token endpoint would return.
    fn sign_test_id_token(issuer: &str, subject: &str, client_id: &str, nonce: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": issuer,
            "sub": subject,
            "aud": client_id,
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
        });
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(TEST_KID.to_string());
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// Spins up a mock IdP (just a `/token` endpoint — discovery and JWKS are
    /// built in-process, no HTTP round trip needed for those) that always
    /// signs an ID token for `subject` containing exactly `nonce` — the
    /// caller supplies whatever nonce it put in the flow-state cookie for
    /// this test, so the mock doesn't need to inspect the request body at
    /// all (it's a fixed one-server-per-test double, not a real IdP).
    async fn mock_oidc_state(
        ui_redirect_url: &str,
        subject: &str,
        nonce: &str,
    ) -> crate::oidc::OidcState {
        let issuer = "https://mock-idp.example.test".to_string();
        let client_id = "test-client".to_string();
        let subject = subject.to_string();
        let nonce = nonce.to_string();

        let app = axum::Router::new().route(
            "/token",
            axum::routing::post({
                let issuer = issuer.clone();
                let client_id = client_id.clone();
                let subject = subject.clone();
                let nonce = nonce.clone();
                move || {
                    let issuer = issuer.clone();
                    let client_id = client_id.clone();
                    let subject = subject.clone();
                    let nonce = nonce.clone();
                    async move {
                        let id_token = sign_test_id_token(&issuer, &subject, &client_id, &nonce);
                        axum::Json(serde_json::json!({
                            "access_token": "mock-access-token",
                            "token_type": "Bearer",
                            "id_token": id_token,
                        }))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let token_url = format!("http://{addr}/token");

        let jwk = CoreJsonWebKey::new_rsa(
            hex_to_bytes(TEST_RSA_MODULUS_HEX),
            TEST_RSA_EXPONENT.to_vec(),
            Some(JsonWebKeyId::new(TEST_KID.to_string())),
        );

        let metadata = CoreProviderMetadata::new(
            IssuerUrl::new(issuer.clone()).unwrap(),
            AuthUrl::new(format!("{issuer}/authorize")).unwrap(),
            JsonWebKeySetUrl::new(format!("{issuer}/jwks")).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            EmptyAdditionalProviderMetadata {},
        )
        .set_token_endpoint(Some(TokenUrl::new(token_url).unwrap()))
        .set_jwks(JsonWebKeySet::new(vec![jwk]));

        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(client_id),
            Some(ClientSecret::new("test-secret".to_string())),
        )
        .set_redirect_uri(
            RedirectUrl::new("https://gateway.example.test/v1/auth/oidc/callback".to_string())
                .unwrap(),
        );

        crate::oidc::OidcState {
            client,
            issuer_url: issuer,
            ui_redirect_url: ui_redirect_url.to_string(),
            http_client: openidconnect::reqwest::Client::builder()
                .redirect(openidconnect::reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        }
    }

    fn extract_cookie_value(headers: &HeaderMap) -> Option<String> {
        headers
            .get(header::SET_COOKIE)?
            .to_str()
            .ok()?
            .split(';')
            .next()
            .and_then(|kv| kv.strip_prefix(&format!("{OIDC_STATE_COOKIE_NAME}=")))
            .map(str::to_string)
    }

    #[tokio::test]
    async fn oidc_login_returns_501_when_unconfigured() {
        let (state, _tenant_id, _token) = setup_state("oidc_login_unconfigured").await;
        let response = oidc_login(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn oidc_callback_returns_501_when_unconfigured() {
        let (state, _tenant_id, _token) = setup_state("oidc_callback_unconfigured").await;
        let response = oidc_callback(
            State(state),
            Query(OidcCallbackQuery {
                code: None,
                state: None,
                error: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn oidc_link_start_returns_501_when_unconfigured() {
        let (state, tenant_id, _token) = setup_state("oidc_link_unconfigured").await;
        let response = oidc_link_start(State(state), TenantId(tenant_id))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn oidc_link_start_requires_authentication() {
        let (mut state, _tenant_id, _token) = setup_state("oidc_link_requires_auth").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state("https://ui.example.test/cb", "sub-1", "unused-nonce").await,
        ));

        let app = axum::Router::new()
            .route("/v1/oidc/link/start", axum::routing::post(oidc_link_start))
            .with_state(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/oidc/link/start")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn oidc_login_redirects_to_idp_and_sets_state_cookie() {
        std::env::set_var("AEGIS_JWT_SECRET", TEST_JWT_SECRET);
        let (mut state, _tenant_id, _token) = setup_state("oidc_login_redirect").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state("https://ui.example.test/cb", "sub-1", "unused-nonce").await,
        ));

        let response = oidc_login(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://mock-idp.example.test/authorize"));
        assert!(extract_cookie_value(response.headers()).is_some());
        std::env::remove_var("AEGIS_JWT_SECRET");
    }

    /// `oidc_login` must fail closed (501) when there is no signing secret to
    /// HMAC-tag the flow-state cookie with, even though `oidc` itself is
    /// configured -- a cookie we can't cryptographically verify must never
    /// be trusted (this is the guard that closes the cross-tenant identity
    /// linking finding: an unsigned `linking_tenant_id` in the cookie would
    /// let an attacker bind their own IdP identity to a victim's tenant).
    #[tokio::test]
    async fn oidc_login_fails_closed_without_a_jwt_signing_secret() {
        std::env::remove_var("AEGIS_JWT_SECRET");
        let (mut state, _tenant_id, _token) = setup_state("oidc_login_no_secret").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state("https://ui.example.test/cb", "sub-1", "unused-nonce").await,
        ));

        let response = oidc_login(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn callback_rejects_state_mismatch_as_a_csrf_defense() {
        std::env::set_var("AEGIS_JWT_SECRET", TEST_JWT_SECRET);
        let (mut state, tenant_id, _token) = setup_state("oidc_callback_state_mismatch").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state("https://ui.example.test/cb", &tenant_id, "unused-nonce").await,
        ));

        let flow_state = OidcFlowState {
            csrf_state: "expected-state".to_string(),
            nonce: "some-nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            linking_tenant_id: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{OIDC_STATE_COOKIE_NAME}={}",
                flow_state.encode(TEST_JWT_SECRET.as_bytes())
            )
            .parse()
            .unwrap(),
        );

        let response = oidc_callback(
            State(state),
            Query(OidcCallbackQuery {
                code: Some("some-code".to_string()),
                state: Some("attacker-supplied-state".to_string()),
                error: None,
            }),
            headers,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("#error=state_mismatch"));
        std::env::remove_var("AEGIS_JWT_SECRET");
    }

    /// Directly proves the fix for the cross-tenant identity-linking finding:
    /// a `linking_tenant_id` smuggled into a cookie the client crafted itself
    /// (rather than one the gateway signed) must be rejected outright, not
    /// silently accepted and used to bind an identity to that tenant.
    #[tokio::test]
    async fn callback_rejects_a_flow_state_cookie_not_signed_by_the_gateway() {
        std::env::set_var("AEGIS_JWT_SECRET", TEST_JWT_SECRET);
        let (mut state, victim_tenant_id, _token) =
            setup_state("oidc_callback_forged_cookie").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state("https://ui.example.test/cb", "attacker-sub", "nonce-forged").await,
        ));

        let forged_flow_state = OidcFlowState {
            csrf_state: "csrf-forged".to_string(),
            nonce: "nonce-forged".to_string(),
            pkce_verifier: "verifier".to_string(),
            linking_tenant_id: Some(victim_tenant_id.clone()),
        };
        // Signed with a DIFFERENT key than the gateway's configured
        // AEGIS_JWT_SECRET -- simulating a client-forged cookie rather than
        // one this gateway actually set.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{OIDC_STATE_COOKIE_NAME}={}",
                forged_flow_state.encode(b"attacker-controlled-key")
            )
            .parse()
            .unwrap(),
        );

        let response = oidc_callback(
            State(state.clone()),
            Query(OidcCallbackQuery {
                code: Some("some-code".to_string()),
                state: Some("csrf-forged".to_string()),
                error: None,
            }),
            headers,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.contains("#error=missing_or_expired_state"),
            "an unverifiable cookie must be treated as absent, got: {location}"
        );

        // The identity must NOT have been linked to the victim tenant.
        let identity = state
            .storage
            .get_oidc_identity(&state.oidc.as_ref().unwrap().issuer_url, "attacker-sub")
            .await
            .unwrap();
        assert!(
            identity.is_none(),
            "a forged cookie must never result in a tenant link"
        );
        std::env::remove_var("AEGIS_JWT_SECRET");
    }

    #[tokio::test]
    async fn callback_fails_closed_for_an_unlinked_identity() {
        std::env::set_var("AEGIS_JWT_SECRET", TEST_JWT_SECRET);
        let (mut state, _tenant_id, _token) = setup_state("oidc_callback_unlinked").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state(
                "https://ui.example.test/cb",
                "sub-never-linked",
                "nonce-marker-1",
            )
            .await,
        ));

        let flow_state = OidcFlowState {
            csrf_state: "csrf-abc".to_string(),
            nonce: "nonce-marker-1".to_string(),
            pkce_verifier: "verifier".to_string(),
            linking_tenant_id: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{OIDC_STATE_COOKIE_NAME}={}",
                flow_state.encode(TEST_JWT_SECRET.as_bytes())
            )
            .parse()
            .unwrap(),
        );

        let response = oidc_callback(
            State(state),
            Query(OidcCallbackQuery {
                code: Some("some-code".to_string()),
                state: Some("csrf-abc".to_string()),
                error: None,
            }),
            headers,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.contains("#error=identity_not_linked"),
            "got: {location}"
        );
        std::env::remove_var("AEGIS_JWT_SECRET");
    }

    #[tokio::test]
    async fn callback_link_flow_links_identity_and_mints_a_valid_jwt() {
        std::env::set_var("AEGIS_JWT_SECRET", TEST_JWT_SECRET);
        let (mut state, tenant_id, _token) = setup_state("oidc_callback_link_flow").await;
        Arc::get_mut(&mut state).unwrap().oidc = Some(Arc::new(
            mock_oidc_state(
                "https://ui.example.test/cb",
                "sub-link-flow",
                "nonce-marker-2",
            )
            .await,
        ));

        let flow_state = OidcFlowState {
            csrf_state: "csrf-link".to_string(),
            nonce: "nonce-marker-2".to_string(),
            pkce_verifier: "verifier".to_string(),
            linking_tenant_id: Some(tenant_id.clone()),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{OIDC_STATE_COOKIE_NAME}={}",
                flow_state.encode(TEST_JWT_SECRET.as_bytes())
            )
            .parse()
            .unwrap(),
        );

        let response = oidc_callback(
            State(state.clone()),
            Query(OidcCallbackQuery {
                code: Some("some-code".to_string()),
                state: Some("csrf-link".to_string()),
                error: None,
            }),
            headers,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://ui.example.test/cb#access_token="),
            "got: {location}"
        );
        let jwt = location.rsplit("access_token=").next().unwrap();
        let resolved_tenant = crate::routes::validate_jwt(jwt);
        assert_eq!(resolved_tenant.as_deref(), Some(tenant_id.as_str()));

        // The identity is now linked; a subsequent plain login (no
        // linking_tenant_id) must resolve to the same tenant.
        let identity = state
            .storage
            .get_oidc_identity(&state.oidc.as_ref().unwrap().issuer_url, "sub-link-flow")
            .await
            .unwrap()
            .expect("identity must be linked after the callback");
        assert_eq!(identity.tenant_id, tenant_id);

        std::env::remove_var("AEGIS_JWT_SECRET");
    }
}
