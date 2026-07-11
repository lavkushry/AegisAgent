//! OIDC console login (roadmap: "OIDC/SAML for console/admin").
//!
//! Gated entirely on four env vars (`AEGIS_OIDC_ISSUER_URL`,
//! `AEGIS_OIDC_CLIENT_ID`, `AEGIS_OIDC_CLIENT_SECRET`,
//! `AEGIS_OIDC_REDIRECT_URL`) plus `AEGIS_OIDC_UI_REDIRECT_URL` (where the
//! browser lands after a token is minted). Unset (the default): `oidc_client`
//! on `AppState` is `None` and every `/v1/auth/oidc/*` / `/v1/oidc/*` route
//! fails closed with 501 — identical to the `AEGIS_POLICY_SIGNING_KEY` /
//! `AEGIS_MTLS_CA_CERT` precedent.
//!
//! PKCE, discovery, JWKS caching, and ID-token signature/claims verification
//! are all handled by the `openidconnect` crate rather than hand-rolled.

use openidconnect::core::{CoreAuthenticationFlow, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};

/// The concrete typestate `CoreClient::from_provider_metadata` returns:
/// discovery always provides an authorization endpoint (`EndpointSet`), a
/// token endpoint that discovery methods report as merely
/// `EndpointMaybeSet` even though OIDC discovery documents always include
/// one, and device-auth/introspection/revocation endpoints stay
/// `EndpointNotSet` since this crate doesn't need them for the authorization
/// code flow. There is no separate redirect-URL typestate — `set_redirect_uri`
/// only sets a plain field, it doesn't change the type.
type DiscoveredCoreClient = openidconnect::core::CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    /// Where the browser is redirected after a successful login/link, with
    /// the minted gateway JWT appended as a `#access_token=` URL fragment
    /// (never sent to a server, never written to access logs).
    pub ui_redirect_url: String,
}

impl OidcConfig {
    /// `None` if any required var is unset — deliberately all-or-nothing so
    /// a half-configured deployment doesn't silently expose a broken login
    /// button rather than a clearly-inert feature.
    pub fn from_env() -> Option<Self> {
        Some(Self {
            issuer_url: non_empty_env("AEGIS_OIDC_ISSUER_URL")?,
            client_id: non_empty_env("AEGIS_OIDC_CLIENT_ID")?,
            client_secret: non_empty_env("AEGIS_OIDC_CLIENT_SECRET")?,
            redirect_url: non_empty_env("AEGIS_OIDC_REDIRECT_URL")?,
            ui_redirect_url: non_empty_env("AEGIS_OIDC_UI_REDIRECT_URL")?,
        })
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Wraps the discovered `CoreClient` plus the config fields the route
/// handlers need directly (the UI redirect target isn't part of the OIDC
/// client itself).
pub struct OidcState {
    pub client: DiscoveredCoreClient,
    /// Stored separately from `client` (rather than re-derived from the
    /// discovery document each time) so `oidc_identities.issuer` is always
    /// exactly the configured issuer string, matching what a self-service
    /// `POST /v1/oidc/link/start` and a later `GET /v1/auth/oidc/login`
    /// both record — this MVP slice supports exactly one IdP per gateway.
    pub issuer_url: String,
    pub ui_redirect_url: String,
    pub(crate) http_client: openidconnect::reqwest::Client,
}

/// The ephemeral, single-use values threaded through the state cookie
/// between `GET /v1/auth/oidc/login` (or `POST /v1/oidc/link/start`) and
/// `GET /v1/auth/oidc/callback`. Round-tripped as base64-encoded JSON in an
/// `HttpOnly`, `SameSite=Lax`, short-TTL cookie — `SameSite=Lax` (not
/// `Strict`) is required because the IdP redirect back to our callback is a
/// top-level cross-site navigation, which `Strict` cookies do not survive.
///
/// **Security-critical**: `linking_tenant_id` is what the callback trusts to
/// decide which tenant a verified identity gets bound to. Because this
/// struct round-trips through a client-held cookie, [`OidcFlowState::encode`]
/// / [`OidcFlowState::decode`] MUST go through the HMAC-tagged form — a
/// caller who could forge this cookie unsigned would be able to link their
/// own IdP identity to an arbitrary victim tenant despite `link/start`'s own
/// `TenantId` bearer-token check, since that check only gates what the
/// *server* writes, not what the *client* presents back at the callback.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct OidcFlowState {
    pub csrf_state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    /// `Some(tenant_id)` for a "link my identity to my tenant" flow started
    /// from an authenticated session; `None` for a plain login attempt
    /// against an already-linked identity.
    pub linking_tenant_id: Option<String>,
}

type FlowStateHmac = hmac::Hmac<sha2::Sha256>;

impl OidcFlowState {
    /// HMAC-tags the JSON payload with `hmac_key` (the gateway's
    /// `AEGIS_JWT_SECRET` primary secret — see
    /// `crate::routes::jwt_signing_secret`) before base64-encoding, so a
    /// client can carry this value but not forge or tamper with it.
    pub fn encode(&self, hmac_key: &[u8]) -> String {
        use base64::Engine;
        use hmac::Mac;
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut mac =
            FlowStateHmac::new_from_slice(hmac_key).expect("HMAC accepts a key of any length");
        mac.update(json.as_bytes());
        let tag = hex::encode(mac.finalize().into_bytes());
        format!(
            "{}.{tag}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }

    /// Verifies the HMAC tag (constant-time) before deserializing — a
    /// missing/invalid tag or a tampered payload both return `None`, never a
    /// partially-trusted value.
    pub fn decode(raw: &str, hmac_key: &[u8]) -> Option<Self> {
        use base64::Engine;
        use hmac::Mac;
        let (encoded_json, tag_hex) = raw.rsplit_once('.')?;
        let json = base64::engine::general_purpose::STANDARD
            .decode(encoded_json)
            .ok()?;
        let tag_bytes = hex::decode(tag_hex).ok()?;
        let mut mac =
            FlowStateHmac::new_from_slice(hmac_key).expect("HMAC accepts a key of any length");
        mac.update(&json);
        mac.verify_slice(&tag_bytes).ok()?;
        serde_json::from_slice(&json).ok()
    }
}

pub const OIDC_STATE_COOKIE_NAME: &str = "aegis_oidc_state";

#[derive(Debug, thiserror::Error)]
pub enum OidcDiscoveryError {
    #[error("invalid issuer URL: {0}")]
    InvalidIssuerUrl(String),
    #[error("invalid redirect URL: {0}")]
    InvalidRedirectUrl(String),
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
}

/// Performs OIDC discovery (`{issuer}/.well-known/openid-configuration`)
/// once at startup. A discovery failure (unreachable IdP, malformed
/// metadata) is logged and leaves OIDC login inert for this process — it
/// does not crash gateway startup, since a misconfigured/unreachable IdP
/// must not take down authorize/approve/receipt traffic that has nothing to
/// do with console login.
pub async fn discover(config: &OidcConfig) -> Result<OidcState, OidcDiscoveryError> {
    let issuer_url = IssuerUrl::new(config.issuer_url.clone())
        .map_err(|e| OidcDiscoveryError::InvalidIssuerUrl(e.to_string()))?;
    let redirect_url = RedirectUrl::new(config.redirect_url.clone())
        .map_err(|e| OidcDiscoveryError::InvalidRedirectUrl(e.to_string()))?;

    let http_client = openidconnect::reqwest::Client::builder()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| OidcDiscoveryError::Discovery(e.to_string()))?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| OidcDiscoveryError::Discovery(e.to_string()))?;

    let client = openidconnect::core::CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(redirect_url);

    Ok(OidcState {
        client,
        issuer_url: config.issuer_url.clone(),
        ui_redirect_url: config.ui_redirect_url.clone(),
        http_client,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum OidcCallbackError {
    #[error("code exchange failed: {0}")]
    Exchange(String),
    #[error("the IdP did not return an ID token")]
    MissingIdToken,
    #[error("ID token verification failed: {0}")]
    ClaimsVerification(String),
}

impl OidcState {
    /// Builds the IdP authorization URL plus the flow state to store in the
    /// short-lived `aegis_oidc_state` cookie. `linking_tenant_id` is `Some`
    /// only for the self-service "link my identity" flow.
    pub fn authorization_url(&self, linking_tenant_id: Option<String>) -> (String, OidcFlowState) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        (
            auth_url.to_string(),
            OidcFlowState {
                csrf_state: csrf_token.secret().clone(),
                nonce: nonce.secret().clone(),
                pkce_verifier: pkce_verifier.secret().clone(),
                linking_tenant_id,
            },
        )
    }

    /// Exchanges the authorization `code` for tokens, verifies the ID
    /// token's signature/issuer/audience/expiry/nonce (all handled by
    /// `openidconnect`'s `IdTokenVerifier`, not hand-rolled), and returns
    /// `(issuer, subject)` on success. Callers map that pair through
    /// `oidc_identities` — this function itself never touches storage or
    /// tenancy, it only proves "this really is who the IdP says it is".
    pub async fn exchange_and_verify(
        &self,
        code: String,
        pkce_verifier: String,
        expected_nonce: String,
    ) -> Result<(String, String), OidcCallbackError> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|e| OidcCallbackError::Exchange(e.to_string()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&self.http_client)
            .await
            .map_err(|e| OidcCallbackError::Exchange(e.to_string()))?;

        let id_token = token_response
            .id_token()
            .ok_or(OidcCallbackError::MissingIdToken)?;
        let verifier = self.client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(expected_nonce))
            .map_err(|e| OidcCallbackError::ClaimsVerification(e.to_string()))?;

        Ok((
            self.issuer_url.clone(),
            claims.subject().as_str().to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_is_none_unless_every_var_is_set() {
        let vars = [
            "AEGIS_OIDC_ISSUER_URL",
            "AEGIS_OIDC_CLIENT_ID",
            "AEGIS_OIDC_CLIENT_SECRET",
            "AEGIS_OIDC_REDIRECT_URL",
            "AEGIS_OIDC_UI_REDIRECT_URL",
        ];
        for v in vars {
            std::env::remove_var(v);
        }
        assert!(OidcConfig::from_env().is_none());

        // Set all but one -- still None.
        for v in &vars[..vars.len() - 1] {
            std::env::set_var(v, "x");
        }
        assert!(OidcConfig::from_env().is_none());

        std::env::set_var(vars[vars.len() - 1], "x");
        assert!(OidcConfig::from_env().is_some());

        for v in vars {
            std::env::remove_var(v);
        }
    }

    #[test]
    fn from_env_treats_blank_value_as_unset() {
        std::env::set_var("AEGIS_OIDC_ISSUER_URL", "   ");
        std::env::set_var("AEGIS_OIDC_CLIENT_ID", "id");
        std::env::set_var("AEGIS_OIDC_CLIENT_SECRET", "secret");
        std::env::set_var("AEGIS_OIDC_REDIRECT_URL", "https://gw/cb");
        std::env::set_var("AEGIS_OIDC_UI_REDIRECT_URL", "https://ui/cb");
        assert!(OidcConfig::from_env().is_none());
        for v in [
            "AEGIS_OIDC_ISSUER_URL",
            "AEGIS_OIDC_CLIENT_ID",
            "AEGIS_OIDC_CLIENT_SECRET",
            "AEGIS_OIDC_REDIRECT_URL",
            "AEGIS_OIDC_UI_REDIRECT_URL",
        ] {
            std::env::remove_var(v);
        }
    }
}
