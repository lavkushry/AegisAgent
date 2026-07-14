//! Transport-neutral authorization request context.

/// Which protocol admitted this authorization request. The service treats the
/// two identically; adapters differ only in how they authenticate and encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Rest,
    Grpc,
}

/// How the adapter proved the caller's agent identity.
///
/// Fail-closed: if neither credential form can be established, the adapter
/// returns its transport error and never builds an [`AuthorizeContext`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthCredential {
    /// Bearer agent token (already stripped of the `Bearer ` prefix).
    BearerToken(String),
    /// Verified mTLS client-certificate Subject CN from the TLS accept loop.
    MtlsCn(String),
}

/// Transport-neutral, already-authenticated context for one authorization
/// evaluation. An adapter constructs this only after it has verified the
/// caller (bearer token, mTLS CN, or request signature) and resolved the
/// tenant; the service trusts these fields and never re-reads a header for
/// tenant authority.
///
/// Fail-closed by construction: if an adapter cannot authenticate the caller
/// or determine the tenant, it returns its transport-appropriate error and
/// never builds an `AuthorizeContext`.
#[derive(Debug, Clone)]
pub struct AuthorizeContext {
    /// The authenticated runtime tenant (from `X-Aegis-Tenant-ID` on REST,
    /// request `tenant_id` / metadata on gRPC). Single tenant authority the
    /// service uses — it does not consult any other source.
    pub tenant_id: String,
    /// Real remote peer, used to key the auth-failure tracker. gRPC supplies
    /// tonic's `remote_addr`, never a forged loopback address.
    pub client_addr: std::net::SocketAddr,
    /// Admitting protocol.
    pub transport: Transport,
    /// Agent identity credential resolved by the adapter.
    pub credential: AuthCredential,
    /// Optional `X-Aegis-Request-Signature` value (agents with signing keys).
    pub request_signature: Option<String>,
}

impl AuthorizeContext {
    pub fn new(
        tenant_id: impl Into<String>,
        client_addr: std::net::SocketAddr,
        transport: Transport,
        credential: AuthCredential,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            client_addr,
            transport,
            credential,
            request_signature: None,
        }
    }

    pub fn with_request_signature(mut self, sig: Option<String>) -> Self {
        self.request_signature = sig.filter(|s| !s.is_empty());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_filters_empty_request_signature() {
        let addr = std::net::SocketAddr::from(([10, 0, 0, 1], 4443));
        let ctx = AuthorizeContext::new(
            "tenant_a",
            addr,
            Transport::Grpc,
            AuthCredential::BearerToken("tok".into()),
        )
        .with_request_signature(Some(String::new()));
        assert_eq!(ctx.request_signature, None);
        assert_eq!(ctx.tenant_id, "tenant_a");
        assert_eq!(ctx.transport, Transport::Grpc);

        let ctx = AuthorizeContext::new(
            "tenant_a",
            addr,
            Transport::Rest,
            AuthCredential::MtlsCn("agent.svc".into()),
        )
        .with_request_signature(Some("sig".into()));
        assert_eq!(ctx.request_signature.as_deref(), Some("sig"));
        match &ctx.credential {
            AuthCredential::MtlsCn(cn) => assert_eq!(cn, "agent.svc"),
            AuthCredential::BearerToken(_) => panic!("expected mtls"),
        }
    }
}
