//! Distributed tracing via OpenTelemetry OTLP export (#1156).
//!
//! Entirely opt-in via `AEGIS_OTLP_ENDPOINT`. Unset, [`init_tracer_provider`]
//! returns `None` and nothing about tracing/logging changes from before this
//! module existed — no exporter is built, no extra `tracing_subscriber`
//! layer is registered, and the global OTel propagator stays the no-op
//! default. Set, spans recorded via `#[tracing::instrument]` throughout the
//! gateway (see `authorize_action`, `PolicyEngine::authorize`,
//! `compute_receipt_hash`, `insert_approval`) are exported in OTLP/protobuf
//! over HTTP to the given collector endpoint, batched in the background.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;

/// Builds and globally registers an OTLP span exporter pointed at
/// `AEGIS_OTLP_ENDPOINT`, returning the provider so the caller can build a
/// `tracing_opentelemetry` layer from it and shut it down on exit (flushing
/// any spans still buffered in the batch processor). Returns `None` — doing
/// nothing else — when the env var is unset.
///
/// Also registers the W3C `traceparent`/`tracestate` propagator globally so
/// `authorize_action` can parent its span to an inbound SDK trace; this is
/// only done in the `Some` branch so an unconfigured gateway never touches
/// OTel global state at all.
pub fn init_tracer_provider() -> Option<SdkTracerProvider> {
    let endpoint = std::env::var("AEGIS_OTLP_ENDPOINT").ok()?;

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&endpoint)
        .build()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            tracing::error!(
                "Failed to build OTLP span exporter for AEGIS_OTLP_ENDPOINT={}: {:?}",
                endpoint,
                e
            );
            return None;
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    tracing::info!(
        "OTLP distributed tracing enabled, exporting to {}",
        endpoint
    );
    Some(provider)
}

/// Builds the `tracing_opentelemetry` layer for a given provider — `None` in
/// means `None` out, so this composes directly into the `Option<Layer>`
/// blanket impl in the `tracing_subscriber::registry()` builder in `main.rs`.
pub fn tracing_layer<S>(
    provider: &Option<SdkTracerProvider>,
) -> Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    provider
        .as_ref()
        .map(|p| tracing_opentelemetry::layer().with_tracer(p.tracer("aegis-gateway")))
}

/// Flushes any spans still buffered in the batch processor and shuts the
/// provider down. Best-effort — logged, not propagated, since a flush
/// failure during shutdown shouldn't block the rest of graceful shutdown.
pub fn shutdown_tracer_provider(provider: &SdkTracerProvider) {
    if let Err(e) = provider.shutdown() {
        tracing::warn!("Failed to cleanly shut down OTLP tracer provider: {:?}", e);
    }
}

/// Extracts a W3C `traceparent`/`tracestate` context from inbound request
/// headers via the globally registered propagator (a no-op when OTel isn't
/// configured — see [`init_tracer_provider`]), and parents the current
/// tracing span to it. Called as the first statement of `authorize_action`
/// so the resulting trace stitches together with whatever trace the calling
/// SDK started, when it sent one.
pub fn set_parent_from_headers(headers: &axum::http::HeaderMap) {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let parent_cx = opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.extract(&opentelemetry_http::HeaderExtractor(headers))
    });
    // `Err` here just means "no OTel layer is registered" (the default,
    // OTel-disabled state) or the span got filtered out — both expected and
    // non-actionable, not worth logging on every request.
    let _ = tracing::Span::current().set_parent(parent_cx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracer_provider_is_noop_when_endpoint_unset() {
        // #1156: no test mutates AEGIS_OTLP_ENDPOINT globally (env vars are
        // process-global and `cargo test` runs tests concurrently — see the
        // equivalent SQLCipher/#1192 lesson learned in
        // `aegis-storage::db::verify_encryption_or_fail_closed`'s test
        // comments). This only asserts the documented contract holds in
        // whatever ambient env the test happens to run in: if some other
        // process/CI step truly has AEGIS_OTLP_ENDPOINT set, this would
        // build a real (possibly failing-to-connect, but successfully
        // *constructed*) exporter and return Some — which is also a correct
        // demonstration of the contract, so don't assert a fixed branch.
        let result = init_tracer_provider();
        let endpoint_was_set = std::env::var("AEGIS_OTLP_ENDPOINT").is_ok();
        assert_eq!(result.is_some(), endpoint_was_set);
        if let Some(provider) = result {
            shutdown_tracer_provider(&provider);
        }
    }

    #[test]
    fn set_parent_from_headers_is_inert_without_traceparent_header() {
        // No panic, no special-casing required — this exercises the no-op
        // propagator path when neither a `traceparent` header nor OTel
        // configuration is present.
        let headers = axum::http::HeaderMap::new();
        set_parent_from_headers(&headers);
    }

    #[test]
    fn set_parent_from_headers_accepts_a_well_formed_traceparent_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );
        // Without `set_text_map_propagator` having been called (i.e. OTel
        // disabled), the global default propagator is a no-op and this
        // remains inert — still must not panic on a well-formed header.
        set_parent_from_headers(&headers);
    }
}
