//! Distributed tracing and metrics export via OpenTelemetry OTLP (#1156, #1287).
//!
//! Entirely opt-in via `AEGIS_OTLP_ENDPOINT`. Unset, [`init_tracer_provider`]
//! and [`init_meter_provider`] return `None` and nothing about
//! tracing/logging/metrics changes from before this module existed — no
//! exporter is built, no extra `tracing_subscriber` layer is registered, and
//! the global OTel propagator/meter stay the no-op defaults. Set, spans
//! recorded via `#[tracing::instrument]` throughout the gateway (see
//! `authorize_action`, `PolicyEngine::authorize`, `compute_receipt_hash`,
//! `insert_approval`) and the metrics below are exported in OTLP/protobuf
//! over HTTP to the given collector endpoint, batched in the background.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::metrics::SecurityMetrics;

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

/// Builds and globally registers an OTLP metric exporter pointed at the same
/// `AEGIS_OTLP_ENDPOINT` used for traces (#1287), returning the provider so
/// the caller can shut it down on exit. Returns `None` when the env var is
/// unset.
///
/// Registers two observable counters that mirror the existing
/// `SecurityMetrics` atomics already exposed on the Prometheus `/metrics`
/// endpoint — `approval_hash_mismatch_total` and `provenance_denials_total`
/// — read at each periodic-export tick rather than incremented separately,
/// so `SecurityMetrics` (in `lib/common`, intentionally OTel-agnostic) never
/// needs to know OTel exists. The third named metric,
/// `authorize_latency_seconds`, is a true per-request histogram and is
/// recorded directly via [`record_authorize_latency`] at its measurement
/// site in `routes::authorize_decision::write_decision_and_audit` — an
/// observable instrument can't backfill individual sample latencies, only a
/// synchronous one can.
pub fn init_meter_provider(metrics: Arc<SecurityMetrics>) -> Option<SdkMeterProvider> {
    let endpoint = std::env::var("AEGIS_OTLP_ENDPOINT").ok()?;

    let exporter = match opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_endpoint(&endpoint)
        .build()
    {
        Ok(exporter) => exporter,
        Err(e) => {
            tracing::error!(
                "Failed to build OTLP metric exporter for AEGIS_OTLP_ENDPOINT={}: {:?}",
                endpoint,
                e
            );
            return None;
        }
    };

    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .build();

    opentelemetry::global::set_meter_provider(provider.clone());

    let meter = opentelemetry::global::meter("aegis-gateway");

    let hash_mismatch_metrics = metrics.clone();
    let _ = meter
        .u64_observable_counter("approval_hash_mismatch_total")
        .with_description("Number of approve-then-swap / hash-mismatch events detected")
        .with_callback(move |observer| {
            observer.observe(
                hash_mismatch_metrics
                    .approval_hash_mismatch_total
                    .load(Ordering::Relaxed),
                &[],
            );
        })
        .build();

    let provenance_metrics = metrics;
    let _ = meter
        .u64_observable_counter("provenance_denials_total")
        .with_description(
            "Number of mutating-action denials due to untrusted/malicious/unknown source provenance",
        )
        .with_callback(move |observer| {
            observer.observe(
                provenance_metrics
                    .provenance_denials_total
                    .load(Ordering::Relaxed),
                &[],
            );
        })
        .build();

    tracing::info!("OTLP metrics export enabled, exporting to {}", endpoint);
    Some(provider)
}

/// Flushes any metrics still buffered and shuts the provider down.
/// Best-effort — logged, not propagated, mirroring [`shutdown_tracer_provider`].
pub fn shutdown_meter_provider(provider: &SdkMeterProvider) {
    if let Err(e) = provider.shutdown() {
        tracing::warn!("Failed to cleanly shut down OTLP meter provider: {:?}", e);
    }
}

/// Records one `/v1/authorize` decision latency sample on the
/// `authorize_latency_seconds` OTLP histogram (#1287). A no-op when OTel
/// metrics aren't configured: `opentelemetry::global::meter` returns the
/// global no-op meter by default, and instruments built from it have inert
/// `record()` calls — see [`init_meter_provider`].
pub fn record_authorize_latency(duration: std::time::Duration) {
    opentelemetry::global::meter("aegis-gateway")
        .f64_histogram("authorize_latency_seconds")
        .with_description("/v1/authorize end-to-end decision latency")
        .with_unit("s")
        .build()
        .record(duration.as_secs_f64(), &[]);
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
    fn init_meter_provider_is_noop_when_endpoint_unset() {
        // #1287: same ambient-env-aware assertion as
        // `init_tracer_provider_is_noop_when_endpoint_unset` above, and for
        // the same reason — no test mutates AEGIS_OTLP_ENDPOINT globally.
        let metrics = Arc::new(SecurityMetrics::new());
        let result = init_meter_provider(metrics);
        let endpoint_was_set = std::env::var("AEGIS_OTLP_ENDPOINT").is_ok();
        assert_eq!(result.is_some(), endpoint_was_set);
        if let Some(provider) = result {
            shutdown_meter_provider(&provider);
        }
    }

    #[test]
    fn record_authorize_latency_is_inert_without_a_registered_meter_provider() {
        // No panic, no special-casing required — exercises the no-op global
        // meter path when OTel metrics aren't configured.
        record_authorize_latency(std::time::Duration::from_millis(42));
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
