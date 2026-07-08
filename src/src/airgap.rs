//! #1297: air-gapped deployment kill-switch.
//!
//! Previously "air-gapped mode" meant nothing more than "the operator chose
//! not to set any of the optional external-integration env vars" -- there
//! was no enforcement. A misconfigured air-gapped deployment (e.g.
//! `AEGIS_AIRGAP=true` alongside a leftover `AEGIS_OTLP_ENDPOINT` from a
//! previous non-air-gapped config) would silently phone home instead of
//! failing loudly.

/// Every env var whose presence causes the gateway to make outbound network
/// calls to a service other than its own configured database/Redis. Purely
/// local config (DB tuning, JWT/receipt-signing secrets, feature-flag
/// toggles, CORS origins, local filesystem paths) is deliberately excluded.
const NETWORK_EGRESS_ENV_VARS: &[&str] = &[
    "AEGIS_QDRANT_URL",
    "AEGIS_OTLP_ENDPOINT",
    "AEGIS_ADMISSION_WEBHOOK_URL",
    "AEGIS_SPLUNK_HEC_URL",
    "AEGIS_KMS_KEY_URI",
    "AEGIS_GITHUB_APP_TOKEN",
    "ANTHROPIC_API_KEY",
];

/// Fails closed when `AEGIS_AIRGAP=true` is set alongside any env var that
/// implies outbound network egress to an external service. A no-op when
/// `AEGIS_AIRGAP` is unset or set to any other value.
pub fn verify_airgap_or_fail_closed() -> Result<(), String> {
    let airgap_enabled = std::env::var("AEGIS_AIRGAP")
        .map(|v| v == "true")
        .unwrap_or(false);
    if !airgap_enabled {
        return Ok(());
    }

    let conflicting: Vec<&str> = NETWORK_EGRESS_ENV_VARS
        .iter()
        .filter(|var| std::env::var(var).is_ok())
        .copied()
        .collect();

    if conflicting.is_empty() {
        return Ok(());
    }

    Err(format!(
        "AEGIS_AIRGAP=true is set, but the following env var(s) that imply outbound \
         network egress are also set: {}. Air-gapped deployments must not configure \
         external integrations. Refusing to start -- unset AEGIS_AIRGAP or the \
         conflicting var(s).",
        conflicting.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global; serialize tests that mutate them so
    // parallel test threads in this file don't race on the same vars.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_all() {
        std::env::remove_var("AEGIS_AIRGAP");
        for var in NETWORK_EGRESS_ENV_VARS {
            std::env::remove_var(var);
        }
    }

    #[test]
    fn is_noop_when_airgap_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        assert!(verify_airgap_or_fail_closed().is_ok());
    }

    #[test]
    fn is_noop_when_airgap_true_and_no_conflicting_vars_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        std::env::set_var("AEGIS_AIRGAP", "true");
        let result = verify_airgap_or_fail_closed();
        clear_all();
        assert!(result.is_ok());
    }

    #[test]
    fn fails_closed_when_airgap_true_and_otlp_endpoint_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        std::env::set_var("AEGIS_AIRGAP", "true");
        std::env::set_var("AEGIS_OTLP_ENDPOINT", "http://collector:4318");
        let result = verify_airgap_or_fail_closed();
        clear_all();
        let err = result.expect_err("must fail closed");
        assert!(err.contains("AEGIS_OTLP_ENDPOINT"));
    }

    #[test]
    fn fails_closed_and_lists_all_conflicting_vars() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        std::env::set_var("AEGIS_AIRGAP", "true");
        std::env::set_var("AEGIS_QDRANT_URL", "http://qdrant:6333");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-test");
        let result = verify_airgap_or_fail_closed();
        clear_all();
        let err = result.expect_err("must fail closed");
        assert!(err.contains("AEGIS_QDRANT_URL"));
        assert!(err.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn is_noop_when_airgap_set_to_non_true_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_all();
        std::env::set_var("AEGIS_AIRGAP", "false");
        std::env::set_var("AEGIS_OTLP_ENDPOINT", "http://collector:4318");
        let result = verify_airgap_or_fail_closed();
        clear_all();
        assert!(result.is_ok());
    }
}
