//! Connector lookup by `connector_type`. The registry is the only path from
//! a broker tool registration (`broker_tools.connector_type`, Phase 6.2) to
//! executable code — an unregistered type fails closed in the executor, it
//! never falls through to some default connector.

use std::collections::HashMap;
use std::sync::Arc;

use aegis_tool_broker_core::Connector;

/// An immutable map of `connector_type` → [`Connector`]. Built once at
/// startup (builder-style [`ConnectorRegistry::register`]), then shared.
#[derive(Default, Clone)]
pub struct ConnectorRegistry {
    connectors: HashMap<&'static str, Arc<dyn Connector>>,
}

impl ConnectorRegistry {
    /// Adds a connector under its own [`Connector::connector_type`]. A
    /// second registration of the same type replaces the first — last one
    /// wins, deliberately simple.
    pub fn register(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connectors
            .insert(connector.connector_type(), connector);
        self
    }

    pub fn get(&self, connector_type: &str) -> Option<Arc<dyn Connector>> {
        self.connectors.get(connector_type).cloned()
    }

    /// The registered type names, sorted — for diagnostics and `GET` listings.
    pub fn types(&self) -> Vec<&'static str> {
        let mut types: Vec<&'static str> = self.connectors.keys().copied().collect();
        types.sort_unstable();
        types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubConnector;
    use crate::http::HttpConnector;

    #[test]
    fn registry_finds_connectors_by_type_and_misses_fail_none() {
        let registry = ConnectorRegistry::default()
            .register(Arc::new(GithubConnector::mock()))
            .register(Arc::new(HttpConnector::new()));
        assert!(registry.get("github").is_some());
        assert!(registry.get("http").is_some());
        assert!(registry.get("smtp").is_none());
        assert_eq!(registry.types(), vec!["github", "http"]);
    }
}
