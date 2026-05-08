//! Customer-side data-source connector contract.
//!
//! Every sector ships at least one concrete connector — for example,
//! the healthcare crate ships connectors for FHIR R4 and HL7 v2; finance
//! ships FIX 4.4 and FpML; energy ships OPC-UA and IEC 61850.
//!
//! The connector's only job is to **subscribe** to the customer's
//! source-of-record system and emit canonical events (sector-specific) for
//! the workflow engine to seal. Connectors never modify the source system.

use crate::SandboxResult;
use serde::{Deserialize, Serialize};

/// Connector lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorMetadata {
    /// Stable id (e.g., `"fhir_r4_subscription"`, `"opc_ua_subscriber"`).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Protocol family (e.g., `"FHIR R4"`, `"FIX 4.4"`, `"OPC-UA"`).
    pub protocol: String,
    /// Connector version.
    pub version: String,
}

/// Connector configuration. Sector crates extend by wrapping this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    /// Endpoint URL or path.
    pub endpoint: String,
    /// Optional auth token (sandbox / dev only — production uses HSM-bound creds).
    pub auth_token: Option<String>,
    /// Maximum events to consume per call. `None` = unlimited.
    pub max_events: Option<usize>,
    /// Sector-specific extension fields.
    #[serde(default)]
    pub extension: serde_json::Map<String, serde_json::Value>,
}

impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            auth_token: None,
            max_events: Some(1000),
            extension: serde_json::Map::new(),
        }
    }
}

/// Universal connector contract.
///
/// `Item` is the sector-specific event type (e.g., a parsed FHIR Bundle, a
/// FIX message, an OPC-UA tag change). The workflow engine consumes these
/// items, runs them through the policy engine, and produces seals.
///
/// This is the synchronous variant. With the `async` feature, sector crates
/// may also use `AsyncConnector` (provided in their own crates).
pub trait Connector {
    /// The event type emitted by this connector.
    type Item;

    /// Connector metadata.
    fn metadata(&self) -> ConnectorMetadata;

    /// Open / initialise. Idempotent.
    fn open(&mut self) -> SandboxResult<()>;

    /// Pull next event. `Ok(None)` means no more events available right now.
    fn next(&mut self) -> SandboxResult<Option<Self::Item>>;

    /// Close. Idempotent.
    fn close(&mut self) -> SandboxResult<()>;
}

/// Trivial in-memory connector for tests / quick demos.
///
/// Sector crates use this in their unit tests so workflows can be exercised
/// without a real source system.
#[derive(Debug)]
pub struct VecConnector<T> {
    metadata: ConnectorMetadata,
    items: std::collections::VecDeque<T>,
    open: bool,
}

impl<T> VecConnector<T> {
    /// New connector with the given metadata and items.
    pub fn new(metadata: ConnectorMetadata, items: Vec<T>) -> Self {
        Self {
            metadata,
            items: items.into(),
            open: false,
        }
    }
}

impl<T> Connector for VecConnector<T> {
    type Item = T;

    fn metadata(&self) -> ConnectorMetadata {
        self.metadata.clone()
    }

    fn open(&mut self) -> SandboxResult<()> {
        self.open = true;
        Ok(())
    }

    fn next(&mut self) -> SandboxResult<Option<T>> {
        Ok(self.items.pop_front())
    }

    fn close(&mut self) -> SandboxResult<()> {
        self.open = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_connector_drains_in_order() {
        let mut c = VecConnector::new(
            ConnectorMetadata {
                id: "test".into(),
                label: "Test".into(),
                protocol: "memory".into(),
                version: "0.1.0".into(),
            },
            vec![1, 2, 3],
        );
        c.open().unwrap();
        assert_eq!(c.next().unwrap(), Some(1));
        assert_eq!(c.next().unwrap(), Some(2));
        assert_eq!(c.next().unwrap(), Some(3));
        assert_eq!(c.next().unwrap(), None);
        c.close().unwrap();
    }
}
