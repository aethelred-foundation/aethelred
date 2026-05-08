//! Finance-protocol shape adapters.
//!
//! These are *minimal* representations of canonical finance messages, used to
//! produce a deterministic content hash for the seal. We do not reimplement
//! FIX / FpML / ISO 20022 in full — sector connectors do that. The adapters
//! here capture the smallest set of fields a sandbox needs to seal an event
//! and project it into the regulator-shape views.

use aethelred_sandbox_core::{Hasher, Sha256Digest};
use serde::{Deserialize, Serialize};

/// Protocol family of a finance message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinanceProtocol {
    /// FIX 4.4 (Financial Information eXchange).
    Fix44,
    /// FIX 5.0 SP2.
    Fix50Sp2,
    /// FpML (Financial Products Markup Language).
    Fpml,
    /// ISO 20022 (e.g., pacs.008, camt.054, pain.001).
    Iso20022,
    /// SWIFT MT (legacy).
    SwiftMt,
    /// Bank-internal proprietary format.
    Internal,
}

impl FinanceProtocol {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fix44 => "fix_4_4",
            Self::Fix50Sp2 => "fix_5_0_sp2",
            Self::Fpml => "fpml",
            Self::Iso20022 => "iso_20022",
            Self::SwiftMt => "swift_mt",
            Self::Internal => "internal",
        }
    }
}

/// Minimal finance-message envelope for sandbox-shape sealing.
///
/// Only the fields we actually hash into the seal are present here. Full
/// message content stays at the connector / source-of-record layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinanceMessageEnvelope {
    /// Protocol family.
    pub protocol: FinanceProtocol,
    /// Message type (e.g., `"NewOrderSingle"`, `"pacs.008"`, `"MT103"`).
    pub message_type: String,
    /// Sender id.
    pub sender_id: String,
    /// Receiver id.
    pub receiver_id: String,
    /// Correlation id.
    pub correlation_id: String,
    /// Hash of the raw message (computed at the connector — never the raw bytes).
    pub raw_message_hash: Sha256Digest,
}

impl FinanceMessageEnvelope {
    /// Hash the envelope for use as a seal `event_hash`.
    pub fn event_hash(&self) -> aethelred_sandbox_core::SandboxResult<Sha256Digest> {
        Hasher::hash_value(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_ids_unique() {
        let all = [
            FinanceProtocol::Fix44,
            FinanceProtocol::Fix50Sp2,
            FinanceProtocol::Fpml,
            FinanceProtocol::Iso20022,
            FinanceProtocol::SwiftMt,
            FinanceProtocol::Internal,
        ];
        let mut ids: Vec<&str> = all.iter().map(|p| p.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn envelope_event_hash_is_deterministic() {
        let env = FinanceMessageEnvelope {
            protocol: FinanceProtocol::Fix44,
            message_type: "NewOrderSingle".into(),
            sender_id: "FAB".into(),
            receiver_id: "EXCHANGE".into(),
            correlation_id: "ord-1".into(),
            raw_message_hash: Hasher::sha256(b"raw"),
        };
        let h1 = env.event_hash().unwrap();
        let h2 = env.event_hash().unwrap();
        assert_eq!(h1, h2);
    }
}
