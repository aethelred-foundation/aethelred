//! Defense protocol envelopes (STANAG / DDS / MIL-STD-1553 / DIS / Link 16).

use aethelred_sandbox_core::{Hasher, Sha256Digest};
use serde::{Deserialize, Serialize};

/// Defense protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefenseProtocol {
    /// NATO STANAG 4586 — UAV control system interoperability.
    Stanag4586,
    /// NATO STANAG 4671 — UAV airworthiness.
    Stanag4671,
    /// NATO STANAG 4660 — interoperable command + control data link (IC2DL).
    Stanag4660,
    /// OMG Data Distribution Service (real-time pub-sub for autonomous platforms).
    Dds,
    /// MIL-STD-1553 / 1553B (avionics serial bus).
    MilStd1553,
    /// ARINC 429 / ARINC 664 / AFDX.
    Arinc664,
    /// JREAP-C (Joint Range Extension Applications Protocol, RFC-style over TCP/IP).
    JreapC,
    /// Link 16 (TADIL-J).
    Link16,
    /// DIS (Distributed Interactive Simulation, IEEE 1278).
    Dis,
    /// HLA (High Level Architecture, IEEE 1516).
    Hla,
    /// Internal mission system.
    Internal,
}

impl DefenseProtocol {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stanag4586 => "stanag_4586",
            Self::Stanag4671 => "stanag_4671",
            Self::Stanag4660 => "stanag_4660",
            Self::Dds => "dds",
            Self::MilStd1553 => "mil_std_1553",
            Self::Arinc664 => "arinc_664",
            Self::JreapC => "jreap_c",
            Self::Link16 => "link_16",
            Self::Dis => "dis",
            Self::Hla => "hla",
            Self::Internal => "internal",
        }
    }
}

/// Defense message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefenseMessageEnvelope {
    /// Protocol family.
    pub protocol: DefenseProtocol,
    /// Message type / J-series number / DDS topic.
    pub message_type: String,
    /// Source platform / system id (e.g., `"micropolis-ugv-1"`, `"steerai-flight-1"`).
    pub source_platform: String,
    /// Correlation id.
    pub correlation_id: String,
    /// Hash of canonicalised message.
    pub raw_message_hash: Sha256Digest,
}

impl DefenseMessageEnvelope {
    /// Hash the envelope for use as a seal `event_hash`.
    pub fn event_hash(&self) -> aethelred_sandbox_core::SandboxResult<Sha256Digest> {
        Hasher::hash_value(self)
    }
}
