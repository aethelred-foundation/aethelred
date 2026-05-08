//! Healthcare protocol envelopes.

use aethelred_sandbox_core::{Hasher, Sha256Digest};
use serde::{Deserialize, Serialize};

/// Healthcare protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthcareProtocol {
    /// FHIR R4 (HL7 Fast Healthcare Interoperability Resources).
    FhirR4,
    /// HL7 v2.5 messages (ORU, ADT, ORM, etc.).
    Hl7V25,
    /// DICOM 3.0 (medical imaging).
    Dicom30,
    /// CDA (Clinical Document Architecture).
    Cda,
    /// IHE XCA / XDS-b (cross-enterprise document sharing).
    IheXdsb,
    /// VCF (Variant Call Format) for genomics.
    Vcf,
    /// GA4GH (Global Alliance for Genomics & Health) htsget / refget.
    Ga4gh,
    /// ICH E2B(R3) for pharmacovigilance.
    IchE2br3,
    /// Internal payor format (e.g., Daman claims schema).
    Internal,
}

impl HealthcareProtocol {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FhirR4 => "fhir_r4",
            Self::Hl7V25 => "hl7_v2_5",
            Self::Dicom30 => "dicom_3_0",
            Self::Cda => "cda",
            Self::IheXdsb => "ihe_xdsb",
            Self::Vcf => "vcf",
            Self::Ga4gh => "ga4gh",
            Self::IchE2br3 => "ich_e2b_r3",
            Self::Internal => "internal",
        }
    }
}

/// Minimal healthcare-message envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcareMessageEnvelope {
    /// Protocol family.
    pub protocol: HealthcareProtocol,
    /// Resource / message type (e.g., `"DocumentReference"`, `"ORU_R01"`,
    /// `"DICOM-SR"`, `"VCF-Variant"`).
    pub resource_type: String,
    /// Source-of-record system identifier (e.g., `"epic-cosmos-1"`,
    /// `"oracle-millennium-1"`, `"malaffi"`).
    pub source_system: String,
    /// Correlation id (e.g., `Bundle.id`, `Encounter.id`).
    pub correlation_id: String,
    /// Hash of the canonicalised message.
    pub raw_message_hash: Sha256Digest,
}

impl HealthcareMessageEnvelope {
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
            HealthcareProtocol::FhirR4,
            HealthcareProtocol::Hl7V25,
            HealthcareProtocol::Dicom30,
            HealthcareProtocol::Cda,
            HealthcareProtocol::IheXdsb,
            HealthcareProtocol::Vcf,
            HealthcareProtocol::Ga4gh,
            HealthcareProtocol::IchE2br3,
            HealthcareProtocol::Internal,
        ];
        let mut ids: Vec<&str> = all.iter().map(|p| p.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }
}
