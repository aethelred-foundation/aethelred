//! Healthcare workflows.

pub mod ambient_scribe;
pub mod claims;
pub mod clinical_ai;
pub mod genomics;

pub use ambient_scribe::{AmbientNote, AmbientNoteSeal};
pub use claims::{ClaimsAdjudication, ClaimsAdjudicationSeal};
pub use clinical_ai::{ClinicalInference, ClinicalInferenceSeal};
pub use genomics::{GenomicsInference, GenomicsInferenceSeal};
