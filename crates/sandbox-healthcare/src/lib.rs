//! # Aethelred Infinity Sandbox — Healthcare AI Assurance
//!
//! Production-grade verification & evidence layer for healthcare AI:
//! genomics interpretation, clinical AI (radiology / pathology), ambient
//! documentation, and claims adjudication. Built on
//! [`aethelred_sandbox_core`].
//!
//! ## Plug-and-play (3 lines)
//!
//! ```no_run
//! use aethelred_sandbox_healthcare::prelude::*;
//!
//! let sandbox = HealthcareSandbox::quickstart("M42").unwrap();
//! let seal = sandbox.seal_genomics_inference(GenomicsInference::demo()).unwrap();
//! println!("Sealed: {}", seal.id_string());
//! ```
//!
//! ## Workflows
//!
//! - [`workflows::genomics`] — variant interpretation seal (VCF / GA4GH).
//! - [`workflows::clinical_ai`] — radiology / pathology AI (DICOM / PACS).
//! - [`workflows::ambient_scribe`] — FHIR R4 DocumentReference for AI notes.
//! - [`workflows::claims`] — adjudication seal (Daman use case).
//!
//! ## Regulators
//!
//! Seven supported regulator-shape views: DoH / DHA / MOHAP / EHS / HIPAA /
//! EU AI Act high-risk Annex III §3 / NHRA.

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::result_large_err)]

pub mod fixtures;
pub mod policy;
pub mod prelude;
pub mod protocols;
pub mod regulators;
pub mod sandbox;
pub mod workflows;

pub use fixtures::{HealthcareFixture, HealthcareFixtures};
pub use sandbox::{HealthcareSandbox, HealthcareSandboxBuilder};
pub use workflows::ambient_scribe::{AmbientNote, AmbientNoteSeal};
pub use workflows::claims::{ClaimsAdjudication, ClaimsAdjudicationSeal};
pub use workflows::clinical_ai::{ClinicalInference, ClinicalInferenceSeal};
pub use workflows::genomics::{GenomicsInference, GenomicsInferenceSeal};

pub use aethelred_sandbox_core as core;
