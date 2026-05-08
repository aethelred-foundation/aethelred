//! # Aethelred Infinity Sandbox — Finance AI Assurance
//!
//! Production-grade verification & evidence layer for AI-driven banking
//! workflows: credit underwriting, AML / sanctions screening, algorithmic
//! trading, and client advisory. Built on top of [`aethelred_sandbox_core`].
//!
//! ## Plug-and-play (3 lines)
//!
//! ```no_run
//! use aethelred_sandbox_finance::prelude::*;
//!
//! let sandbox = FinanceSandbox::quickstart("FAB").unwrap();
//! let seal = sandbox.seal_credit_decision(CreditDecision::demo()).unwrap();
//! println!("Sealed: {}", seal.id_string());
//! ```
//!
//! ## Workflows
//!
//! - [`workflows::credit_decision`] — adverse-action seal for credit /
//!   underwriting AI. EU AI Act Annex III §5 high-risk; SR 11-7 / EBA model
//!   risk lineage.
//! - [`workflows::aml_screening`] — per-alert AML / sanctions / PEP screening
//!   evidence. FATF Recommendation 11 retention; CBUAE AML; Wolfsberg.
//! - [`workflows::trading_event`] — order-event seal with risk-limit check.
//!   MAR (EU 596/2014) / MiFID II (Directive 2014/65/EU).
//! - [`workflows::advisory`] — robo-advice / suitability seal with advisor
//!   bind. Fiduciary evidence trail.
//!
//! ## Regulator views
//!
//! Every seal can be projected into a regulator-shape view — same canonical
//! seal, different presentation:
//!
//! - [`regulators::FinanceJurisdiction::Cbuae`]
//! - [`regulators::FinanceJurisdiction::Sca`]
//! - [`regulators::FinanceJurisdiction::Fsra`]
//! - [`regulators::FinanceJurisdiction::Dfsa`]
//! - [`regulators::FinanceJurisdiction::FcaUk`]
//! - [`regulators::FinanceJurisdiction::OccFedFincenUs`]
//! - [`regulators::FinanceJurisdiction::Mas`]
//!
//! ## Protocols
//!
//! Sector-shape adapters for FIX 4.4, FpML, ISO 20022, and SWIFT MT/MX.

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::result_large_err)]

pub mod fixtures;
pub mod policy;
pub mod prelude;
pub mod protocols;
pub mod regulators;
pub mod sandbox;
pub mod workflows;

pub use fixtures::{FinanceFixture, FinanceFixtures};
pub use sandbox::{FinanceSandbox, FinanceSandboxBuilder};
pub use workflows::advisory::{Advisory, AdvisorySeal};
pub use workflows::aml_screening::{AmlAlert, AmlAlertSeal};
pub use workflows::credit_decision::{CreditDecision, CreditDecisionSeal};
pub use workflows::trading_event::{TradingEvent, TradingEventSeal};

/// Re-export of the core crate.
pub use aethelred_sandbox_core as core;
