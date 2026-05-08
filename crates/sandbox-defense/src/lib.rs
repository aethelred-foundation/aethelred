//! # Aethelred Infinity Sandbox — Defense AI Assurance
//!
//! Production-grade verification & evidence layer for defense AI:
//! autonomous logistics, sensor fusion, AI-assisted manufacturing inspection,
//! and cyber-defense decisioning. Built on
//! [`aethelred_sandbox_core`].
//!
//! ## Air-gap mode
//!
//! When `DefenseSandbox::builder().air_gap(true)` is set, the sandbox refuses
//! to call any external service for attestation, proving, or anchoring. This
//! is the default posture for classified / TS-SCI-adjacent environments.
//!
//! ## Plug-and-play
//!
//! ```no_run
//! use aethelred_sandbox_defense::prelude::*;
//!
//! let sandbox = DefenseSandbox::quickstart("EDGE").unwrap();
//! let seal = sandbox.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
//! ```

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::result_large_err)]

pub mod fixtures;
pub mod policy;
pub mod prelude;
pub mod protocols;
pub mod regulators;
pub mod sandbox;
pub mod workflows;

pub use fixtures::{DefenseFixture, DefenseFixtures};
pub use sandbox::{DefenseSandbox, DefenseSandboxBuilder};
pub use workflows::autonomous_logistics::{AutonomousLogistics, AutonomousLogisticsSeal};
pub use workflows::cyber_defense::{CyberDefenseEvent, CyberDefenseSeal};
pub use workflows::inspection_qa::{InspectionQa, InspectionQaSeal};
pub use workflows::sensor_fusion::{SensorFusion, SensorFusionSeal};

pub use aethelred_sandbox_core as core;
