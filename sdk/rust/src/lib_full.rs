//! Full SDK compatibility module.
//!
//! This module exists so downstream integrators and reviewers can locate a
//! single "full surface" export in the Rust SDK crate when the `full-sdk`
//! feature is enabled.

pub use crate::core;
pub use crate::crypto;
pub use crate::jobs;
pub use crate::models;
pub use crate::nn;
pub use crate::optim;
pub use crate::runtime;
pub use crate::seals;
pub use crate::tensor;
pub use crate::validators;
pub use crate::verification;

pub use crate::AethelredClient;
pub use crate::Network;
pub use crate::AUTHOR;
pub use crate::LICENSE;
pub use crate::VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_module_exposes_version() {
        assert!(!VERSION.is_empty());
    }
}
