//! Quantization support (feature-gated placeholder module).
//!
//! This placeholder keeps the crate module tree complete for tooling and
//! packaging. Quantization functionality for the Rust SDK is planned to be
//! implemented behind the `quantize` feature.

#![allow(missing_docs)]

use crate::core::error::{AethelredError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantizationType {
    Int8,
    Int4,
    FP16,
    BF16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantizationScheme {
    PerTensorAffine,
    PerChannelAffine,
    Symmetric,
}

#[derive(Debug, Clone, Default)]
pub struct QuantizationConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct QuantizationEngine;

#[derive(Debug, Clone, Default)]
pub struct QATEngine;

#[derive(Debug, Clone, Default)]
pub struct QuantizedLinear;

pub fn not_available() -> Result<()> {
    Err(AethelredError::Unknown(
        "quantize feature is enabled but the quantize module is a placeholder in this SDK build"
            .to_string(),
    ))
}
