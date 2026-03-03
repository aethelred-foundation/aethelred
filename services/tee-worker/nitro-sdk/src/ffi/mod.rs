//! # Foreign Function Interface
//!
//! Bindings for Python, JavaScript/WASM, and Go.

/// Python bindings (via PyO3)
#[cfg(feature = "python")]
pub mod python;

/// WASM bindings
#[cfg(feature = "wasm")]
pub mod wasm;

/// C ABI for Go/other languages
pub mod c_api;

pub use c_api::*;
