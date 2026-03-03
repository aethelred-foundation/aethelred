//! Offline-compatible entrypoint for `aethelred-py`.
//!
//! The full Python extension is available behind the `python-bindings` feature.

#[cfg(feature = "python-bindings")]
include!("lib_full.rs");

#[cfg(not(feature = "python-bindings"))]
/// A lightweight marker exported in strict offline mode.
pub const OFFLINE_STUB: &str = "aethelred-py offline stub";
