//! Offline-compatible entrypoint for `aethelred-sdk`.
//!
//! In strict offline mode we compile a lightweight stub surface by default.
//! Enable the `full-sdk` feature to compile the complete SDK implementation.

pub(crate) mod serde_arrays;

#[cfg(feature = "full-sdk")]
#[path = "lib_full.rs"]
mod lib_full;

#[cfg(feature = "full-sdk")]
pub use lib_full::*;

#[cfg(all(not(feature = "full-sdk"), feature = "attestation-evidence"))]
pub mod compliance {
    /// Minimal jurisdiction enum used by the attestation module in evidence mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
    pub enum Jurisdiction {
        /// Global/default jurisdiction for offline evidence tests.
        Global,
    }
}

#[cfg(all(not(feature = "full-sdk"), feature = "attestation-evidence"))]
pub mod attestation;

#[cfg(all(not(feature = "full-sdk"), feature = "attestation-evidence"))]
pub use attestation::*;

#[cfg(not(any(feature = "full-sdk", feature = "attestation-evidence")))]
mod offline {
    /// SDK version.
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");

    /// SDK name.
    pub const NAME: &str = "Aethelred SDK (offline stub)";

    /// Build timestamp placeholder.
    pub const BUILD_TIME: &str = env!("CARGO_PKG_VERSION");

    /// Feature flags exposed by the offline stub.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct Features {
        /// Python bindings enabled.
        pub python_bindings: bool,
        /// WASM bindings enabled.
        pub wasm_bindings: bool,
        /// Intel SGX support enabled.
        pub intel_sgx: bool,
        /// AMD SEV support enabled.
        pub amd_sev: bool,
        /// gRPC support enabled.
        pub grpc: bool,
    }

    /// Version information returned in offline mode.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct VersionInfo {
        /// SDK name.
        pub name: String,
        /// SDK version.
        pub version: String,
        /// Enabled features.
        pub features: Features,
    }

    /// Return SDK version info in offline mode.
    pub fn version_info() -> VersionInfo {
        VersionInfo {
            name: NAME.to_string(),
            version: VERSION.to_string(),
            features: Features {
                python_bindings: false,
                wasm_bindings: false,
                intel_sgx: false,
                amd_sev: false,
                grpc: false,
            },
        }
    }
}

#[cfg(not(any(feature = "full-sdk", feature = "attestation-evidence")))]
pub use offline::*;

#[cfg(test)]
mod source_presence_tests {
    #[test]
    fn lib_full_source_is_present() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib_full.rs");
        assert!(
            path.exists(),
            "expected full SDK source file at {}",
            path.display()
        );
    }
}
