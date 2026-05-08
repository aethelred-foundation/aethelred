//! Zero-knowledge ML proof primitives.
//!
//! Like [`crate::tee`], this module is the *receipt* side. Generation lives
//! in dedicated proving crates (planned: `aethelred-zkml-ezkl`,
//! `aethelred-zkml-risc0`, `aethelred-zkml-plonky2`).
//!
//! ## Decision heuristic
//!
//! - Latency budget < 10 ms p99: **don't use zkML**, rely on TEE attestation.
//! - Tabular / decision-shape models, < 50M params, async OK: **EZKL** /
//!   **Modulus Labs Remainder** (Halo2-based).
//! - General programs, batched proofs: **RISC Zero** (zkVM).
//! - High-throughput sealing of small circuits: **Plonky2 / 3** (STARK).
//! - Fixed audited inference, smallest verify: **Groth16**.
//! - Audit-time only (regulator sample-pull, monthly recertification):
//!   any of the above with async generation.

use crate::hashing::Sha256Digest;
use serde::{Deserialize, Serialize};

/// zkML proof system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    /// EZKL — Halo2-based, ONNX in, KZG commitments. Best for small/medium
    /// tabular / decision-shape models.
    Ezkl,
    /// RISC Zero — Risc-V zkVM, STARK proofs, batched. Best for general
    /// programs and audit pipelines.
    RiscZero,
    /// Modulus Labs Remainder — Halo2 + ML gadgets, production-tuned.
    ModulusRemainder,
    /// Plonky2 / Plonky3 — STARK with FRI commitments, recursive composition.
    Plonky2,
    /// Groth16 — pairing-based SNARK, smallest proofs, trusted setup per circuit.
    Groth16,
    /// No proof — the seal carries TEE attestation only.
    None,
}

impl ProofSystem {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ezkl => "ezkl",
            Self::RiscZero => "risc_zero",
            Self::ModulusRemainder => "modulus_remainder",
            Self::Plonky2 => "plonky2",
            Self::Groth16 => "groth16",
            Self::None => "none",
        }
    }

    /// Whether this system supports recursive proof composition (matters for
    /// batched audit pulls).
    pub fn supports_recursion(self) -> bool {
        matches!(self, Self::Plonky2 | Self::RiscZero)
    }
}

/// zkML proof artefact embedded in a [`crate::seal::DigitalSeal`].
///
/// The artefact carries the *hash* of the proof blob and the verifier-key
/// hash. The actual proof bytes are stored alongside the seal in the
/// evidence log — never inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofArtefact {
    /// Proof system used.
    pub system: ProofSystem,
    /// Hash of the circuit / program artefact.
    pub circuit_hash: Sha256Digest,
    /// Hash of the public-inputs vector.
    pub public_inputs_hash: Sha256Digest,
    /// Hash of the proof blob (the proof itself is stored in the evidence log).
    pub proof_blob_hash: Sha256Digest,
    /// Hash of the verifier key.
    pub verifier_key_hash: Sha256Digest,
    /// Verification status (`true` only after a verifier accepted the proof).
    pub verified: bool,
}

impl ProofArtefact {
    /// Construct a placeholder for design-time wiring.
    ///
    /// Sector workflows that require a real proof will refuse to seal when
    /// `system == ProofSystem::None` and the policy gate demands one.
    pub fn placeholder(system: ProofSystem) -> Self {
        Self {
            system,
            circuit_hash: Sha256Digest([0u8; 32]),
            public_inputs_hash: Sha256Digest([0u8; 32]),
            proof_blob_hash: Sha256Digest([0u8; 32]),
            verifier_key_hash: Sha256Digest([0u8; 32]),
            verified: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_system_string_ids_unique() {
        let all = [
            ProofSystem::Ezkl,
            ProofSystem::RiscZero,
            ProofSystem::ModulusRemainder,
            ProofSystem::Plonky2,
            ProofSystem::Groth16,
            ProofSystem::None,
        ];
        let mut ids: Vec<&str> = all.iter().map(|p| p.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn recursive_systems_correctly_classified() {
        assert!(ProofSystem::Plonky2.supports_recursion());
        assert!(ProofSystem::RiscZero.supports_recursion());
        assert!(!ProofSystem::Groth16.supports_recursion());
        assert!(!ProofSystem::Ezkl.supports_recursion());
    }
}
