//! Real zkML proof verification interfaces.
//!
//! The v0.2.0 / v0.2.1 `ProofArtefact` was metadata-only: hashes of the
//! circuit, public inputs, proof blob, and verifier key — but no actual
//! verification path. This module fills the gap.
//!
//! ## What this module does
//!
//! - Defines [`ZkmlVerifier`] — the pluggable contract every proving
//!   backend implements (EZKL, RISC Zero, Modulus Remainder, Plonky2,
//!   Groth16).
//! - Defines [`ZkmlVerificationInput`] — the bundle a verifier needs:
//!   proof bytes, public inputs, verifier key.
//! - Ships [`MockZkmlVerifier`] for tests / CI: structurally checks the
//!   `ProofArtefact` lines up with the verification input but doesn't run
//!   the actual cryptographic verifier (that lives in dedicated proving
//!   crates).
//! - Ships [`ZkmlVerifierRegistry`] — routes a `ProofArtefact` to the
//!   right verifier based on `ProofSystem`.
//!
//! ## What this module deliberately does *not* do
//!
//! Bundle EZKL / Halo2 / Risc0 / Plonky2 / Groth16 verification crates.
//! Those are large, frequently-broken-by-upstream-versions, and have
//! conflicting transitive deps. Production deployments wire their
//! preferred backend behind this trait. We ship a `MockZkmlVerifier` and
//! a recipe.

use crate::hashing::{Hasher, Sha256Digest};
use crate::zkml::{ProofArtefact, ProofSystem};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ZkmlVerificationInput
// =============================================================================

/// The bundle a verifier consumes.
///
/// Customers receive this bundle from their prover process; the verifier
/// hashes the components and cross-checks them against the seal's
/// `ProofArtefact` before running the real cryptographic verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkmlVerificationInput {
    /// Stable circuit/program id (e.g., `"credit-decision-circuit-v3"`).
    pub circuit_id: String,
    /// Raw proof blob bytes (varies by system).
    pub proof_bytes: Vec<u8>,
    /// Public-inputs vector (system-specific encoding).
    pub public_inputs: Vec<u8>,
    /// Verifier key bytes (system-specific encoding).
    pub verifier_key: Vec<u8>,
    /// Proof system the bundle was produced for.
    pub system: ProofSystem,
}

impl ZkmlVerificationInput {
    /// Compute the hashes we cross-check against `ProofArtefact`.
    pub fn compute_hashes(&self) -> ZkmlInputHashes {
        ZkmlInputHashes {
            circuit_hash: Hasher::sha256(self.circuit_id.as_bytes()),
            proof_blob_hash: Hasher::sha256(&self.proof_bytes),
            public_inputs_hash: Hasher::sha256(&self.public_inputs),
            verifier_key_hash: Hasher::sha256(&self.verifier_key),
        }
    }
}

/// Hashes derived from a verification input — cross-checked against
/// `ProofArtefact`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkmlInputHashes {
    /// Circuit id hash.
    pub circuit_hash: Sha256Digest,
    /// Proof blob hash.
    pub proof_blob_hash: Sha256Digest,
    /// Public-inputs hash.
    pub public_inputs_hash: Sha256Digest,
    /// Verifier-key hash.
    pub verifier_key_hash: Sha256Digest,
}

// =============================================================================
// ZkmlVerifier trait
// =============================================================================

/// Pluggable zkML verifier.
///
/// Production backends wire this trait to their proving crate of choice:
///
/// - **EZKL** → `aethelred-zkml-ezkl`
/// - **RISC Zero** → `aethelred-zkml-risc0`
/// - **Modulus Remainder** → `aethelred-zkml-modulus`
/// - **Plonky2 / 3** → `aethelred-zkml-plonky2`
/// - **Groth16** → `aethelred-zkml-groth16`
pub trait ZkmlVerifier: Send + Sync {
    /// Proof system this verifier handles.
    fn system(&self) -> ProofSystem;

    /// Verify the input. Returns `Ok(())` if the proof is valid.
    fn verify(&self, input: &ZkmlVerificationInput) -> SandboxResult<()>;
}

// =============================================================================
// MockZkmlVerifier
// =============================================================================

/// Mock verifier — structural checks only. Use for tests / CI.
///
/// Real verifiers do these structural checks AND run the cryptographic
/// verify against the proof bytes. This mock is the *floor*, not a
/// replacement.
pub struct MockZkmlVerifier {
    system: ProofSystem,
    /// If `true`, also fails when proof bytes are empty (catches obvious
    /// upstream bugs).
    require_nonempty_proof: bool,
}

impl MockZkmlVerifier {
    /// New mock verifier.
    pub fn new(system: ProofSystem) -> Self {
        Self {
            system,
            require_nonempty_proof: true,
        }
    }

    /// Allow empty proof bytes (test scaffolds only).
    pub fn allow_empty_proof(mut self) -> Self {
        self.require_nonempty_proof = false;
        self
    }
}

impl ZkmlVerifier for MockZkmlVerifier {
    fn system(&self) -> ProofSystem {
        self.system
    }
    fn verify(&self, input: &ZkmlVerificationInput) -> SandboxResult<()> {
        if input.system != self.system {
            return Err(SandboxError::Zkml {
                system: self.system.as_str().into(),
                reason: format!(
                    "proof system mismatch: input={:?} verifier={:?}",
                    input.system, self.system
                ),
            });
        }
        if self.require_nonempty_proof && input.proof_bytes.is_empty() {
            return Err(SandboxError::Zkml {
                system: self.system.as_str().into(),
                reason: "empty proof bytes".into(),
            });
        }
        if input.public_inputs.is_empty() {
            return Err(SandboxError::Zkml {
                system: self.system.as_str().into(),
                reason: "empty public-inputs vector".into(),
            });
        }
        if input.verifier_key.is_empty() {
            return Err(SandboxError::Zkml {
                system: self.system.as_str().into(),
                reason: "empty verifier key".into(),
            });
        }
        Ok(())
    }
}

// =============================================================================
// Cross-check (artefact ↔ input)
// =============================================================================

/// Cross-check a `ProofArtefact` against a `ZkmlVerificationInput`. Confirms
/// that the four hashes in the artefact match the hashes computed from the
/// real input bytes.
pub fn cross_check(
    artefact: &ProofArtefact,
    input: &ZkmlVerificationInput,
) -> SandboxResult<()> {
    if artefact.system != input.system {
        return Err(SandboxError::Zkml {
            system: artefact.system.as_str().into(),
            reason: format!(
                "system mismatch: artefact={:?} input={:?}",
                artefact.system, input.system
            ),
        });
    }
    let hashes = input.compute_hashes();
    if hashes.circuit_hash != artefact.circuit_hash {
        return Err(SandboxError::Zkml {
            system: artefact.system.as_str().into(),
            reason: "circuit_hash mismatch".into(),
        });
    }
    if hashes.proof_blob_hash != artefact.proof_blob_hash {
        return Err(SandboxError::Zkml {
            system: artefact.system.as_str().into(),
            reason: "proof_blob_hash mismatch".into(),
        });
    }
    if hashes.public_inputs_hash != artefact.public_inputs_hash {
        return Err(SandboxError::Zkml {
            system: artefact.system.as_str().into(),
            reason: "public_inputs_hash mismatch".into(),
        });
    }
    if hashes.verifier_key_hash != artefact.verifier_key_hash {
        return Err(SandboxError::Zkml {
            system: artefact.system.as_str().into(),
            reason: "verifier_key_hash mismatch".into(),
        });
    }
    Ok(())
}

// =============================================================================
// ZkmlVerifierRegistry
// =============================================================================

/// Routes a proof to the right verifier by `ProofSystem`.
pub struct ZkmlVerifierRegistry {
    verifiers: RwLock<HashMap<ProofSystem, Box<dyn ZkmlVerifier>>>,
}

impl Default for ZkmlVerifierRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkmlVerifierRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self {
            verifiers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a verifier.
    pub fn register(&self, verifier: Box<dyn ZkmlVerifier>) {
        let s = verifier.system();
        let mut g = match self.verifiers.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.insert(s, verifier);
    }

    /// `true` if a verifier is registered for `system`.
    pub fn has(&self, system: ProofSystem) -> bool {
        self.verifiers
            .read()
            .map(|g| g.contains_key(&system))
            .unwrap_or(false)
    }

    /// Number of registered verifiers.
    pub fn len(&self) -> usize {
        self.verifiers.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Verify an input via the registered verifier.
    pub fn verify(&self, input: &ZkmlVerificationInput) -> SandboxResult<()> {
        let g = self.verifiers.read().map_err(|_| SandboxError::Zkml {
            system: input.system.as_str().into(),
            reason: "zkml registry poisoned".into(),
        })?;
        let v = g.get(&input.system).ok_or_else(|| SandboxError::Zkml {
            system: input.system.as_str().into(),
            reason: "no verifier registered".into(),
        })?;
        v.verify(input)
    }

    /// Verify an artefact against an input — cross-checks first, then
    /// runs the cryptographic verifier.
    pub fn verify_artefact(
        &self,
        artefact: &ProofArtefact,
        input: &ZkmlVerificationInput,
    ) -> SandboxResult<()> {
        cross_check(artefact, input)?;
        self.verify(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(system: ProofSystem) -> ZkmlVerificationInput {
        ZkmlVerificationInput {
            circuit_id: "test-circuit".into(),
            proof_bytes: b"proof-bytes".to_vec(),
            public_inputs: b"pi".to_vec(),
            verifier_key: b"vk".to_vec(),
            system,
        }
    }

    fn matching_artefact(input: &ZkmlVerificationInput) -> ProofArtefact {
        let h = input.compute_hashes();
        ProofArtefact {
            system: input.system,
            circuit_hash: h.circuit_hash,
            public_inputs_hash: h.public_inputs_hash,
            proof_blob_hash: h.proof_blob_hash,
            verifier_key_hash: h.verifier_key_hash,
            verified: true,
        }
    }

    #[test]
    fn input_compute_hashes_is_deterministic() {
        let i = input(ProofSystem::Ezkl);
        let h1 = i.compute_hashes();
        let h2 = i.compute_hashes();
        assert_eq!(h1, h2);
    }

    #[test]
    fn cross_check_accepts_matching() {
        let i = input(ProofSystem::Ezkl);
        let a = matching_artefact(&i);
        cross_check(&a, &i).unwrap();
    }

    #[test]
    fn cross_check_rejects_system_mismatch() {
        let i = input(ProofSystem::Ezkl);
        let mut a = matching_artefact(&i);
        a.system = ProofSystem::RiscZero;
        assert!(cross_check(&a, &i).is_err());
    }

    #[test]
    fn cross_check_rejects_circuit_hash_mismatch() {
        let i = input(ProofSystem::Ezkl);
        let mut a = matching_artefact(&i);
        a.circuit_hash = Hasher::sha256(b"different");
        assert!(cross_check(&a, &i).is_err());
    }

    #[test]
    fn cross_check_rejects_proof_hash_mismatch() {
        let i = input(ProofSystem::Ezkl);
        let mut a = matching_artefact(&i);
        a.proof_blob_hash = Hasher::sha256(b"different");
        assert!(cross_check(&a, &i).is_err());
    }

    #[test]
    fn cross_check_rejects_public_inputs_mismatch() {
        let i = input(ProofSystem::Ezkl);
        let mut a = matching_artefact(&i);
        a.public_inputs_hash = Hasher::sha256(b"different");
        assert!(cross_check(&a, &i).is_err());
    }

    #[test]
    fn cross_check_rejects_verifier_key_mismatch() {
        let i = input(ProofSystem::Ezkl);
        let mut a = matching_artefact(&i);
        a.verifier_key_hash = Hasher::sha256(b"different");
        assert!(cross_check(&a, &i).is_err());
    }

    #[test]
    fn mock_verifier_accepts_well_formed() {
        let i = input(ProofSystem::Ezkl);
        let v = MockZkmlVerifier::new(ProofSystem::Ezkl);
        v.verify(&i).unwrap();
    }

    #[test]
    fn mock_verifier_rejects_empty_proof() {
        let mut i = input(ProofSystem::Ezkl);
        i.proof_bytes.clear();
        let v = MockZkmlVerifier::new(ProofSystem::Ezkl);
        assert!(v.verify(&i).is_err());
    }

    #[test]
    fn mock_verifier_rejects_empty_pi() {
        let mut i = input(ProofSystem::Ezkl);
        i.public_inputs.clear();
        let v = MockZkmlVerifier::new(ProofSystem::Ezkl);
        assert!(v.verify(&i).is_err());
    }

    #[test]
    fn mock_verifier_rejects_empty_vk() {
        let mut i = input(ProofSystem::Ezkl);
        i.verifier_key.clear();
        let v = MockZkmlVerifier::new(ProofSystem::Ezkl);
        assert!(v.verify(&i).is_err());
    }

    #[test]
    fn mock_verifier_allow_empty_proof_works() {
        let mut i = input(ProofSystem::Ezkl);
        i.proof_bytes.clear();
        let v = MockZkmlVerifier::new(ProofSystem::Ezkl).allow_empty_proof();
        v.verify(&i).unwrap();
    }

    #[test]
    fn mock_verifier_rejects_system_mismatch() {
        let i = input(ProofSystem::RiscZero);
        let v = MockZkmlVerifier::new(ProofSystem::Ezkl);
        assert!(v.verify(&i).is_err());
    }

    #[test]
    fn registry_routes_to_correct_verifier() {
        let r = ZkmlVerifierRegistry::new();
        r.register(Box::new(MockZkmlVerifier::new(ProofSystem::Ezkl)));
        r.register(Box::new(MockZkmlVerifier::new(ProofSystem::RiscZero)));
        assert!(r.has(ProofSystem::Ezkl));
        assert!(r.has(ProofSystem::RiscZero));
        assert!(!r.has(ProofSystem::Plonky2));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn registry_unknown_system_errors() {
        let r = ZkmlVerifierRegistry::new();
        let i = input(ProofSystem::Plonky2);
        assert!(r.verify(&i).is_err());
    }

    #[test]
    fn registry_verify_artefact_full_path() {
        let r = ZkmlVerifierRegistry::new();
        r.register(Box::new(MockZkmlVerifier::new(ProofSystem::Ezkl)));
        let i = input(ProofSystem::Ezkl);
        let a = matching_artefact(&i);
        r.verify_artefact(&a, &i).unwrap();
    }

    #[test]
    fn registry_verify_artefact_rejects_mismatched_artefact() {
        let r = ZkmlVerifierRegistry::new();
        r.register(Box::new(MockZkmlVerifier::new(ProofSystem::Ezkl)));
        let i = input(ProofSystem::Ezkl);
        let mut a = matching_artefact(&i);
        a.proof_blob_hash = Hasher::sha256(b"tampered");
        assert!(r.verify_artefact(&a, &i).is_err());
    }

    #[test]
    fn input_serde_round_trip() {
        let i = input(ProofSystem::Groth16);
        let j = serde_json::to_string(&i).unwrap();
        let p: ZkmlVerificationInput = serde_json::from_str(&j).unwrap();
        assert_eq!(p.circuit_id, i.circuit_id);
        assert_eq!(p.system, i.system);
    }

    #[test]
    fn hashes_serde_round_trip() {
        let i = input(ProofSystem::Ezkl);
        let h = i.compute_hashes();
        let j = serde_json::to_string(&h).unwrap();
        let p: ZkmlInputHashes = serde_json::from_str(&j).unwrap();
        assert_eq!(p, h);
    }

    #[test]
    fn registry_default_is_empty() {
        let r = ZkmlVerifierRegistry::default();
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn all_proof_systems_have_string_ids() {
        for s in [
            ProofSystem::Ezkl,
            ProofSystem::RiscZero,
            ProofSystem::ModulusRemainder,
            ProofSystem::Plonky2,
            ProofSystem::Groth16,
            ProofSystem::None,
        ] {
            assert!(!s.as_str().is_empty());
        }
    }
}
