//! Async API surface for sandbox-core.
//!
//! Gated behind the `async` feature. Enables enterprise users running large
//! concurrent workloads (e.g., a bank ingesting thousands of FIX messages per
//! second, or a hospital streaming FHIR `Subscription` notifications) to use
//! the sandbox without spawning blocking tasks.
//!
//! ## Design
//!
//! All long-running operations on the sandbox are CPU-bound (hashing,
//! Merkle-proof construction). To avoid blocking the executor, we wrap them
//! in [`tokio::task::spawn_blocking`] when the input batch exceeds a
//! threshold. Below the threshold, we run inline — spawning a blocking task
//! per call has overhead.
//!
//! ## Usage
//!
//! ```ignore
//! use aethelred_sandbox_core::prelude::*;
//! use aethelred_sandbox_core::async_api::SandboxAsync;
//!
//! let sb = build_sandbox()?; // (sector-specific)
//! let envs = sb.append_and_envelope_batch_async(seals).await?;
//! let report = sb.audit_trail_async(AuditFormat::Markdown).await?;
//! ```

use crate::audit::AuditFormat;
use crate::evidence::{EvidenceBundle, EvidenceLogEntry};
use crate::sandbox::Sandbox;
use crate::seal::{DigitalSeal, SealEnvelope};
use crate::verify::{VerificationReport, Verifier};
use crate::{SandboxResult, Sha256Digest};
use async_trait::async_trait;

/// Threshold above which we use `spawn_blocking` for batch operations.
/// Below this, we run inline because the overhead of spawning a task
/// outweighs the cost of doing the work directly.
const SPAWN_BLOCKING_THRESHOLD: usize = 16;

/// Async surface for [`Sandbox`].
///
/// Implemented for `Sandbox` itself when the `async` feature is enabled.
#[async_trait]
pub trait SandboxAsync {
    /// Append a single seal asynchronously.
    async fn append_seal_async(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry>;

    /// Append a batch of seals asynchronously.
    async fn append_seals_async(
        &self,
        seals: Vec<DigitalSeal>,
    ) -> SandboxResult<Vec<EvidenceLogEntry>>;

    /// Append + envelope a single seal asynchronously.
    async fn append_and_envelope_async(&self, seal: DigitalSeal) -> SandboxResult<SealEnvelope>;

    /// Append + envelope a batch of seals asynchronously.
    async fn append_and_envelope_batch_async(
        &self,
        seals: Vec<DigitalSeal>,
    ) -> SandboxResult<Vec<SealEnvelope>>;

    /// Export the evidence bundle asynchronously.
    async fn export_evidence_async(&self) -> SandboxResult<EvidenceBundle>;

    /// Render the audit trail asynchronously.
    async fn audit_trail_async(&self, format: AuditFormat) -> SandboxResult<String>;

    /// Compute the current Merkle root asynchronously.
    async fn current_root_async(&self) -> SandboxResult<Sha256Digest>;
}

#[async_trait]
impl SandboxAsync for Sandbox {
    async fn append_seal_async(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> {
        // Single append is cheap; run inline.
        self.append_seal(seal)
    }

    async fn append_seals_async(
        &self,
        seals: Vec<DigitalSeal>,
    ) -> SandboxResult<Vec<EvidenceLogEntry>> {
        if seals.len() < SPAWN_BLOCKING_THRESHOLD {
            return self.append_seals(seals);
        }
        // Use scoped-style: take a clone of the evidence Arc and process on
        // a blocking thread, then return the result.
        let evidence = self.evidence();
        tokio::task::spawn_blocking(move || -> SandboxResult<Vec<EvidenceLogEntry>> {
            let mut out = Vec::with_capacity(seals.len());
            for seal in seals {
                out.push(evidence.append(seal)?);
            }
            Ok(out)
        })
        .await
        .map_err(|e| crate::SandboxError::Other(format!("blocking task: {e}")))?
    }

    async fn append_and_envelope_async(&self, seal: DigitalSeal) -> SandboxResult<SealEnvelope> {
        self.append_and_envelope(seal)
    }

    async fn append_and_envelope_batch_async(
        &self,
        seals: Vec<DigitalSeal>,
    ) -> SandboxResult<Vec<SealEnvelope>> {
        if seals.len() < SPAWN_BLOCKING_THRESHOLD {
            return self.append_and_envelope_batch(seals);
        }
        let evidence = self.evidence();
        tokio::task::spawn_blocking(move || -> SandboxResult<Vec<SealEnvelope>> {
            let mut entries = Vec::with_capacity(seals.len());
            for seal in seals {
                entries.push(evidence.append(seal)?);
            }
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                let proof = evidence.proof(entry.index)?;
                out.push(SealEnvelope {
                    seal: entry.seal,
                    merkle_proof: Some(proof),
                    anchor_block_height: None,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| crate::SandboxError::Other(format!("blocking task: {e}")))?
    }

    async fn export_evidence_async(&self) -> SandboxResult<EvidenceBundle> {
        self.export_evidence()
    }

    async fn audit_trail_async(&self, format: AuditFormat) -> SandboxResult<String> {
        self.audit_trail(format)
    }

    async fn current_root_async(&self) -> SandboxResult<Sha256Digest> {
        self.current_root()
    }
}

/// Async helpers on [`Verifier`].
#[async_trait]
pub trait VerifierAsync {
    /// Verify a batch asynchronously.
    async fn verify_batch_async(
        &self,
        envelopes: Vec<SealEnvelope>,
        expected_root: Sha256Digest,
    ) -> SandboxResult<Vec<VerificationReport>>;
}

#[async_trait]
impl VerifierAsync for Verifier {
    async fn verify_batch_async(
        &self,
        envelopes: Vec<SealEnvelope>,
        expected_root: Sha256Digest,
    ) -> SandboxResult<Vec<VerificationReport>> {
        if envelopes.len() < SPAWN_BLOCKING_THRESHOLD {
            return self.verify_batch(&envelopes, expected_root);
        }
        let v = self.clone();
        tokio::task::spawn_blocking(move || v.verify_batch(&envelopes, expected_root))
            .await
            .map_err(|e| crate::SandboxError::Other(format!("blocking task: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::Hasher;
    use crate::policy::PolicyGate;
    use crate::sandbox::SandboxBuilder;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use crate::tee::TeePlatform;
    use crate::zkml::ProofSystem;
    use crate::Sector;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn dummy_seal(seed: u64) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(format!("event-{seed}").as_bytes()),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(format!("in-{seed}").as_bytes()),
            output_hash: Hasher::sha256(format!("out-{seed}").as_bytes()),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn fab_sandbox() -> Sandbox {
        SandboxBuilder::new(Sector::Finance)
            .tenant("FAB")
            .label("FAB")
            .jurisdiction("AE-CBUAE")
            .tee(TeePlatform::IntelTdx)
            .zkml(ProofSystem::Ezkl)
            .crate_name("test")
            .crate_version("0.2.0")
            .workflow("wf")
            .with_gate(PolicyGate::required("g", "G", "rule"))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn append_seal_async_works() {
        let sb = fab_sandbox();
        let entry = sb.append_seal_async(dummy_seal(0)).await.unwrap();
        assert_eq!(entry.index, 0);
    }

    #[tokio::test]
    async fn append_seals_async_inline_path() {
        let sb = fab_sandbox();
        let seals: Vec<DigitalSeal> = (0..3).map(dummy_seal).collect();
        let entries = sb.append_seals_async(seals).await.unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn append_seals_async_blocking_path() {
        let sb = fab_sandbox();
        let seals: Vec<DigitalSeal> = (0..32).map(dummy_seal).collect();
        let entries = sb.append_seals_async(seals).await.unwrap();
        assert_eq!(entries.len(), 32);
    }

    #[tokio::test]
    async fn append_and_envelope_batch_async_uses_final_root() {
        let sb = fab_sandbox();
        let envs = sb
            .append_and_envelope_batch_async((0..32).map(dummy_seal).collect())
            .await
            .unwrap();
        assert_eq!(envs.len(), 32);
        let root = sb.current_root_async().await.unwrap();
        for e in &envs {
            assert_eq!(e.merkle_proof.as_ref().unwrap().root, root);
        }
    }

    #[tokio::test]
    async fn export_evidence_async_returns_bundle() {
        let sb = fab_sandbox();
        sb.append_seal_async(dummy_seal(0)).await.unwrap();
        let bundle = sb.export_evidence_async().await.unwrap();
        assert_eq!(bundle.entries.len(), 1);
    }

    #[tokio::test]
    async fn audit_trail_async_renders() {
        let sb = fab_sandbox();
        sb.append_seal_async(dummy_seal(0)).await.unwrap();
        let s = sb.audit_trail_async(AuditFormat::Markdown).await.unwrap();
        assert!(s.contains("|"));
    }

    #[tokio::test]
    async fn verify_batch_async_inline_path() {
        let sb = fab_sandbox();
        let envs = sb
            .append_and_envelope_batch_async((0..3).map(dummy_seal).collect())
            .await
            .unwrap();
        let root = sb.current_root_async().await.unwrap();
        let reports = Verifier::default()
            .verify_batch_async(envs, root)
            .await
            .unwrap();
        assert_eq!(reports.len(), 3);
        for r in &reports {
            assert!(r.passed());
        }
    }

    #[tokio::test]
    async fn verify_batch_async_blocking_path() {
        let sb = fab_sandbox();
        let envs = sb
            .append_and_envelope_batch_async((0..32).map(dummy_seal).collect())
            .await
            .unwrap();
        let root = sb.current_root_async().await.unwrap();
        let reports = Verifier::default()
            .verify_batch_async(envs, root)
            .await
            .unwrap();
        assert_eq!(reports.len(), 32);
        for r in &reports {
            assert!(r.passed());
        }
    }
}
