//! Cross-chain anchoring — anchor seal-bundle hashes to multiple chains
//! for redundancy.
//!
//! [`crate::anchor`] is single-chain; this module orchestrates `M-of-N`
//! anchoring across multiple chains so the protocol survives any one chain
//! losing data. Examples of target chains: Aethelred mainnet, Bitcoin
//! (via OpenTimestamps-style attestation), Ethereum (via a registry
//! contract), an internal regulator-managed chain, etc.

use crate::hashing::Sha256Digest;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ChainId
// =============================================================================

/// Identifier for one target chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(pub String);

impl ChainId {
    /// New id.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// ChainReceipt
// =============================================================================

/// One per-chain anchor receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainReceipt {
    /// Stable id.
    pub receipt_id: Uuid,
    /// Target chain.
    pub chain_id: ChainId,
    /// On-chain transaction id (or block reference).
    pub tx_id: String,
    /// Anchored hash.
    pub anchored_hash: Sha256Digest,
    /// RFC 3339 anchored at.
    pub anchored_at: String,
    /// `true` if confirmed (sufficient confirmations).
    pub confirmed: bool,
    /// Optional explorer URL.
    pub explorer_url: Option<String>,
}

// =============================================================================
// CrossChainStatus
// =============================================================================

/// Aggregate status across chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossChainStatus {
    /// Pending anchors (below threshold).
    Pending,
    /// Threshold met (≥ M of N anchored and confirmed).
    Anchored,
    /// All chains anchored and confirmed.
    FullyAnchored,
    /// Failed (cannot reach threshold).
    Failed,
}

// =============================================================================
// CrossChainBundle
// =============================================================================

/// One anchored bundle across chains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossChainBundle {
    /// Stable id.
    pub bundle_id: Uuid,
    /// Hash being anchored (typically a Merkle root over many seals).
    pub root_hash: Sha256Digest,
    /// Target chain ids.
    pub target_chains: Vec<ChainId>,
    /// Threshold M (chains required for `Anchored`).
    pub threshold_m: u32,
    /// Per-chain receipts (one per chain attempted).
    pub receipts: HashMap<ChainId, ChainReceipt>,
    /// RFC 3339 created at.
    pub created_at: String,
    /// Status as last computed.
    pub status: CrossChainStatus,
}

impl CrossChainBundle {
    /// Number of confirmed receipts.
    pub fn confirmed_count(&self) -> u32 {
        self.receipts.values().filter(|r| r.confirmed).count() as u32
    }
    /// Compute current status.
    pub fn compute_status(&self) -> CrossChainStatus {
        let n = self.target_chains.len() as u32;
        let confirmed = self.confirmed_count();
        if confirmed == n && n > 0 {
            return CrossChainStatus::FullyAnchored;
        }
        if confirmed >= self.threshold_m {
            return CrossChainStatus::Anchored;
        }
        // Failed if remaining chains can't reach threshold.
        let attempted = self.receipts.len() as u32;
        let remaining = n.saturating_sub(attempted);
        if confirmed + remaining < self.threshold_m {
            return CrossChainStatus::Failed;
        }
        CrossChainStatus::Pending
    }
}

// =============================================================================
// CrossChainAnchor
// =============================================================================

#[derive(Default)]
struct State {
    bundles: HashMap<Uuid, CrossChainBundle>,
}

/// Multi-chain anchor coordinator.
pub struct CrossChainAnchor {
    state: RwLock<State>,
}

impl Default for CrossChainAnchor {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for CrossChainAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrossChainAnchor")
            .field("bundles", &self.len())
            .finish()
    }
}

impl CrossChainAnchor {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new bundle.
    pub fn open(
        &self,
        root_hash: Sha256Digest,
        target_chains: Vec<ChainId>,
        threshold_m: u32,
    ) -> SandboxResult<CrossChainBundle> {
        let n = target_chains.len() as u32;
        if threshold_m == 0 || threshold_m > n {
            return Err(SandboxError::Other(format!(
                "invalid threshold {} for n={}",
                threshold_m, n
            )));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let b = CrossChainBundle {
            bundle_id: Uuid::now_v7(),
            root_hash,
            target_chains,
            threshold_m,
            receipts: HashMap::new(),
            created_at: now,
            status: CrossChainStatus::Pending,
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cross-chain anchor poisoned".into()))?;
        g.bundles.insert(b.bundle_id, b.clone());
        Ok(b)
    }

    /// Record a per-chain receipt.
    pub fn record_receipt(
        &self,
        bundle_id: Uuid,
        chain: ChainId,
        tx_id: impl Into<String>,
        confirmed: bool,
    ) -> SandboxResult<ChainReceipt> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cross-chain anchor poisoned".into()))?;
        let b = g
            .bundles
            .get_mut(&bundle_id)
            .ok_or_else(|| SandboxError::Other(format!("bundle {} not found", bundle_id)))?;
        if !b.target_chains.contains(&chain) {
            return Err(SandboxError::Other(format!(
                "chain {} not in target chains",
                chain.as_str()
            )));
        }
        if b.receipts.contains_key(&chain) {
            return Err(SandboxError::Other(format!(
                "receipt for chain {} already recorded",
                chain.as_str()
            )));
        }
        let receipt = ChainReceipt {
            receipt_id: Uuid::now_v7(),
            chain_id: chain.clone(),
            tx_id: tx_id.into(),
            anchored_hash: b.root_hash.clone(),
            anchored_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            confirmed,
            explorer_url: None,
        };
        b.receipts.insert(chain, receipt.clone());
        b.status = b.compute_status();
        Ok(receipt)
    }

    /// Mark a previously-recorded receipt as confirmed.
    pub fn mark_confirmed(&self, bundle_id: Uuid, chain: &ChainId) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cross-chain anchor poisoned".into()))?;
        let b = g
            .bundles
            .get_mut(&bundle_id)
            .ok_or_else(|| SandboxError::Other(format!("bundle {} not found", bundle_id)))?;
        let r = b
            .receipts
            .get_mut(chain)
            .ok_or_else(|| {
                SandboxError::Other(format!(
                    "no receipt for chain {} on bundle {}",
                    chain.as_str(),
                    bundle_id
                ))
            })?;
        r.confirmed = true;
        b.status = b.compute_status();
        Ok(())
    }

    /// Lookup bundle.
    pub fn bundle(&self, id: Uuid) -> Option<CrossChainBundle> {
        self.state.read().ok()?.bundles.get(&id).cloned()
    }
    /// All bundles.
    pub fn all(&self) -> Vec<CrossChainBundle> {
        self.state
            .read()
            .map(|g| g.bundles.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Filter by status.
    pub fn by_status(&self, s: CrossChainStatus) -> Vec<CrossChainBundle> {
        self.all().into_iter().filter(|b| b.status == s).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.bundles.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hasher;

    fn h() -> Sha256Digest {
        Hasher::sha256(b"root")
    }

    fn chains3() -> Vec<ChainId> {
        vec![
            ChainId::new("aethelred"),
            ChainId::new("ethereum"),
            ChainId::new("bitcoin"),
        ]
    }

    #[test]
    fn open_with_valid_threshold() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        assert_eq!(b.threshold_m, 2);
        assert_eq!(b.status, CrossChainStatus::Pending);
    }

    #[test]
    fn open_invalid_threshold_errors() {
        let a = CrossChainAnchor::new();
        assert!(a.open(h(), chains3(), 0).is_err());
        assert!(a.open(h(), chains3(), 10).is_err());
    }

    #[test]
    fn record_receipt_increments() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-1", true)
            .unwrap();
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.receipts.len(), 1);
    }

    #[test]
    fn duplicate_receipt_errors() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-1", true)
            .unwrap();
        assert!(a
            .record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-2", true)
            .is_err());
    }

    #[test]
    fn unknown_chain_rejected() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        assert!(a
            .record_receipt(b.bundle_id, ChainId::new("solana"), "tx-1", true)
            .is_err());
    }

    #[test]
    fn threshold_reached_status_anchored() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-1", true)
            .unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("ethereum"), "tx-2", true)
            .unwrap();
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.status, CrossChainStatus::Anchored);
    }

    #[test]
    fn all_chains_makes_fully_anchored() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        for c in &chains3() {
            a.record_receipt(b.bundle_id, c.clone(), "tx", true).unwrap();
        }
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.status, CrossChainStatus::FullyAnchored);
    }

    #[test]
    fn confirmed_count_excludes_unconfirmed() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-1", false)
            .unwrap();
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.confirmed_count(), 0);
    }

    #[test]
    fn mark_confirmed_advances_status() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-1", false)
            .unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("ethereum"), "tx-2", false)
            .unwrap();
        a.mark_confirmed(b.bundle_id, &ChainId::new("aethelred"))
            .unwrap();
        a.mark_confirmed(b.bundle_id, &ChainId::new("ethereum"))
            .unwrap();
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.status, CrossChainStatus::Anchored);
    }

    #[test]
    fn mark_confirmed_unknown_errors() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        assert!(a
            .mark_confirmed(b.bundle_id, &ChainId::new("aethelred"))
            .is_err());
    }

    #[test]
    fn failed_when_too_few_remaining() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 3).unwrap();
        // Anchor only one chain unconfirmed-style, then mark all attempted.
        a.record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx-1", false)
            .unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("ethereum"), "tx-2", false)
            .unwrap();
        a.record_receipt(b.bundle_id, ChainId::new("bitcoin"), "tx-3", false)
            .unwrap();
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.status, CrossChainStatus::Failed);
    }

    #[test]
    fn by_status_filters() {
        let a = CrossChainAnchor::new();
        let b1 = a.open(h(), chains3(), 2).unwrap();
        a.open(h(), chains3(), 2).unwrap();
        a.record_receipt(b1.bundle_id, ChainId::new("aethelred"), "tx", true)
            .unwrap();
        a.record_receipt(b1.bundle_id, ChainId::new("ethereum"), "tx", true)
            .unwrap();
        assert_eq!(a.by_status(CrossChainStatus::Anchored).len(), 1);
        assert_eq!(a.by_status(CrossChainStatus::Pending).len(), 1);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let a = CrossChainAnchor::new();
        assert!(a.bundle(Uuid::now_v7()).is_none());
    }

    #[test]
    fn registry_count_tracks() {
        let a = CrossChainAnchor::new();
        assert!(a.is_empty());
        a.open(h(), chains3(), 2).unwrap();
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn bundle_serde() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        let j = serde_json::to_string(&b).unwrap();
        let p: CrossChainBundle = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn receipt_serde() {
        let r = ChainReceipt {
            receipt_id: Uuid::now_v7(),
            chain_id: ChainId::new("x"),
            tx_id: "tx".into(),
            anchored_hash: h(),
            anchored_at: "t".into(),
            confirmed: true,
            explorer_url: Some("https://x.test/tx".into()),
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: ChainReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn chain_id_serde_transparent() {
        let id = ChainId::new("ethereum");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"ethereum\"");
    }

    #[test]
    fn status_serde() {
        for s in [
            CrossChainStatus::Pending,
            CrossChainStatus::Anchored,
            CrossChainStatus::FullyAnchored,
            CrossChainStatus::Failed,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CrossChainStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn record_unknown_bundle_errors() {
        let a = CrossChainAnchor::new();
        assert!(a
            .record_receipt(Uuid::now_v7(), ChainId::new("x"), "tx", true)
            .is_err());
    }

    #[test]
    fn mark_confirmed_unknown_bundle_errors() {
        let a = CrossChainAnchor::new();
        assert!(a
            .mark_confirmed(Uuid::now_v7(), &ChainId::new("x"))
            .is_err());
    }

    #[test]
    fn anchored_hash_matches_root() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        let r = a
            .record_receipt(b.bundle_id, ChainId::new("aethelred"), "tx", true)
            .unwrap();
        assert_eq!(r.anchored_hash, h());
    }

    #[test]
    fn receipt_count_reflects_chains() {
        let a = CrossChainAnchor::new();
        let b = a.open(h(), chains3(), 2).unwrap();
        for c in &chains3() {
            a.record_receipt(b.bundle_id, c.clone(), "tx", false).unwrap();
        }
        let updated = a.bundle(b.bundle_id).unwrap();
        assert_eq!(updated.receipts.len(), 3);
    }
}
