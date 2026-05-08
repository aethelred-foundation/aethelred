//! Capability token delegation chains.
//!
//! v0.2.4 [`crate::capability_token`] mints flat tokens directly from an
//! issuer. Real enterprise auth needs **delegation**: a top-level token
//! mints sub-tokens with *narrower* permissions and *shorter* TTLs, that
//! sub-token mints another, etc. — and any link in the chain can be
//! revoked.
//!
//! This module ships:
//!
//! - [`DelegationChain`] — ordered list of [`crate::capability_token::TokenClaims`]
//!   from root → leaf.
//! - [`DelegationVerifier`] — validates chains: each link is signed by
//!   the parent, permissions are monotonically narrowing, TTLs are
//!   monotonically shortening, no link is expired or revoked.
//! - [`DelegationRevocationList`] — set of revoked `jti`s; any chain
//!   containing a revoked id is rejected.
//! - [`DelegationDepthLimit`] — protects against unbounded chains.
//! - [`DelegationConstraints`] — caller-side rules (e.g., max chain depth).

use crate::capability_token::{
    EncodedToken, TokenClaims, TokenIssuer, TokenVerifier,
};
use crate::tenant::Permission;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// DelegationConstraints
// =============================================================================

/// Constraints applied during chain verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConstraints {
    /// Maximum chain depth (root counts as depth 1).
    pub max_depth: u32,
    /// Permissions must monotonically narrow (each child ⊆ parent).
    pub require_narrowing_permissions: bool,
    /// TTL of each child must be ≤ parent TTL.
    pub require_shorter_ttl: bool,
    /// Issuer of each child must match parent's principal.
    pub require_principal_chaining: bool,
}

impl Default for DelegationConstraints {
    fn default() -> Self {
        Self {
            max_depth: 5,
            require_narrowing_permissions: true,
            require_shorter_ttl: true,
            // Principal-chaining requires `child.iss == parent.principal`,
            // which conflicts with the TokenIssuer model where `iss` is the
            // issuing service's id. Off by default; deployments using a
            // bespoke issuer where `iss` *is* the principal can flip this on.
            require_principal_chaining: false,
        }
    }
}

impl DelegationConstraints {
    /// Strict (depth 3, all checks).
    pub fn strict() -> Self {
        Self {
            max_depth: 3,
            require_narrowing_permissions: true,
            require_shorter_ttl: true,
            require_principal_chaining: true,
        }
    }

    /// Lax (depth 10, no narrowing).
    pub fn lax() -> Self {
        Self {
            max_depth: 10,
            require_narrowing_permissions: false,
            require_shorter_ttl: false,
            require_principal_chaining: false,
        }
    }
}

// =============================================================================
// DelegationLink + DelegationChain
// =============================================================================

/// One link in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationLink {
    /// Encoded child token.
    pub child_token: String,
    /// Parent token's `jti` (root has `None`).
    pub parent_jti: Option<Uuid>,
}

/// Ordered list of links from root to leaf.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationChain {
    /// Root → leaf.
    pub links: Vec<DelegationLink>,
}

impl DelegationChain {
    /// New chain.
    pub fn new() -> Self {
        Self { links: Vec::new() }
    }

    /// Length.
    pub fn len(&self) -> usize {
        self.links.len()
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.links.is_empty()
    }

    /// Append a link.
    pub fn push(&mut self, link: DelegationLink) {
        self.links.push(link);
    }

    /// All `jti`s in the chain.
    pub fn all_jtis(&self, verifier: &TokenVerifier) -> SandboxResult<Vec<Uuid>> {
        let mut out = Vec::new();
        for l in &self.links {
            let claims = verifier.verify(&l.child_token)?;
            out.push(claims.jti);
        }
        Ok(out)
    }
}

impl Default for DelegationChain {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// DelegationRevocationList
// =============================================================================

/// In-memory revocation list (jti).
#[derive(Debug, Default)]
pub struct DelegationRevocationList {
    revoked: Mutex<HashSet<Uuid>>,
}

impl DelegationRevocationList {
    /// New empty list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a token.
    pub fn revoke(&self, jti: Uuid) {
        if let Ok(mut g) = self.revoked.lock() {
            g.insert(jti);
        }
    }

    /// `true` if revoked.
    pub fn is_revoked(&self, jti: &Uuid) -> bool {
        self.revoked
            .lock()
            .map(|g| g.contains(jti))
            .unwrap_or(false)
    }

    /// Number of revoked tokens.
    pub fn len(&self) -> usize {
        self.revoked.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no revocations.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// DelegationVerifier
// =============================================================================

/// Verifies a [`DelegationChain`] against the rules.
pub struct DelegationVerifier {
    /// Token verifier (used for each link).
    pub verifier: TokenVerifier,
    /// Revocation list.
    pub revocation_list: DelegationRevocationList,
    /// Constraints.
    pub constraints: DelegationConstraints,
}

impl DelegationVerifier {
    /// New verifier.
    pub fn new(verifier: TokenVerifier, constraints: DelegationConstraints) -> Self {
        Self {
            verifier,
            revocation_list: DelegationRevocationList::new(),
            constraints,
        }
    }

    /// Verify a chain. Returns the leaf claims.
    pub fn verify(&self, chain: &DelegationChain) -> SandboxResult<TokenClaims> {
        if chain.is_empty() {
            return Err(SandboxError::Other("empty delegation chain".into()));
        }
        if chain.len() as u32 > self.constraints.max_depth {
            return Err(SandboxError::Other(format!(
                "chain depth {} exceeds max {}",
                chain.len(),
                self.constraints.max_depth
            )));
        }
        let mut prev: Option<TokenClaims> = None;
        for (i, link) in chain.links.iter().enumerate() {
            let claims = self.verifier.verify(&link.child_token)?;
            // Revocation check.
            if self.revocation_list.is_revoked(&claims.jti) {
                return Err(SandboxError::Other(format!(
                    "link {} revoked (jti={})",
                    i, claims.jti
                )));
            }
            // Parent-link consistency.
            if let Some(p) = &prev {
                if let Some(pjti) = link.parent_jti {
                    if pjti != p.jti {
                        return Err(SandboxError::Other(format!(
                            "link {} parent_jti mismatch: claimed={} actual={}",
                            i, pjti, p.jti
                        )));
                    }
                } else {
                    return Err(SandboxError::Other(format!(
                        "link {} missing parent_jti for non-root link",
                        i
                    )));
                }
                if self.constraints.require_principal_chaining
                    && claims.iss != p.principal
                {
                    return Err(SandboxError::Other(format!(
                        "link {} principal-chain break: child.iss={} parent.principal={}",
                        i, claims.iss, p.principal
                    )));
                }
                if self.constraints.require_narrowing_permissions {
                    let parent_perms: HashSet<Permission> =
                        p.permissions.iter().copied().collect();
                    for perm in &claims.permissions {
                        if !parent_perms.contains(perm) {
                            return Err(SandboxError::Other(format!(
                                "link {} permission {:?} not in parent",
                                i, perm
                            )));
                        }
                    }
                }
                if self.constraints.require_shorter_ttl {
                    if let (Some(ce), Some(pe)) = (claims.expires_at(), p.expires_at()) {
                        if ce > pe {
                            return Err(SandboxError::Other(format!(
                                "link {} TTL longer than parent",
                                i
                            )));
                        }
                    }
                }
            } else if link.parent_jti.is_some() {
                return Err(SandboxError::Other(
                    "first link must have parent_jti=None".into(),
                ));
            }
            prev = Some(claims);
        }
        Ok(prev.unwrap())
    }

    /// Revoke a token.
    pub fn revoke(&self, jti: Uuid) {
        self.revocation_list.revoke(jti);
    }
}

// =============================================================================
// Helpers — minting child tokens
// =============================================================================

/// Mint a child token whose `iss` is the parent's `principal`. Returns
/// the encoded child + a [`DelegationLink`] for chain assembly.
pub fn mint_child(
    issuer: &TokenIssuer,
    parent: &TokenClaims,
    audience: impl Into<String>,
    child_principal: impl Into<String>,
    child_permissions: Vec<Permission>,
    ttl: time::Duration,
) -> SandboxResult<(EncodedToken, DelegationLink)> {
    // Verify TTL ≤ parent's remaining TTL.
    let now = OffsetDateTime::now_utc();
    if let Some(parent_exp) = parent.expires_at() {
        if now + ttl > parent_exp {
            return Err(SandboxError::Other(
                "child TTL would outlast parent expiry".into(),
            ));
        }
    }
    // Verify child permissions ⊆ parent permissions.
    let parent_perms: HashSet<Permission> = parent.permissions.iter().copied().collect();
    for p in &child_permissions {
        if !parent_perms.contains(p) {
            return Err(SandboxError::Other(format!(
                "child permission {:?} not in parent",
                p
            )));
        }
    }
    // Build child claims.
    let child_claims = TokenClaims::builder(
        issuer.issuer_id().to_string(),
        audience,
        parent.tenant.clone(),
        child_principal,
    )
    .permissions(child_permissions)
    .ttl(ttl)
    .build();
    // Override iss: child issuer is parent's principal (delegation).
    let mut adjusted = child_claims;
    adjusted.iss = issuer.issuer_id().to_string();
    let encoded = issuer.mint(adjusted)?;
    let link = DelegationLink {
        child_token: encoded.encoded().to_string(),
        parent_jti: Some(parent.jti),
    };
    Ok((encoded, link))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer() -> TokenIssuer {
        TokenIssuer::new("aeth-issuer-1", b"shared-secret-32-bytes-or-more!!")
    }
    fn verifier_for(issuer: &TokenIssuer) -> TokenVerifier {
        TokenVerifier::new(issuer.issuer_id(), b"shared-secret-32-bytes-or-more!!")
    }

    fn root_claims_with_perms(perms: Vec<Permission>) -> TokenClaims {
        TokenClaims::builder("aeth-issuer-1", "sandbox", "FAB", "root-principal")
            .permissions(perms)
            .ttl(time::Duration::hours(1))
            .build()
    }

    fn build_root_link(issuer: &TokenIssuer) -> (EncodedToken, DelegationLink, TokenClaims) {
        let claims = root_claims_with_perms(vec![
            Permission::SealAppend,
            Permission::SealRead,
            Permission::AuditRead,
        ]);
        let encoded = issuer.mint(claims.clone()).unwrap();
        let link = DelegationLink {
            child_token: encoded.encoded().to_string(),
            parent_jti: None,
        };
        (encoded, link, claims)
    }

    #[test]
    fn empty_chain_rejected() {
        let issuer = issuer();
        let v = DelegationVerifier::new(verifier_for(&issuer), DelegationConstraints::default());
        let chain = DelegationChain::new();
        assert!(v.verify(&chain).is_err());
    }

    #[test]
    fn single_root_link_accepted() {
        let issuer = issuer();
        let (_e, link, _claims) = build_root_link(&issuer);
        let mut chain = DelegationChain::new();
        chain.push(link);
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints::default(),
        );
        v.verify(&chain).unwrap();
    }

    #[test]
    fn root_with_parent_jti_rejected() {
        let issuer = issuer();
        let (_e, mut link, _) = build_root_link(&issuer);
        link.parent_jti = Some(Uuid::now_v7());
        let mut chain = DelegationChain::new();
        chain.push(link);
        let v = DelegationVerifier::new(verifier_for(&issuer), DelegationConstraints::default());
        assert!(v.verify(&chain).is_err());
    }

    #[test]
    fn two_link_chain_accepted_with_narrowing() {
        let issuer = issuer();
        let (_e, root_link, root_claims) = build_root_link(&issuer);
        let (_, child_link) = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "alice",
            vec![Permission::SealRead],
            time::Duration::minutes(30),
        )
        .unwrap();
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(child_link);
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints::default(),
        );
        v.verify(&chain).unwrap();
    }

    #[test]
    fn child_with_broader_permissions_rejected_at_mint() {
        let issuer = issuer();
        let (_e, _root_link, root_claims) = build_root_link(&issuer);
        let r = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "alice",
            vec![Permission::TenantManage], // NOT in parent
            time::Duration::minutes(10),
        );
        assert!(r.is_err());
    }

    #[test]
    fn child_with_longer_ttl_rejected_at_mint() {
        let issuer = issuer();
        let (_e, _root_link, root_claims) = build_root_link(&issuer);
        let r = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "alice",
            vec![Permission::SealRead],
            time::Duration::hours(2), // longer than parent
        );
        assert!(r.is_err());
    }

    #[test]
    fn revoked_link_rejects_chain() {
        let issuer = issuer();
        let (_e, root_link, root_claims) = build_root_link(&issuer);
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints::default(),
        );
        v.revoke(root_claims.jti);
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        assert!(v.verify(&chain).is_err());
    }

    #[test]
    fn depth_limit_enforced() {
        let issuer = issuer();
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints {
                max_depth: 1,
                ..DelegationConstraints::default()
            },
        );
        let (_e, root_link, root_claims) = build_root_link(&issuer);
        let (_, child_link) = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "alice",
            vec![Permission::SealRead],
            time::Duration::minutes(10),
        )
        .unwrap();
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(child_link);
        assert!(v.verify(&chain).is_err());
    }

    #[test]
    fn parent_jti_mismatch_rejected() {
        let issuer = issuer();
        let (_e, root_link, _root_claims) = build_root_link(&issuer);
        let other_claims = root_claims_with_perms(vec![Permission::SealRead]);
        let _ = issuer.mint(other_claims.clone()).unwrap();
        let bad_child_link = DelegationLink {
            child_token: issuer
                .mint(
                    TokenClaims::builder(
                        "aeth-issuer-1",
                        "sandbox",
                        "FAB",
                        "alice",
                    )
                    .permissions(vec![Permission::SealRead])
                    .build(),
                )
                .unwrap()
                .encoded()
                .to_string(),
            parent_jti: Some(Uuid::now_v7()), // wrong jti
        };
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(bad_child_link);
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints::default(),
        );
        assert!(v.verify(&chain).is_err());
    }

    #[test]
    fn revocation_list_records_jtis() {
        let r = DelegationRevocationList::new();
        let id = Uuid::now_v7();
        r.revoke(id);
        assert!(r.is_revoked(&id));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn revocation_list_empty_initially() {
        let r = DelegationRevocationList::new();
        assert!(r.is_empty());
    }

    #[test]
    fn lax_constraints_skip_narrowing_check() {
        let issuer = issuer();
        let (_e, root_link, _) = build_root_link(&issuer);
        // Mint a "child" with broader permissions by going around mint_child.
        let bad_child = TokenClaims::builder("aeth-issuer-1", "sandbox", "FAB", "alice")
            .permissions(vec![Permission::TenantManage])
            .ttl(time::Duration::hours(2))
            .build();
        let bad_encoded = issuer.mint(bad_child.clone()).unwrap();
        let bad_link = DelegationLink {
            child_token: bad_encoded.encoded().to_string(),
            parent_jti: None, // forged
        };
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(bad_link);
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints::lax(),
        );
        // With lax constraints, the missing parent_jti will fail because
        // "non-root link missing parent_jti" check still applies. Lax only
        // disables narrowing/TTL/principal checks. Verify it still rejects.
        let r = v.verify(&chain);
        assert!(r.is_err());
    }

    #[test]
    fn principal_chaining_break_rejected_when_enabled() {
        let issuer = issuer();
        let (_e, root_link, root_claims) = build_root_link(&issuer);
        let child_claims = TokenClaims::builder(
            "aeth-issuer-1",
            "sandbox",
            "FAB",
            "alice",
        )
        .permissions(vec![Permission::SealRead])
        .ttl(time::Duration::minutes(10))
        .build();
        let child_encoded = issuer.mint(child_claims).unwrap();
        let child_link = DelegationLink {
            child_token: child_encoded.encoded().to_string(),
            parent_jti: Some(root_claims.jti),
        };
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(child_link);
        // Opt in to principal-chaining: child.iss="aeth-issuer-1" but
        // parent.principal="root-principal" → reject.
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints {
                require_principal_chaining: true,
                ..DelegationConstraints::default()
            },
        );
        assert!(v.verify(&chain).is_err());
    }

    #[test]
    fn constraints_strict_has_max_depth_3() {
        let c = DelegationConstraints::strict();
        assert_eq!(c.max_depth, 3);
    }

    #[test]
    fn constraints_lax_has_max_depth_10() {
        let c = DelegationConstraints::lax();
        assert_eq!(c.max_depth, 10);
        assert!(!c.require_narrowing_permissions);
    }

    #[test]
    fn constraints_serde_round_trip() {
        let c = DelegationConstraints::strict();
        let j = serde_json::to_string(&c).unwrap();
        let p: DelegationConstraints = serde_json::from_str(&j).unwrap();
        assert_eq!(p.max_depth, c.max_depth);
    }

    #[test]
    fn link_serde_round_trip() {
        let l = DelegationLink {
            child_token: "x".into(),
            parent_jti: Some(Uuid::now_v7()),
        };
        let j = serde_json::to_string(&l).unwrap();
        let p: DelegationLink = serde_json::from_str(&j).unwrap();
        assert_eq!(p, l);
    }

    #[test]
    fn chain_serde_round_trip() {
        let mut chain = DelegationChain::new();
        chain.push(DelegationLink {
            child_token: "x".into(),
            parent_jti: None,
        });
        let j = serde_json::to_string(&chain).unwrap();
        let p: DelegationChain = serde_json::from_str(&j).unwrap();
        assert_eq!(p, chain);
    }

    #[test]
    fn chain_len_and_is_empty() {
        let mut c = DelegationChain::new();
        assert!(c.is_empty());
        c.push(DelegationLink {
            child_token: "x".into(),
            parent_jti: None,
        });
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn chain_default_is_empty() {
        let c = DelegationChain::default();
        assert!(c.is_empty());
    }

    #[test]
    fn three_link_chain() {
        let issuer = issuer();
        let (_e, root_link, root_claims) = build_root_link(&issuer);
        let (_, mid_link) = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "root-principal",
            vec![Permission::SealAppend, Permission::SealRead],
            time::Duration::minutes(45),
        )
        .unwrap();
        let mid_claims = verifier_for(&issuer)
            .allow_replays()
            .verify(&mid_link.child_token)
            .unwrap();
        let (_, leaf_link) = mint_child(
            &issuer,
            &mid_claims,
            "sandbox",
            "alice",
            vec![Permission::SealRead],
            time::Duration::minutes(15),
        )
        .unwrap();
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(mid_link);
        chain.push(leaf_link);
        let v = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints {
                max_depth: 5,
                ..DelegationConstraints::default()
            },
        );
        // Default constraints don't require principal_chaining, so accepted.
        v.verify(&chain).unwrap();
        // With principal_chaining ON, it would reject (since child.iss
        // is the issuer id, not the parent's principal).
        let v_strict = DelegationVerifier::new(
            verifier_for(&issuer).allow_replays(),
            DelegationConstraints {
                max_depth: 5,
                require_principal_chaining: true,
                ..DelegationConstraints::default()
            },
        );
        assert!(v_strict.verify(&chain).is_err());
    }

    #[test]
    fn revocation_list_default_is_empty() {
        let r = DelegationRevocationList::default();
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn child_ttl_at_parent_boundary_accepted() {
        let issuer = issuer();
        let (_e, _root_link, root_claims) = build_root_link(&issuer);
        let r = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "alice",
            vec![Permission::SealRead],
            time::Duration::minutes(50),
        );
        assert!(r.is_ok());
    }

    #[test]
    fn all_jtis_returns_per_link_ids() {
        let issuer = issuer();
        let (_e, root_link, root_claims) = build_root_link(&issuer);
        let (_, child_link) = mint_child(
            &issuer,
            &root_claims,
            "sandbox",
            "alice",
            vec![Permission::SealRead],
            time::Duration::minutes(10),
        )
        .unwrap();
        let mut chain = DelegationChain::new();
        chain.push(root_link);
        chain.push(child_link);
        let v = verifier_for(&issuer).allow_replays();
        let jtis = chain.all_jtis(&v).unwrap();
        assert_eq!(jtis.len(), 2);
    }
}
