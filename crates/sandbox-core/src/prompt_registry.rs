//! Prompt registry — versioned prompt provenance.
//!
//! Generative-AI workflows depend on the *exact* prompt template. The
//! template is part of the "model" for compliance purposes (EU AI Act,
//! NIST AI RMF). When a regulator asks "what instructions did the model
//! receive?", the operator needs to point at a specific prompt version.
//!
//! ## Model
//!
//! - [`PromptVersion`] — one immutable, hashed prompt string.
//! - [`PromptRegistry`] — append-only history of versions per `prompt_id`,
//!   with effective-from dating and a chained-hash for tamper evidence.
//! - Per-version [`PromptVariant`]s (variable interpolations / system vs
//!   user splits) are captured for auditability.
//!
//! Operators look up the prompt active at decision time via
//! [`PromptRegistry::active_at`].

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// PromptRole
// =============================================================================

/// Conversation role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptRole {
    /// System / instructions.
    System,
    /// User / input.
    User,
    /// Assistant / few-shot example.
    Assistant,
    /// Tool / function output.
    Tool,
}

// =============================================================================
// PromptVariant
// =============================================================================

/// One role's prompt fragment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptVariant {
    /// Role.
    pub role: PromptRole,
    /// Template text.
    pub template: String,
    /// Hash of the template.
    pub template_hash: Sha256Digest,
}

impl PromptVariant {
    /// New variant from text (auto-hashes).
    pub fn new(role: PromptRole, template: impl Into<String>) -> Self {
        let template = template.into();
        let template_hash = Hasher::sha256(template.as_bytes());
        Self {
            role,
            template,
            template_hash,
        }
    }
}

// =============================================================================
// PromptVersion
// =============================================================================

/// One immutable prompt version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromptVersion {
    /// Stable prompt id.
    pub prompt_id: String,
    /// Version number.
    pub version: u32,
    /// Variants in conversation order.
    pub variants: Vec<PromptVariant>,
    /// Author.
    pub author: String,
    /// RFC 3339 effective from.
    pub effective_from: String,
    /// RFC 3339 effective to (None = latest).
    pub effective_to: Option<String>,
    /// Free-text rationale.
    pub rationale: Option<String>,
    /// Combined hash of all variant hashes (deterministic).
    pub combined_hash: Sha256Digest,
    /// Hash of prior version (None for v1).
    pub prior_hash: Option<Sha256Digest>,
}

fn combined_hash(variants: &[PromptVariant]) -> Sha256Digest {
    let mut buf = Vec::new();
    for v in variants {
        buf.push(role_byte(v.role));
        buf.extend_from_slice(&v.template_hash.0);
    }
    Hasher::sha256(&buf)
}

fn role_byte(r: PromptRole) -> u8 {
    match r {
        PromptRole::System => 1,
        PromptRole::User => 2,
        PromptRole::Assistant => 3,
        PromptRole::Tool => 4,
    }
}

// =============================================================================
// PromptRegistry
// =============================================================================

#[derive(Default)]
struct State {
    /// `prompt_id` → version list (in version-number order).
    versions: HashMap<String, Vec<PromptVersion>>,
}

/// Registry.
pub struct PromptRegistry {
    state: RwLock<State>,
}

impl Default for PromptRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for PromptRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self
            .state
            .read()
            .map(|g| g.versions.values().map(|v| v.len()).sum::<usize>())
            .unwrap_or(0);
        f.debug_struct("PromptRegistry")
            .field("versions", &total)
            .finish()
    }
}

impl PromptRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new version.
    pub fn publish(
        &self,
        prompt_id: impl Into<String>,
        variants: Vec<PromptVariant>,
        author: impl Into<String>,
        rationale: Option<String>,
        effective_from: Option<OffsetDateTime>,
    ) -> SandboxResult<PromptVersion> {
        if variants.is_empty() {
            return Err(SandboxError::Other(
                "prompt version must have at least one variant".into(),
            ));
        }
        let prompt_id = prompt_id.into();
        let now = effective_from
            .unwrap_or_else(OffsetDateTime::now_utc)
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("prompt registry poisoned".into()))?;
        let prior_versions = g.versions.entry(prompt_id.clone()).or_default();
        // Close out previous version's effective_to.
        if let Some(prev) = prior_versions.last_mut() {
            if prev.effective_to.is_none() {
                prev.effective_to = Some(now.clone());
            }
        }
        let version = (prior_versions.len() as u32) + 1;
        let prior_hash = prior_versions.last().map(|v| v.combined_hash);
        let combined = combined_hash(&variants);
        let pv = PromptVersion {
            prompt_id: prompt_id.clone(),
            version,
            variants,
            author: author.into(),
            effective_from: now,
            effective_to: None,
            rationale,
            combined_hash: combined,
            prior_hash,
        };
        prior_versions.push(pv.clone());
        Ok(pv)
    }

    /// Lookup version active at `ts`.
    pub fn active_at(
        &self,
        prompt_id: &str,
        ts: OffsetDateTime,
    ) -> Option<PromptVersion> {
        let ts_str = ts
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let g = self.state.read().ok()?;
        let versions = g.versions.get(prompt_id)?;
        let mut active: Option<&PromptVersion> = None;
        for v in versions {
            if v.effective_from.as_str() > ts_str.as_str() {
                continue;
            }
            if let Some(eto) = &v.effective_to {
                if eto.as_str() <= ts_str.as_str() {
                    continue;
                }
            }
            match active {
                None => active = Some(v),
                Some(cur) if v.effective_from > cur.effective_from => active = Some(v),
                _ => {}
            }
        }
        active.cloned()
    }

    /// Latest version.
    pub fn latest(&self, prompt_id: &str) -> Option<PromptVersion> {
        self.state.read().ok()?.versions.get(prompt_id)?.last().cloned()
    }

    /// History.
    pub fn history(&self, prompt_id: &str) -> Vec<PromptVersion> {
        self.state
            .read()
            .map(|g| g.versions.get(prompt_id).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// Number of distinct prompt ids registered.
    pub fn prompt_count(&self) -> usize {
        self.state.read().map(|g| g.versions.len()).unwrap_or(0)
    }

    /// Total versions.
    pub fn total_versions(&self) -> usize {
        self.state
            .read()
            .map(|g| g.versions.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }

    /// Verify the chain of one prompt id.
    pub fn verify_chain(&self, prompt_id: &str) -> SandboxResult<()> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("prompt registry poisoned".into()))?;
        let versions = match g.versions.get(prompt_id) {
            Some(v) => v,
            None => return Ok(()),
        };
        let mut prior: Option<Sha256Digest> = None;
        for v in versions {
            match (v.prior_hash, prior) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "prompt {} chain break at v{}",
                        prompt_id, v.version
                    )))
                }
            }
            // Recompute combined.
            let recomputed = combined_hash(&v.variants);
            if recomputed != v.combined_hash {
                return Err(SandboxError::Other(format!(
                    "prompt {} v{} hash mismatch",
                    prompt_id, v.version
                )));
            }
            prior = Some(v.combined_hash);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vsys(text: &str) -> PromptVariant {
        PromptVariant::new(PromptRole::System, text)
    }
    fn vusr(text: &str) -> PromptVariant {
        PromptVariant::new(PromptRole::User, text)
    }

    #[test]
    fn publish_creates_v1() {
        let r = PromptRegistry::new();
        let v = r
            .publish("p1", vec![vsys("be helpful")], "alice", None, None)
            .unwrap();
        assert_eq!(v.version, 1);
        assert!(v.prior_hash.is_none());
    }

    #[test]
    fn second_publish_chains() {
        let r = PromptRegistry::new();
        let v1 = r
            .publish("p1", vec![vsys("a")], "a", None, None)
            .unwrap();
        let v2 = r
            .publish("p1", vec![vsys("b")], "a", None, None)
            .unwrap();
        assert_eq!(v2.version, 2);
        assert_eq!(v2.prior_hash, Some(v1.combined_hash));
    }

    #[test]
    fn publish_empty_errors() {
        let r = PromptRegistry::new();
        assert!(r.publish("p", vec![], "a", None, None).is_err());
    }

    #[test]
    fn variant_hash_from_text() {
        let v = vsys("hi");
        assert_eq!(v.template_hash, Hasher::sha256(b"hi"));
    }

    #[test]
    fn combined_hash_deterministic() {
        let vs = vec![vsys("a"), vusr("b")];
        assert_eq!(combined_hash(&vs), combined_hash(&vs.clone()));
    }

    #[test]
    fn combined_hash_changes_with_role_order() {
        let v1 = vec![vsys("a"), vusr("b")];
        let v2 = vec![vusr("a"), vsys("b")];
        assert_ne!(combined_hash(&v1), combined_hash(&v2));
    }

    #[test]
    fn active_at_returns_active() {
        let r = PromptRegistry::new();
        let now = OffsetDateTime::now_utc();
        r.publish(
            "p",
            vec![vsys("a")],
            "x",
            None,
            Some(now - time::Duration::days(10)),
        )
        .unwrap();
        let active = r.active_at("p", now).unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn active_at_picks_latest_within_window() {
        let r = PromptRegistry::new();
        let now = OffsetDateTime::now_utc();
        r.publish(
            "p",
            vec![vsys("v1")],
            "x",
            None,
            Some(now - time::Duration::days(10)),
        )
        .unwrap();
        r.publish(
            "p",
            vec![vsys("v2")],
            "x",
            None,
            Some(now - time::Duration::days(2)),
        )
        .unwrap();
        let active = r.active_at("p", now).unwrap();
        assert_eq!(active.version, 2);
    }

    #[test]
    fn active_at_before_first_returns_none() {
        let r = PromptRegistry::new();
        let now = OffsetDateTime::now_utc();
        r.publish(
            "p",
            vec![vsys("v1")],
            "x",
            None,
            Some(now - time::Duration::days(2)),
        )
        .unwrap();
        let q = now - time::Duration::days(20);
        assert!(r.active_at("p", q).is_none());
    }

    #[test]
    fn latest_returns_top_version() {
        let r = PromptRegistry::new();
        for _ in 0..3 {
            r.publish("p", vec![vsys("x")], "a", None, None).unwrap();
        }
        let l = r.latest("p").unwrap();
        assert_eq!(l.version, 3);
    }

    #[test]
    fn history_in_order() {
        let r = PromptRegistry::new();
        for i in 0..5 {
            r.publish("p", vec![vsys(&format!("v{i}"))], "a", None, None).unwrap();
        }
        let h = r.history("p");
        assert_eq!(h.len(), 5);
        for (i, v) in h.iter().enumerate() {
            assert_eq!(v.version, (i + 1) as u32);
        }
    }

    #[test]
    fn previous_version_effective_to_set() {
        let r = PromptRegistry::new();
        r.publish("p", vec![vsys("a")], "x", None, None).unwrap();
        r.publish("p", vec![vsys("b")], "x", None, None).unwrap();
        let h = r.history("p");
        assert!(h[0].effective_to.is_some());
        assert!(h[1].effective_to.is_none());
    }

    #[test]
    fn verify_chain_empty_ok() {
        let r = PromptRegistry::new();
        r.verify_chain("ghost").unwrap();
    }

    #[test]
    fn verify_chain_after_writes_ok() {
        let r = PromptRegistry::new();
        for i in 0..5 {
            r.publish("p", vec![vsys(&format!("v{i}"))], "a", None, None).unwrap();
        }
        r.verify_chain("p").unwrap();
    }

    #[test]
    fn role_serde() {
        for r in [
            PromptRole::System,
            PromptRole::User,
            PromptRole::Assistant,
            PromptRole::Tool,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let p: PromptRole = serde_json::from_str(&j).unwrap();
            assert_eq!(p, r);
        }
    }

    #[test]
    fn variant_serde() {
        let v = vsys("x");
        let j = serde_json::to_string(&v).unwrap();
        let p: PromptVariant = serde_json::from_str(&j).unwrap();
        assert_eq!(p, v);
    }

    #[test]
    fn version_serde() {
        let r = PromptRegistry::new();
        let v = r
            .publish("p", vec![vsys("x")], "a", Some("rationale".into()), None)
            .unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let p: PromptVersion = serde_json::from_str(&j).unwrap();
        assert_eq!(p, v);
    }

    #[test]
    fn prompt_count_tracks_unique_ids() {
        let r = PromptRegistry::new();
        r.publish("a", vec![vsys("x")], "x", None, None).unwrap();
        r.publish("b", vec![vsys("x")], "x", None, None).unwrap();
        r.publish("a", vec![vsys("y")], "x", None, None).unwrap();
        assert_eq!(r.prompt_count(), 2);
        assert_eq!(r.total_versions(), 3);
    }

    #[test]
    fn rationale_recorded() {
        let r = PromptRegistry::new();
        let v = r
            .publish("p", vec![vsys("x")], "a", Some("policy update".into()), None)
            .unwrap();
        assert_eq!(v.rationale.as_deref(), Some("policy update"));
    }

    #[test]
    fn many_publishes_dont_panic() {
        let r = PromptRegistry::new();
        for i in 0..100 {
            r.publish("p", vec![vsys(&format!("v{i}"))], "a", None, None).unwrap();
        }
        assert_eq!(r.history("p").len(), 100);
    }

    #[test]
    fn history_unknown_returns_empty() {
        let r = PromptRegistry::new();
        assert!(r.history("ghost").is_empty());
    }

    #[test]
    fn latest_unknown_returns_none() {
        let r = PromptRegistry::new();
        assert!(r.latest("ghost").is_none());
    }

    #[test]
    fn role_byte_unique() {
        let bytes: std::collections::HashSet<u8> = [
            role_byte(PromptRole::System),
            role_byte(PromptRole::User),
            role_byte(PromptRole::Assistant),
            role_byte(PromptRole::Tool),
        ]
        .iter()
        .copied()
        .collect();
        assert_eq!(bytes.len(), 4);
    }
}
