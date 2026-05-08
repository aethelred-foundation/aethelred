//! Content moderation labels + audit.
//!
//! Records per-input moderation results across categories (hate, violence,
//! sexual, self-harm, etc.) with confidence scores. Distinct from
//! [`crate::adversarial_detector`] which targets prompt-injection / jailbreaks.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ModerationCategory
// =============================================================================

/// Moderation category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationCategory {
    /// Hate speech.
    Hate,
    /// Violence.
    Violence,
    /// Sexual / explicit.
    Sexual,
    /// Self-harm.
    SelfHarm,
    /// Harassment.
    Harassment,
    /// Illegal activity.
    Illegal,
    /// Misinformation.
    Misinformation,
    /// Custom category.
    Custom,
}

// =============================================================================
// ModerationLabel
// =============================================================================

/// One label.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModerationLabel {
    /// Category.
    pub category: ModerationCategory,
    /// Custom label (when Custom).
    pub custom_label: Option<String>,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// `true` if exceeds operator threshold.
    pub flagged: bool,
}

// =============================================================================
// ModerationVerdict
// =============================================================================

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationVerdict {
    /// Allowed.
    Allow,
    /// Allowed with warning.
    Warn,
    /// Blocked.
    Block,
    /// Pending human review.
    Review,
}

// =============================================================================
// ModerationResult
// =============================================================================

/// One moderation event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModerationResult {
    /// Stable id.
    pub result_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Source: input or output.
    pub source: ModerationSource,
    /// Hash of content.
    pub content_hash: Sha256Digest,
    /// Length in bytes.
    pub content_len: u64,
    /// Labels.
    pub labels: Vec<ModerationLabel>,
    /// Verdict.
    pub verdict: ModerationVerdict,
    /// Optional reason text.
    pub reason: Option<String>,
    /// RFC 3339 evaluated.
    pub evaluated_at: String,
}

/// Source of moderated text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationSource {
    /// User input.
    UserInput,
    /// Model output.
    ModelOutput,
    /// Tool output.
    ToolOutput,
}

// =============================================================================
// ModerationLog
// =============================================================================

#[derive(Default)]
struct State {
    results: HashMap<Uuid, ModerationResult>,
    /// Per-category threshold (default 0.7).
    thresholds: HashMap<ModerationCategory, f64>,
}

/// Log.
pub struct ModerationLog {
    state: RwLock<State>,
}

impl Default for ModerationLog {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ModerationLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModerationLog")
            .field("results", &self.len())
            .finish()
    }
}

impl ModerationLog {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set per-category threshold.
    pub fn set_threshold(&self, category: ModerationCategory, threshold: f64) -> SandboxResult<()> {
        if !(0.0..=1.0).contains(&threshold) {
            return Err(SandboxError::Other("threshold must be in [0,1]".into()));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("moderation log poisoned".into()))?
            .thresholds
            .insert(category, threshold);
        Ok(())
    }

    /// Lookup threshold (default 0.7).
    pub fn threshold_for(&self, category: ModerationCategory) -> f64 {
        self.state
            .read()
            .map(|g| g.thresholds.get(&category).copied().unwrap_or(0.7))
            .unwrap_or(0.7)
    }

    /// Record a moderation result. Auto-applies thresholds to compute `flagged`.
    pub fn record(
        &self,
        tenant: impl Into<String>,
        source: ModerationSource,
        content: &str,
        mut labels: Vec<ModerationLabel>,
    ) -> SandboxResult<ModerationResult> {
        // Apply thresholds.
        for label in &mut labels {
            label.flagged = label.confidence >= self.threshold_for(label.category);
        }
        let any_flagged = labels.iter().any(|l| l.flagged);
        let highest_flag_conf = labels
            .iter()
            .filter(|l| l.flagged)
            .map(|l| l.confidence)
            .fold(0.0_f64, |a, b| a.max(b));
        let verdict = if !any_flagged {
            ModerationVerdict::Allow
        } else if highest_flag_conf >= 0.95 {
            ModerationVerdict::Block
        } else if highest_flag_conf >= 0.85 {
            ModerationVerdict::Review
        } else {
            ModerationVerdict::Warn
        };
        let r = ModerationResult {
            result_id: Uuid::now_v7(),
            tenant_id: tenant.into(),
            source,
            content_hash: Hasher::sha256(content.as_bytes()),
            content_len: content.len() as u64,
            labels,
            verdict,
            reason: None,
            evaluated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("moderation log poisoned".into()))?
            .results
            .insert(r.result_id, r.clone());
        Ok(r)
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<ModerationResult> {
        self.state.read().ok()?.results.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<ModerationResult> {
        self.state
            .read()
            .map(|g| g.results.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Filter by verdict.
    pub fn by_verdict(&self, v: ModerationVerdict) -> Vec<ModerationResult> {
        self.all().into_iter().filter(|r| r.verdict == v).collect()
    }
    /// Filter by category presence (any label).
    pub fn for_category(&self, c: ModerationCategory) -> Vec<ModerationResult> {
        self.all()
            .into_iter()
            .filter(|r| r.labels.iter().any(|l| l.category == c))
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.results.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(cat: ModerationCategory, conf: f64) -> ModerationLabel {
        ModerationLabel {
            category: cat,
            custom_label: None,
            confidence: conf,
            flagged: false, // re-set during record
        }
    }

    #[test]
    fn benign_input_allowed() {
        let l = ModerationLog::new();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "Hello",
                vec![label(ModerationCategory::Hate, 0.1)],
            )
            .unwrap();
        assert_eq!(r.verdict, ModerationVerdict::Allow);
    }

    #[test]
    fn high_confidence_blocks() {
        let l = ModerationLog::new();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "x",
                vec![label(ModerationCategory::Violence, 0.99)],
            )
            .unwrap();
        assert_eq!(r.verdict, ModerationVerdict::Block);
    }

    #[test]
    fn medium_high_review() {
        let l = ModerationLog::new();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "x",
                vec![label(ModerationCategory::Hate, 0.88)],
            )
            .unwrap();
        assert_eq!(r.verdict, ModerationVerdict::Review);
    }

    #[test]
    fn just_above_threshold_warns() {
        let l = ModerationLog::new();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "x",
                vec![label(ModerationCategory::Hate, 0.75)],
            )
            .unwrap();
        assert_eq!(r.verdict, ModerationVerdict::Warn);
    }

    #[test]
    fn flagged_set_on_threshold_breach() {
        let l = ModerationLog::new();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "x",
                vec![label(ModerationCategory::Hate, 0.8)],
            )
            .unwrap();
        assert!(r.labels[0].flagged);
    }

    #[test]
    fn custom_threshold_used() {
        let l = ModerationLog::new();
        l.set_threshold(ModerationCategory::Hate, 0.95).unwrap();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "x",
                vec![label(ModerationCategory::Hate, 0.9)],
            )
            .unwrap();
        // 0.9 < 0.95 → not flagged → Allow.
        assert_eq!(r.verdict, ModerationVerdict::Allow);
    }

    #[test]
    fn invalid_threshold_errors() {
        let l = ModerationLog::new();
        assert!(l.set_threshold(ModerationCategory::Hate, 1.5).is_err());
        assert!(l.set_threshold(ModerationCategory::Hate, -0.1).is_err());
    }

    #[test]
    fn content_hash_recorded() {
        let l = ModerationLog::new();
        let r = l
            .record("FAB", ModerationSource::UserInput, "secret", vec![])
            .unwrap();
        assert_eq!(r.content_hash, Hasher::sha256(b"secret"));
    }

    #[test]
    fn content_len_recorded() {
        let l = ModerationLog::new();
        let r = l
            .record("FAB", ModerationSource::UserInput, "abcde", vec![])
            .unwrap();
        assert_eq!(r.content_len, 5);
    }

    #[test]
    fn by_verdict_filters() {
        let l = ModerationLog::new();
        l.record(
            "FAB",
            ModerationSource::UserInput,
            "x",
            vec![label(ModerationCategory::Violence, 0.99)],
        )
        .unwrap();
        l.record("FAB", ModerationSource::UserInput, "y", vec![]).unwrap();
        assert_eq!(l.by_verdict(ModerationVerdict::Block).len(), 1);
        assert_eq!(l.by_verdict(ModerationVerdict::Allow).len(), 1);
    }

    #[test]
    fn for_category_filters() {
        let l = ModerationLog::new();
        l.record(
            "FAB",
            ModerationSource::UserInput,
            "x",
            vec![label(ModerationCategory::Hate, 0.5)],
        )
        .unwrap();
        l.record(
            "FAB",
            ModerationSource::UserInput,
            "y",
            vec![label(ModerationCategory::Sexual, 0.5)],
        )
        .unwrap();
        assert_eq!(l.for_category(ModerationCategory::Hate).len(), 1);
        assert_eq!(l.for_category(ModerationCategory::Sexual).len(), 1);
    }

    #[test]
    fn label_serde() {
        let lbl = label(ModerationCategory::Hate, 0.5);
        let j = serde_json::to_string(&lbl).unwrap();
        let p: ModerationLabel = serde_json::from_str(&j).unwrap();
        assert_eq!(p, lbl);
    }

    #[test]
    fn result_serde() {
        let l = ModerationLog::new();
        let r = l.record("FAB", ModerationSource::UserInput, "x", vec![]).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let p: ModerationResult = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn category_serde() {
        for c in [
            ModerationCategory::Hate,
            ModerationCategory::Violence,
            ModerationCategory::Sexual,
            ModerationCategory::SelfHarm,
            ModerationCategory::Harassment,
            ModerationCategory::Illegal,
            ModerationCategory::Misinformation,
            ModerationCategory::Custom,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let p: ModerationCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(p, c);
        }
    }

    #[test]
    fn source_serde() {
        for s in [
            ModerationSource::UserInput,
            ModerationSource::ModelOutput,
            ModerationSource::ToolOutput,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ModerationSource = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn verdict_serde() {
        for v in [
            ModerationVerdict::Allow,
            ModerationVerdict::Warn,
            ModerationVerdict::Block,
            ModerationVerdict::Review,
        ] {
            let j = serde_json::to_string(&v).unwrap();
            let p: ModerationVerdict = serde_json::from_str(&j).unwrap();
            assert_eq!(p, v);
        }
    }

    #[test]
    fn count_tracks() {
        let l = ModerationLog::new();
        assert!(l.is_empty());
        l.record("FAB", ModerationSource::UserInput, "x", vec![]).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn lookup_unknown_none() {
        let l = ModerationLog::new();
        assert!(l.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn multiple_categories_pick_highest() {
        let l = ModerationLog::new();
        let r = l
            .record(
                "FAB",
                ModerationSource::UserInput,
                "x",
                vec![
                    label(ModerationCategory::Hate, 0.5),
                    label(ModerationCategory::Violence, 0.99),
                ],
            )
            .unwrap();
        assert_eq!(r.verdict, ModerationVerdict::Block);
    }

    #[test]
    fn no_labels_allow() {
        let l = ModerationLog::new();
        let r = l.record("FAB", ModerationSource::UserInput, "x", vec![]).unwrap();
        assert_eq!(r.verdict, ModerationVerdict::Allow);
    }

    #[test]
    fn threshold_for_default_07() {
        let l = ModerationLog::new();
        assert!((l.threshold_for(ModerationCategory::Hate) - 0.7).abs() < 1e-9);
    }
}
