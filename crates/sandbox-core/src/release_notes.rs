//! Customer-facing release-notes registry.
//!
//! Distinct from [`crate::feature_announcement`] (windowed dashboard
//! messages) and from the source-controlled `CHANGELOG.md` (which is a
//! human-curated narrative), this module is the **structured release log**:
//! every shipped version is one [`ReleaseNote`] with:
//!
//! - the version label (semver or date),
//! - publish date,
//! - support stage (`Preview`, `Beta`, `Ga`, `Deprecated`, `Removed`),
//! - per-section [`NoteEntry`] items grouped by category (`Added`, `Changed`,
//!   `Fixed`, `Security`, `Deprecated`, `Removed`),
//! - optional supersedes / superseded-by links to express the version chain.
//!
//! The registry can render a CHANGELOG view (`render_markdown()`), filter to
//! the latest GA version, and answer "what changed since version X?".

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// SupportStage
// =============================================================================

/// Support stage of the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStage {
    /// Preview / experimental.
    Preview,
    /// Public beta.
    Beta,
    /// Generally available.
    Ga,
    /// Deprecated, but still callable.
    Deprecated,
    /// Removed; metadata retained.
    Removed,
}

impl SupportStage {
    /// True if customers can still call this version.
    pub fn is_callable(self) -> bool {
        matches!(self, Self::Preview | Self::Beta | Self::Ga | Self::Deprecated)
    }
}

// =============================================================================
// NoteCategory
// =============================================================================

/// Keep-a-Changelog-style category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteCategory {
    /// New capability.
    Added,
    /// Existing capability changed.
    Changed,
    /// Bug fix.
    Fixed,
    /// Security patch.
    Security,
    /// Deprecation notice.
    Deprecated,
    /// Capability removed.
    Removed,
    /// Performance improvement.
    Performance,
}

impl NoteCategory {
    /// Display label used in the rendered Markdown.
    pub fn label(self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Changed => "Changed",
            Self::Fixed => "Fixed",
            Self::Security => "Security",
            Self::Deprecated => "Deprecated",
            Self::Removed => "Removed",
            Self::Performance => "Performance",
        }
    }
}

// =============================================================================
// NoteEntry
// =============================================================================

/// One bullet within a release note.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NoteEntry {
    /// Category bucket.
    pub category: NoteCategory,
    /// Headline (one line).
    pub headline: String,
    /// Optional longer body / migration guidance.
    pub detail: Option<String>,
    /// Optional issue / PR id this entry references.
    pub references: Vec<String>,
}

impl NoteEntry {
    /// Construct a new bullet.
    pub fn new(category: NoteCategory, headline: impl Into<String>) -> Self {
        Self {
            category,
            headline: headline.into(),
            detail: None,
            references: Vec::new(),
        }
    }

    /// Builder: attach a detail body.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Builder: attach an issue/PR reference.
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }
}

// =============================================================================
// ReleaseNote
// =============================================================================

/// One published release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReleaseNote {
    /// Version label (e.g., "0.2.22", "2025-05-08", "v3").
    pub version: String,
    /// Tenant scope (use "global" for product-wide).
    pub tenant_id: String,
    /// Public title.
    pub title: String,
    /// One-line summary.
    pub summary: String,
    /// Stage.
    pub stage: SupportStage,
    /// RFC 3339 — published.
    pub published_at: String,
    /// Note bullets.
    pub entries: Vec<NoteEntry>,
    /// Versions this release supersedes (optional ordering hint).
    pub supersedes: Vec<String>,
    /// Set if a later version replaces this one.
    pub superseded_by: Option<String>,
    /// Optional changelog URL.
    pub changelog_url: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl ReleaseNote {
    /// Construct a new release note.
    pub fn new(
        version: impl Into<String>,
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        summary: impl Into<String>,
        stage: SupportStage,
        published_at: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            tenant_id: tenant_id.into(),
            title: title.into(),
            summary: summary.into(),
            stage,
            published_at: published_at.into(),
            entries: Vec::new(),
            supersedes: Vec::new(),
            superseded_by: None,
            changelog_url: None,
            tags: Vec::new(),
        }
    }

    /// Render this release as a Markdown chunk.
    pub fn render_markdown(&self) -> String {
        use std::collections::BTreeMap;
        let mut out = String::new();
        out.push_str(&format!("## [{}] - {}\n\n", self.version, self.published_at));
        out.push_str(&format!("**{}** — {}\n\n", self.title, self.summary));
        // Group entries by category in a stable display order.
        let mut grouped: BTreeMap<&'static str, Vec<&NoteEntry>> = BTreeMap::new();
        for e in &self.entries {
            grouped.entry(e.category.label()).or_default().push(e);
        }
        for label in [
            "Added",
            "Changed",
            "Performance",
            "Fixed",
            "Security",
            "Deprecated",
            "Removed",
        ] {
            if let Some(items) = grouped.get(label) {
                out.push_str(&format!("### {label}\n\n"));
                for it in items {
                    out.push_str(&format!("- {}\n", it.headline));
                    if let Some(d) = &it.detail {
                        out.push_str(&format!("  {d}\n"));
                    }
                }
                out.push('\n');
            }
        }
        out
    }
}

// =============================================================================
// ReleaseNotesRegistry
// =============================================================================

/// Thread-safe registry of release notes.
#[derive(Debug, Default)]
pub struct ReleaseNotesRegistry {
    inner: RwLock<HashMap<(String, String), ReleaseNote>>, // (tenant, version)
}

impl ReleaseNotesRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a release note. Errors on duplicate `(tenant, version)`.
    pub fn publish(&self, note: ReleaseNote) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("release notes registry poisoned".into()))?;
        let key = (note.tenant_id.clone(), note.version.clone());
        if g.contains_key(&key) {
            return Err(SandboxError::Other(format!(
                "release note already published: {}/{}",
                key.0, key.1
            )));
        }
        g.insert(key, note);
        Ok(())
    }

    /// Append a note entry.
    pub fn add_entry(
        &self,
        tenant_id: &str,
        version: &str,
        entry: NoteEntry,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("release notes registry poisoned".into()))?;
        let r = g
            .get_mut(&(tenant_id.to_string(), version.to_string()))
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown release note {tenant_id}/{version}"))
            })?;
        r.entries.push(entry);
        Ok(())
    }

    /// Set the changelog URL.
    pub fn set_changelog(
        &self,
        tenant_id: &str,
        version: &str,
        url: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("release notes registry poisoned".into()))?;
        let r = g
            .get_mut(&(tenant_id.to_string(), version.to_string()))
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown release note {tenant_id}/{version}"))
            })?;
        r.changelog_url = Some(url.into());
        Ok(())
    }

    /// Mark `older` as superseded by `newer`. Both must already exist for the
    /// same tenant.
    pub fn supersede(
        &self,
        tenant_id: &str,
        older: &str,
        newer: &str,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("release notes registry poisoned".into()))?;
        if !g.contains_key(&(tenant_id.to_string(), newer.to_string())) {
            return Err(SandboxError::Other(format!(
                "unknown release note {tenant_id}/{newer}"
            )));
        }
        let old = g
            .get_mut(&(tenant_id.to_string(), older.to_string()))
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown release note {tenant_id}/{older}"))
            })?;
        old.superseded_by = Some(newer.to_string());
        let new = g
            .get_mut(&(tenant_id.to_string(), newer.to_string()))
            .expect("checked above");
        if !new.supersedes.iter().any(|v| v == older) {
            new.supersedes.push(older.to_string());
        }
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(
        &self,
        tenant_id: &str,
        version: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("release notes registry poisoned".into()))?;
        let r = g
            .get_mut(&(tenant_id.to_string(), version.to_string()))
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown release note {tenant_id}/{version}"))
            })?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a release note.
    pub fn get(&self, tenant_id: &str, version: &str) -> Option<ReleaseNote> {
        let g = self.inner.read().ok()?;
        g.get(&(tenant_id.to_string(), version.to_string())).cloned()
    }

    /// All notes.
    pub fn all(&self) -> Vec<ReleaseNote> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All notes for a tenant, sorted by published_at ascending.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<ReleaseNote> {
        let mut out: Vec<ReleaseNote> = self
            .all()
            .into_iter()
            .filter(|n| n.tenant_id == tenant_id)
            .collect();
        out.sort_by(|a, b| a.published_at.cmp(&b.published_at));
        out
    }

    /// Latest note in a given stage for a tenant.
    pub fn latest_in_stage(
        &self,
        tenant_id: &str,
        stage: SupportStage,
    ) -> Option<ReleaseNote> {
        self.for_tenant(tenant_id)
            .into_iter()
            .filter(|n| n.stage == stage)
            .last()
    }

    /// Latest GA note for a tenant.
    pub fn latest_ga(&self, tenant_id: &str) -> Option<ReleaseNote> {
        self.latest_in_stage(tenant_id, SupportStage::Ga)
    }

    /// All notes for a tenant published strictly after `version`. Uses
    /// `published_at` to compute "after" — versions with newer
    /// `published_at` than the reference's `published_at`.
    pub fn since_version(&self, tenant_id: &str, version: &str) -> Vec<ReleaseNote> {
        let anchor = match self.get(tenant_id, version) {
            Some(n) => n.published_at,
            None => return Vec::new(),
        };
        self.for_tenant(tenant_id)
            .into_iter()
            .filter(|n| n.published_at.as_str() > anchor.as_str())
            .collect()
    }

    /// Render the full per-tenant changelog as Markdown — newest first.
    pub fn render_tenant_markdown(&self, tenant_id: &str) -> String {
        let mut notes = self.for_tenant(tenant_id);
        notes.reverse();
        let mut out = String::new();
        out.push_str(&format!("# Release notes — {tenant_id}\n\n"));
        for n in notes {
            out.push_str(&n.render_markdown());
        }
        out
    }

    /// Number of registered notes.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn note(version: &str, stage: SupportStage, when: &str) -> ReleaseNote {
        ReleaseNote::new(
            version,
            "global",
            format!("title-{version}"),
            "summary",
            stage,
            when,
        )
    }

    #[test]
    fn publish_and_get() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        let n = r.get("global", "0.2.22").unwrap();
        assert_eq!(n.stage, SupportStage::Ga);
    }

    #[test]
    fn duplicate_publish_errors() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        let err = r
            .publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap_err();
        assert!(format!("{err}").contains("already published"));
    }

    #[test]
    fn add_entry_appends() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.add_entry(
            "global",
            "0.2.22",
            NoteEntry::new(NoteCategory::Added, "disaster_recovery module"),
        )
        .unwrap();
        r.add_entry(
            "global",
            "0.2.22",
            NoteEntry::new(NoteCategory::Added, "service_catalog module"),
        )
        .unwrap();
        let n = r.get("global", "0.2.22").unwrap();
        assert_eq!(n.entries.len(), 2);
    }

    #[test]
    fn add_entry_unknown_errors() {
        let r = ReleaseNotesRegistry::new();
        let err = r
            .add_entry(
                "global",
                "0.2.22",
                NoteEntry::new(NoteCategory::Added, "x"),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown release note"));
    }

    #[test]
    fn set_changelog() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.set_changelog("global", "0.2.22", "https://example.com/CHANGELOG.md")
            .unwrap();
        assert_eq!(
            r.get("global", "0.2.22").unwrap().changelog_url.as_deref(),
            Some("https://example.com/CHANGELOG.md")
        );
    }

    #[test]
    fn supersede_links_both_directions() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.21", SupportStage::Ga, "2025-05-07T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.supersede("global", "0.2.21", "0.2.22").unwrap();
        let old = r.get("global", "0.2.21").unwrap();
        let new = r.get("global", "0.2.22").unwrap();
        assert_eq!(old.superseded_by.as_deref(), Some("0.2.22"));
        assert_eq!(new.supersedes, vec!["0.2.21".to_string()]);
    }

    #[test]
    fn supersede_dedupes_supersedes_list() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.21", SupportStage::Ga, "2025-05-07T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.supersede("global", "0.2.21", "0.2.22").unwrap();
        r.supersede("global", "0.2.21", "0.2.22").unwrap();
        assert_eq!(
            r.get("global", "0.2.22").unwrap().supersedes,
            vec!["0.2.21".to_string()]
        );
    }

    #[test]
    fn supersede_unknown_errors() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        let err = r.supersede("global", "0.2.21", "0.2.22").unwrap_err();
        assert!(format!("{err}").contains("unknown release note"));
        let err = r.supersede("global", "0.2.22", "0.2.99").unwrap_err();
        assert!(format!("{err}").contains("unknown release note"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.add_tag("global", "0.2.22", "ga").unwrap();
        r.add_tag("global", "0.2.22", "ga").unwrap();
        r.add_tag("global", "0.2.22", "milestone").unwrap();
        assert_eq!(
            r.get("global", "0.2.22").unwrap().tags,
            vec!["ga", "milestone"]
        );
    }

    #[test]
    fn for_tenant_sorted_ascending() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.20", SupportStage::Ga, "2025-05-06T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.21", SupportStage::Ga, "2025-05-07T00:00:00Z"))
            .unwrap();
        let v: Vec<_> = r
            .for_tenant("global")
            .into_iter()
            .map(|n| n.version)
            .collect();
        assert_eq!(v, vec!["0.2.20", "0.2.21", "0.2.22"]);
    }

    #[test]
    fn latest_ga_picks_newest_ga() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.20", SupportStage::Ga, "2025-05-06T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.21", SupportStage::Beta, "2025-05-07T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        let g = r.latest_ga("global").unwrap();
        assert_eq!(g.version, "0.2.22");
    }

    #[test]
    fn latest_in_stage_handles_missing() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        assert!(r.latest_in_stage("global", SupportStage::Beta).is_none());
    }

    #[test]
    fn since_version_returns_strictly_newer() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.20", SupportStage::Ga, "2025-05-06T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.21", SupportStage::Ga, "2025-05-07T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        let since = r.since_version("global", "0.2.20");
        let v: Vec<_> = since.into_iter().map(|n| n.version).collect();
        assert_eq!(v, vec!["0.2.21", "0.2.22"]);
    }

    #[test]
    fn since_version_unknown_returns_empty() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        assert!(r.since_version("global", "0.2.0").is_empty());
    }

    #[test]
    fn render_markdown_includes_sections() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        r.add_entry(
            "global",
            "0.2.22",
            NoteEntry::new(NoteCategory::Added, "disaster_recovery"),
        )
        .unwrap();
        r.add_entry(
            "global",
            "0.2.22",
            NoteEntry::new(NoteCategory::Security, "rotate signing keys"),
        )
        .unwrap();
        let md = r.get("global", "0.2.22").unwrap().render_markdown();
        assert!(md.contains("## [0.2.22]"));
        assert!(md.contains("### Added"));
        assert!(md.contains("### Security"));
        assert!(md.contains("disaster_recovery"));
    }

    #[test]
    fn render_tenant_markdown_orders_newest_first() {
        let r = ReleaseNotesRegistry::new();
        r.publish(note("0.2.21", SupportStage::Ga, "2025-05-07T00:00:00Z"))
            .unwrap();
        r.publish(note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z"))
            .unwrap();
        let md = r.render_tenant_markdown("global");
        let p21 = md.find("[0.2.21]").unwrap();
        let p22 = md.find("[0.2.22]").unwrap();
        assert!(p22 < p21, "0.2.22 must appear before 0.2.21");
    }

    #[test]
    fn note_entry_builders() {
        let e = NoteEntry::new(NoteCategory::Added, "foo")
            .with_detail("body")
            .with_reference("PR-42");
        assert_eq!(e.detail.as_deref(), Some("body"));
        assert_eq!(e.references, vec!["PR-42"]);
    }

    #[test]
    fn category_label_stable() {
        assert_eq!(NoteCategory::Added.label(), "Added");
        assert_eq!(NoteCategory::Security.label(), "Security");
        assert_eq!(NoteCategory::Performance.label(), "Performance");
    }

    #[test]
    fn stage_callable_helpers() {
        assert!(SupportStage::Ga.is_callable());
        assert!(SupportStage::Beta.is_callable());
        assert!(SupportStage::Preview.is_callable());
        assert!(SupportStage::Deprecated.is_callable());
        assert!(!SupportStage::Removed.is_callable());
    }

    #[test]
    fn count_tracks() {
        let r = ReleaseNotesRegistry::new();
        assert_eq!(r.count(), 0);
        r.publish(note("a", SupportStage::Ga, "2025-05-01T00:00:00Z"))
            .unwrap();
        r.publish(note("b", SupportStage::Ga, "2025-05-02T00:00:00Z"))
            .unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn note_serde() {
        let n = note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z");
        let j = serde_json::to_string(&n).unwrap();
        let back: ReleaseNote = serde_json::from_str(&j).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn entry_serde() {
        let e = NoteEntry::new(NoteCategory::Fixed, "fix")
            .with_detail("more")
            .with_reference("issue-7");
        let j = serde_json::to_string(&e).unwrap();
        let back: NoteEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn category_serde() {
        for c in [
            NoteCategory::Added,
            NoteCategory::Changed,
            NoteCategory::Fixed,
            NoteCategory::Security,
            NoteCategory::Deprecated,
            NoteCategory::Removed,
            NoteCategory::Performance,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let back: NoteCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(c, back);
        }
    }

    #[test]
    fn stage_serde() {
        for s in [
            SupportStage::Preview,
            SupportStage::Beta,
            SupportStage::Ga,
            SupportStage::Deprecated,
            SupportStage::Removed,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let back: SupportStage = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn for_tenant_filters_by_tenant() {
        let r = ReleaseNotesRegistry::new();
        let mut a = note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z");
        a.tenant_id = "tenant-a".into();
        let mut b = note("0.2.22", SupportStage::Ga, "2025-05-08T00:00:00Z");
        b.tenant_id = "tenant-b".into();
        r.publish(a).unwrap();
        r.publish(b).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_tenant("nope").len(), 0);
    }
}
