//! Customer-facing Knowledge Base article register.
//!
//! Distinct from internal [`crate::runbook_engine`] (operational
//! runbooks) and [`crate::regulatory_change`] (regulator change
//! tracking), this is the **customer-visible KB**: how-to articles,
//! release notes, FAQ entries, and troubleshooting guides published to
//! the help centre or in-app docs portal.
//!
//! ## Lifecycle
//!
//! `Drafted → InReview → Published → (Updated → Published) | Archived`
//!
//! `Updated` is a transient state — content has been edited; on
//! publication it returns to `Published` with the version bumped. When
//! a topic is no longer relevant the article moves to `Archived`
//! (terminal).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ArticleCategory
// =============================================================================

/// KB article category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArticleCategory {
    /// How-to guide.
    HowTo,
    /// FAQ entry.
    Faq,
    /// Troubleshooting article.
    Troubleshooting,
    /// Release notes summary.
    ReleaseNotes,
    /// Concept / explainer.
    Concept,
    /// API reference snippet.
    Reference,
    /// Onboarding / getting-started.
    Onboarding,
    /// Best practices.
    BestPractices,
}

// =============================================================================
// ArticleStage
// =============================================================================

/// Lifecycle stage of an article.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArticleStage {
    /// Author working on first draft.
    Drafted,
    /// In editorial review.
    InReview,
    /// Live on the help centre.
    Published,
    /// Edited (off the live site temporarily) pending re-publish.
    Updated,
    /// No longer relevant; hidden from help centre.
    Archived,
}

impl ArticleStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Archived)
    }

    /// True if currently visible to customers.
    pub fn is_visible(self) -> bool {
        matches!(self, Self::Published)
    }
}

// =============================================================================
// ArticleVersion
// =============================================================================

/// One historical revision of an article.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArticleVersion {
    /// Monotonic version number (1 = first publication).
    pub version: u32,
    /// Author for this revision.
    pub author: String,
    /// Content SHA-256 (immutable evidence).
    pub content_sha256: String,
    /// RFC 3339 — when published.
    pub published_at: String,
    /// Optional change-summary.
    pub change_summary: Option<String>,
}

// =============================================================================
// ArticleEvent
// =============================================================================

/// One event on the article timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArticleEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: ArticleStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// KnowledgeBaseArticle
// =============================================================================

/// One KB article.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeBaseArticle {
    /// Unique article id.
    pub article_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// URL slug (deterministic from id but kept separately for renames).
    pub slug: String,
    /// Title.
    pub title: String,
    /// Free-text body (the live published version).
    pub body: String,
    /// Category.
    pub category: ArticleCategory,
    /// Author of the current version.
    pub author: String,
    /// Reviewer (set when entering Published from InReview).
    pub reviewer: Option<String>,
    /// Stage.
    pub stage: ArticleStage,
    /// Current published version number (0 = never published).
    pub current_version: u32,
    /// Version history (one entry per Published transition).
    pub versions: Vec<ArticleVersion>,
    /// Total view count.
    pub view_count: u64,
    /// Helpful votes.
    pub helpful_votes: u64,
    /// Unhelpful votes.
    pub unhelpful_votes: u64,
    /// Linked feature announcement id, if associated with a release.
    pub linked_announcement_id: Option<String>,
    /// RFC 3339 — first drafted.
    pub created_at: String,
    /// RFC 3339 — last published.
    pub last_published_at: Option<String>,
    /// RFC 3339 — last updated (any edit).
    pub last_updated_at: String,
    /// RFC 3339 — archived (terminal).
    pub archived_at: Option<String>,
    /// Event log.
    pub events: Vec<ArticleEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl KnowledgeBaseArticle {
    /// New `Drafted` article.
    pub fn new(
        article_id: impl Into<String>,
        tenant_id: impl Into<String>,
        slug: impl Into<String>,
        title: impl Into<String>,
        body: impl Into<String>,
        category: ArticleCategory,
        author: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        let when = created_at.into();
        Self {
            article_id: article_id.into(),
            tenant_id: tenant_id.into(),
            slug: slug.into(),
            title: title.into(),
            body: body.into(),
            category,
            author: author.into(),
            reviewer: None,
            stage: ArticleStage::Drafted,
            current_version: 0,
            versions: Vec::new(),
            view_count: 0,
            helpful_votes: 0,
            unhelpful_votes: 0,
            linked_announcement_id: None,
            created_at: when.clone(),
            last_published_at: None,
            last_updated_at: when,
            archived_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Helpfulness ratio (0.0-1.0). `None` if no votes.
    pub fn helpfulness(&self) -> Option<f64> {
        let total = self.helpful_votes + self.unhelpful_votes;
        if total == 0 {
            return None;
        }
        Some(self.helpful_votes as f64 / total as f64)
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: ArticleStage, to: ArticleStage) -> bool {
    use ArticleStage::*;
    matches!(
        (from, to),
        (Drafted, InReview)
            | (Drafted, Archived)
            | (InReview, Drafted)        // sent back for revisions
            | (InReview, Published)
            | (InReview, Archived)
            | (Published, Updated)
            | (Published, Archived)
            | (Updated, Published)
            | (Updated, Archived)
    )
}

// =============================================================================
// KnowledgeBaseRegister
// =============================================================================

/// Thread-safe register of KB articles.
#[derive(Debug, Default)]
pub struct KnowledgeBaseRegister {
    inner: RwLock<HashMap<String, KnowledgeBaseArticle>>,
}

impl KnowledgeBaseRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new draft.
    pub fn register(&self, article: KnowledgeBaseArticle) -> SandboxResult<()> {
        if !matches!(article.stage, ArticleStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "article must start Drafted, got {:?}",
                article.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        if g.contains_key(&article.article_id) {
            return Err(SandboxError::Other(format!(
                "article already registered: {}",
                article.article_id
            )));
        }
        g.insert(article.article_id.clone(), article);
        Ok(())
    }

    /// Update the body / title (allowed in Drafted, InReview, or Updated).
    pub fn edit(
        &self,
        article_id: &str,
        title: Option<String>,
        body: Option<String>,
        author: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        if !matches!(
            a.stage,
            ArticleStage::Drafted | ArticleStage::InReview | ArticleStage::Updated
        ) {
            return Err(SandboxError::Other(format!(
                "cannot edit {article_id}: stage is {:?}",
                a.stage
            )));
        }
        if let Some(t) = title {
            a.title = t;
        }
        if let Some(b) = body {
            a.body = b;
        }
        a.author = author.into();
        a.last_updated_at = at.into();
        Ok(a.clone())
    }

    /// Submit for review (Drafted → InReview).
    pub fn submit_for_review(
        &self,
        article_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        self.simple_transition(article_id, ArticleStage::InReview, actor, at, "submitted")
    }

    /// Send back to Drafted (InReview → Drafted).
    pub fn return_to_draft(
        &self,
        article_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        self.simple_transition(article_id, ArticleStage::Drafted, actor, at, note)
    }

    /// Mark Updated (Published → Updated). Used to take an article off the
    /// live site temporarily while editing.
    pub fn mark_updated(
        &self,
        article_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        self.simple_transition(article_id, ArticleStage::Updated, actor, at, "edits in flight")
    }

    /// Archive an article.
    pub fn archive(
        &self,
        article_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        if !legal_transition(a.stage, ArticleStage::Archived) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Archived",
                a.stage
            )));
        }
        let when = at.into();
        a.stage = ArticleStage::Archived;
        a.archived_at = Some(when.clone());
        a.events.push(ArticleEvent {
            at: when,
            actor: actor.into(),
            stage: ArticleStage::Archived,
            note: reason.into(),
        });
        Ok(a.clone())
    }

    /// Publish — transitions InReview or Updated to Published, bumps the
    /// version number, and records the snapshot in `versions`.
    pub fn publish(
        &self,
        article_id: &str,
        reviewer: impl Into<String>,
        at: impl Into<String>,
        content_sha256: impl Into<String>,
        change_summary: Option<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        if !legal_transition(a.stage, ArticleStage::Published) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Published",
                a.stage
            )));
        }
        let when = at.into();
        let reviewer = reviewer.into();
        a.stage = ArticleStage::Published;
        a.current_version += 1;
        a.last_published_at = Some(when.clone());
        a.reviewer = Some(reviewer.clone());
        a.versions.push(ArticleVersion {
            version: a.current_version,
            author: a.author.clone(),
            content_sha256: content_sha256.into(),
            published_at: when.clone(),
            change_summary,
        });
        a.events.push(ArticleEvent {
            at: when,
            actor: reviewer,
            stage: ArticleStage::Published,
            note: format!("published v{}", a.current_version),
        });
        Ok(a.clone())
    }

    fn simple_transition(
        &self,
        article_id: &str,
        new_stage: ArticleStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<KnowledgeBaseArticle> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        if !legal_transition(a.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                a.stage, new_stage
            )));
        }
        let when = at.into();
        a.stage = new_stage;
        a.events.push(ArticleEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        Ok(a.clone())
    }

    /// Increment view count. Allowed only on Published.
    pub fn record_view(&self, article_id: &str) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        if !a.stage.is_visible() {
            return Err(SandboxError::Other(format!(
                "cannot record view on {article_id}: not visible (stage {:?})",
                a.stage
            )));
        }
        a.view_count = a.view_count.saturating_add(1);
        Ok(())
    }

    /// Record a vote (helpful or not). Allowed only on Published.
    pub fn record_vote(&self, article_id: &str, helpful: bool) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        if !a.stage.is_visible() {
            return Err(SandboxError::Other(format!(
                "cannot record vote on {article_id}: not visible (stage {:?})",
                a.stage
            )));
        }
        if helpful {
            a.helpful_votes = a.helpful_votes.saturating_add(1);
        } else {
            a.unhelpful_votes = a.unhelpful_votes.saturating_add(1);
        }
        Ok(())
    }

    /// Link a feature announcement.
    pub fn link_announcement(
        &self,
        article_id: &str,
        announcement_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        a.linked_announcement_id = Some(announcement_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, article_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("kb register poisoned".into()))?;
        let a = g
            .get_mut(article_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown article {article_id}")))?;
        let tag = tag.into();
        if !a.tags.contains(&tag) {
            a.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, article_id: &str) -> Option<KnowledgeBaseArticle> {
        let g = self.inner.read().ok()?;
        g.get(article_id).cloned()
    }

    /// Look up by slug.
    pub fn get_by_slug(&self, slug: &str) -> Option<KnowledgeBaseArticle> {
        let g = self.inner.read().ok()?;
        g.values().find(|a| a.slug == slug).cloned()
    }

    /// All articles.
    pub fn all(&self) -> Vec<KnowledgeBaseArticle> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Articles for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<KnowledgeBaseArticle> {
        self.all()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// Articles by category.
    pub fn by_category(&self, category: ArticleCategory) -> Vec<KnowledgeBaseArticle> {
        self.all()
            .into_iter()
            .filter(|a| a.category == category)
            .collect()
    }

    /// Articles by stage.
    pub fn by_stage(&self, stage: ArticleStage) -> Vec<KnowledgeBaseArticle> {
        self.all().into_iter().filter(|a| a.stage == stage).collect()
    }

    /// Currently published (visible).
    pub fn published(&self) -> Vec<KnowledgeBaseArticle> {
        self.by_stage(ArticleStage::Published)
    }

    /// Articles whose helpfulness ratio is below `threshold` (0.0-1.0)
    /// with at least `min_votes` total votes — candidates for rewriting.
    pub fn low_helpfulness(
        &self,
        threshold: f64,
        min_votes: u64,
    ) -> Vec<KnowledgeBaseArticle> {
        self.all()
            .into_iter()
            .filter(|a| {
                let total = a.helpful_votes + a.unhelpful_votes;
                if total < min_votes {
                    return false;
                }
                match a.helpfulness() {
                    Some(h) => h < threshold,
                    None => false,
                }
            })
            .collect()
    }

    /// Number of articles.
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

    fn article(id: &str, slug: &str) -> KnowledgeBaseArticle {
        KnowledgeBaseArticle::new(
            id,
            "tenant-a",
            slug,
            format!("Title {id}"),
            "Initial body content",
            ArticleCategory::HowTo,
            "alice",
            "2025-04-01T00:00:00Z",
        )
    }

    fn drive_to_published(r: &KnowledgeBaseRegister, id: &str) {
        r.submit_for_review(id, "alice", "2025-04-02T00:00:00Z").unwrap();
        r.publish(
            id,
            "bob",
            "2025-04-03T00:00:00Z",
            "sha256-v1",
            None,
        )
        .unwrap();
    }

    #[test]
    fn register_and_get() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        assert!(r.get("a1").is_some());
        assert!(r.get_by_slug("how-to-foo").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        let err = r.register(article("a1", "how-to-foo")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_drafted() {
        let mut a = article("a1", "how-to-foo");
        a.stage = ArticleStage::Published;
        let r = KnowledgeBaseRegister::new();
        let err = r.register(a).unwrap_err();
        assert!(format!("{err}").contains("must start Drafted"));
    }

    #[test]
    fn legal_transitions() {
        use ArticleStage::*;
        assert!(legal_transition(Drafted, InReview));
        assert!(legal_transition(InReview, Drafted));
        assert!(legal_transition(InReview, Published));
        assert!(legal_transition(Published, Updated));
        assert!(legal_transition(Updated, Published));
        assert!(legal_transition(Drafted, Archived));
        assert!(legal_transition(Published, Archived));
        // illegal
        assert!(!legal_transition(Drafted, Published));
        assert!(!legal_transition(Archived, Published));
    }

    #[test]
    fn happy_path_publish() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        r.submit_for_review("a1", "alice", "2025-04-02T00:00:00Z").unwrap();
        let a = r
            .publish(
                "a1",
                "bob",
                "2025-04-03T00:00:00Z",
                "sha256-v1",
                Some("initial publication".into()),
            )
            .unwrap();
        assert_eq!(a.stage, ArticleStage::Published);
        assert_eq!(a.current_version, 1);
        assert_eq!(a.versions.len(), 1);
        assert_eq!(a.last_published_at.as_deref(), Some("2025-04-03T00:00:00Z"));
        assert_eq!(a.reviewer.as_deref(), Some("bob"));
    }

    #[test]
    fn republish_bumps_version() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        drive_to_published(&r, "a1");
        // Update content and re-publish
        r.mark_updated("a1", "alice", "2025-04-04T00:00:00Z").unwrap();
        r.edit(
            "a1",
            None,
            Some("revised body".into()),
            "alice",
            "2025-04-04T00:01:00Z",
        )
        .unwrap();
        let a = r
            .publish(
                "a1",
                "bob",
                "2025-04-05T00:00:00Z",
                "sha256-v2",
                Some("clarified step 3".into()),
            )
            .unwrap();
        assert_eq!(a.current_version, 2);
        assert_eq!(a.versions.len(), 2);
        assert_eq!(a.versions[1].change_summary.as_deref(), Some("clarified step 3"));
    }

    #[test]
    fn return_to_draft_from_review() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        r.submit_for_review("a1", "alice", "2025-04-02T00:00:00Z").unwrap();
        let a = r
            .return_to_draft("a1", "bob", "2025-04-02T01:00:00Z", "needs revision")
            .unwrap();
        assert_eq!(a.stage, ArticleStage::Drafted);
    }

    #[test]
    fn edit_in_drafted_inreview_updated() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        r.edit(
            "a1",
            Some("New title".into()),
            None,
            "alice",
            "2025-04-01T01:00:00Z",
        )
        .unwrap();
        r.submit_for_review("a1", "alice", "2025-04-02T00:00:00Z").unwrap();
        r.edit(
            "a1",
            None,
            Some("Updated body during review".into()),
            "alice",
            "2025-04-02T01:00:00Z",
        )
        .unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.title, "New title");
        assert_eq!(a.body, "Updated body during review");
    }

    #[test]
    fn edit_in_published_errors() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        drive_to_published(&r, "a1");
        let err = r
            .edit(
                "a1",
                None,
                Some("inline edit not allowed".into()),
                "alice",
                "2025-04-04T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot edit"));
    }

    #[test]
    fn record_view_only_when_published() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        let err = r.record_view("a1").unwrap_err();
        assert!(format!("{err}").contains("not visible"));
        drive_to_published(&r, "a1");
        r.record_view("a1").unwrap();
        r.record_view("a1").unwrap();
        assert_eq!(r.get("a1").unwrap().view_count, 2);
    }

    #[test]
    fn record_vote_only_when_published() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "how-to-foo")).unwrap();
        let err = r.record_vote("a1", true).unwrap_err();
        assert!(format!("{err}").contains("not visible"));
        drive_to_published(&r, "a1");
        r.record_vote("a1", true).unwrap();
        r.record_vote("a1", true).unwrap();
        r.record_vote("a1", false).unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.helpful_votes, 2);
        assert_eq!(a.unhelpful_votes, 1);
    }

    #[test]
    fn helpfulness_ratio() {
        let mut a = article("a1", "x");
        a.helpful_votes = 8;
        a.unhelpful_votes = 2;
        assert!((a.helpfulness().unwrap() - 0.8).abs() < 1e-9);

        let a = article("a2", "y");
        assert!(a.helpfulness().is_none());
    }

    #[test]
    fn archive_from_drafted_or_published() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "x")).unwrap();
        let a = r
            .archive("a1", "alice", "2025-04-02T00:00:00Z", "deprecated")
            .unwrap();
        assert_eq!(a.stage, ArticleStage::Archived);

        let r = KnowledgeBaseRegister::new();
        r.register(article("a2", "y")).unwrap();
        drive_to_published(&r, "a2");
        let a = r
            .archive("a2", "alice", "2025-04-10T00:00:00Z", "topic obsolete")
            .unwrap();
        assert_eq!(a.stage, ArticleStage::Archived);
    }

    #[test]
    fn archive_terminal_errors() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "x")).unwrap();
        r.archive("a1", "alice", "2025-04-02T00:00:00Z", "n").unwrap();
        let err = r.archive("a1", "alice", "2025-04-03T00:00:00Z", "n").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn link_announcement_set_tag() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "x")).unwrap();
        r.link_announcement("a1", "ANN-007").unwrap();
        r.add_tag("a1", "release").unwrap();
        r.add_tag("a1", "release").unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.linked_announcement_id.as_deref(), Some("ANN-007"));
        assert_eq!(a.tags, vec!["release"]);
    }

    #[test]
    fn unknown_article_errors() {
        let r = KnowledgeBaseRegister::new();
        let err = r.link_announcement("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown article"));
    }

    #[test]
    fn for_tenant_by_category_filters() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "a1")).unwrap();
        let mut other = article("a2", "a2");
        other.tenant_id = "tenant-b".into();
        other.category = ArticleCategory::Faq;
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.by_category(ArticleCategory::HowTo).len(), 1);
        assert_eq!(r.by_category(ArticleCategory::Faq).len(), 1);
    }

    #[test]
    fn by_stage_published_filter() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("a1", "a1")).unwrap();
        r.register(article("a2", "a2")).unwrap();
        drive_to_published(&r, "a2");
        assert_eq!(r.by_stage(ArticleStage::Drafted).len(), 1);
        assert_eq!(r.by_stage(ArticleStage::Published).len(), 1);
        assert_eq!(r.published().len(), 1);
    }

    #[test]
    fn low_helpfulness_filter() {
        let r = KnowledgeBaseRegister::new();
        r.register(article("good", "good")).unwrap();
        drive_to_published(&r, "good");
        for _ in 0..8 {
            r.record_vote("good", true).unwrap();
        }
        for _ in 0..2 {
            r.record_vote("good", false).unwrap();
        }
        r.register(article("bad", "bad")).unwrap();
        drive_to_published(&r, "bad");
        for _ in 0..3 {
            r.record_vote("bad", true).unwrap();
        }
        for _ in 0..7 {
            r.record_vote("bad", false).unwrap();
        }
        // No votes
        r.register(article("untouched", "untouched")).unwrap();
        drive_to_published(&r, "untouched");

        let low = r.low_helpfulness(0.5, 5);
        let ids: Vec<_> = low.iter().map(|a| a.article_id.clone()).collect();
        assert!(ids.contains(&"bad".to_string()));
        assert!(!ids.contains(&"good".to_string()));
        assert!(!ids.contains(&"untouched".to_string())); // below min_votes
    }

    #[test]
    fn stage_helpers() {
        assert!(ArticleStage::Archived.is_terminal());
        assert!(!ArticleStage::Published.is_terminal());
        assert!(ArticleStage::Published.is_visible());
        assert!(!ArticleStage::Updated.is_visible());
        assert!(!ArticleStage::Drafted.is_visible());
    }

    #[test]
    fn count_tracks() {
        let r = KnowledgeBaseRegister::new();
        assert_eq!(r.count(), 0);
        r.register(article("a1", "x")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn article_serde() {
        let a = article("a1", "x");
        let j = serde_json::to_string(&a).unwrap();
        let back: KnowledgeBaseArticle = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enums_serde() {
        for c in [
            ArticleCategory::HowTo,
            ArticleCategory::Faq,
            ArticleCategory::Troubleshooting,
            ArticleCategory::ReleaseNotes,
            ArticleCategory::Concept,
            ArticleCategory::Reference,
            ArticleCategory::Onboarding,
            ArticleCategory::BestPractices,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<ArticleCategory>(&serde_json::to_string(&c).unwrap())
                    .unwrap()
            );
        }
        for s in [
            ArticleStage::Drafted,
            ArticleStage::InReview,
            ArticleStage::Published,
            ArticleStage::Updated,
            ArticleStage::Archived,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ArticleStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
