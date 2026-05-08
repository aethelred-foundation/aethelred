//! Feature-announcement registry.
//!
//! Records customer-facing announcements (new features, deprecations,
//! breaking changes) with publish/expiry windows and per-tenant audience
//! filters. Composes with [`crate::tenant_lifecycle`] to surface only
//! relevant items to each customer's dashboard.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// AnnouncementKind
// =============================================================================

/// Kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnouncementKind {
    /// New feature.
    NewFeature,
    /// Deprecation notice.
    Deprecation,
    /// Breaking change.
    BreakingChange,
    /// Security advisory.
    SecurityAdvisory,
    /// Operational maintenance.
    Maintenance,
    /// Compliance update.
    Compliance,
}

// =============================================================================
// Announcement
// =============================================================================

/// One announcement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Announcement {
    /// Stable id.
    pub announcement_id: Uuid,
    /// Title.
    pub title: String,
    /// Body (markdown supported).
    pub body: String,
    /// Kind.
    pub kind: AnnouncementKind,
    /// RFC 3339 publish at.
    pub publish_at: String,
    /// RFC 3339 expires at (None = no expiry).
    pub expires_at: Option<String>,
    /// Audience: None = all, Some = subset of tenants.
    pub audience_tenants: Option<Vec<String>>,
    /// Tags.
    pub tags: Vec<String>,
    /// Author.
    pub author: String,
    /// `true` if active.
    pub active: bool,
    /// RFC 3339 created.
    pub created_at: String,
}

impl Announcement {
    /// `true` if visible to a tenant at `now`.
    pub fn is_visible_for(&self, tenant: &str, now: OffsetDateTime) -> bool {
        if !self.active {
            return false;
        }
        // Audience check.
        if let Some(audience) = &self.audience_tenants {
            if !audience.iter().any(|t| t == tenant) {
                return false;
            }
        }
        // Window.
        if let Ok(t) = OffsetDateTime::parse(
            &self.publish_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            if now < t {
                return false;
            }
        }
        if let Some(exp) = &self.expires_at {
            if let Ok(t) = OffsetDateTime::parse(
                exp,
                &time::format_description::well_known::Rfc3339,
            ) {
                if now >= t {
                    return false;
                }
            }
        }
        true
    }
}

// =============================================================================
// AnnouncementRegistry
// =============================================================================

#[derive(Default)]
struct State {
    announcements: HashMap<Uuid, Announcement>,
}

/// Registry.
pub struct AnnouncementRegistry {
    state: RwLock<State>,
}

impl Default for AnnouncementRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for AnnouncementRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnnouncementRegistry")
            .field("count", &self.len())
            .finish()
    }
}

impl AnnouncementRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish.
    pub fn publish(&self, a: Announcement) -> SandboxResult<Uuid> {
        let id = a.announcement_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("announcement registry poisoned".into()))?
            .announcements
            .insert(id, a);
        Ok(id)
    }

    /// Toggle active.
    pub fn set_active(&self, id: Uuid, active: bool) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("announcement registry poisoned".into()))?;
        let a = g
            .announcements
            .get_mut(&id)
            .ok_or_else(|| SandboxError::Other(format!("announcement {} not found", id)))?;
        a.active = active;
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<Announcement> {
        self.state.read().ok()?.announcements.get(&id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<Announcement> {
        self.state
            .read()
            .map(|g| g.announcements.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Visible announcements for a tenant at `now`.
    pub fn visible_for(&self, tenant: &str, now: OffsetDateTime) -> Vec<Announcement> {
        self.all()
            .into_iter()
            .filter(|a| a.is_visible_for(tenant, now))
            .collect()
    }

    /// By kind.
    pub fn by_kind(&self, kind: AnnouncementKind) -> Vec<Announcement> {
        self.all().into_iter().filter(|a| a.kind == kind).collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.announcements.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// AnnouncementBuilder
// =============================================================================

/// Builder.
pub struct AnnouncementBuilder {
    title: String,
    body: String,
    kind: AnnouncementKind,
    publish_at: Option<OffsetDateTime>,
    expires_at: Option<OffsetDateTime>,
    audience_tenants: Option<Vec<String>>,
    tags: Vec<String>,
    author: String,
}

impl AnnouncementBuilder {
    /// New.
    pub fn new(
        title: impl Into<String>,
        kind: AnnouncementKind,
        author: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            body: String::new(),
            kind,
            publish_at: None,
            expires_at: None,
            audience_tenants: None,
            tags: Vec::new(),
            author: author.into(),
        }
    }
    /// Body.
    pub fn body(mut self, b: impl Into<String>) -> Self {
        self.body = b.into();
        self
    }
    /// Publish at.
    pub fn publish_at(mut self, at: OffsetDateTime) -> Self {
        self.publish_at = Some(at);
        self
    }
    /// Expires at.
    pub fn expires_at(mut self, at: OffsetDateTime) -> Self {
        self.expires_at = Some(at);
        self
    }
    /// Restrict audience.
    pub fn audience(mut self, tenants: Vec<String>) -> Self {
        self.audience_tenants = Some(tenants);
        self
    }
    /// Tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        let t = t.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<Announcement> {
        if self.title.trim().is_empty() {
            return Err(SandboxError::Other("title required".into()));
        }
        let now = OffsetDateTime::now_utc();
        Ok(Announcement {
            announcement_id: Uuid::now_v7(),
            title: self.title,
            body: self.body,
            kind: self.kind,
            publish_at: self
                .publish_at
                .unwrap_or(now)
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            expires_at: self.expires_at.map(|t| {
                t.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            }),
            audience_tenants: self.audience_tenants,
            tags: self.tags,
            author: self.author,
            active: true,
            created_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ann() -> Announcement {
        AnnouncementBuilder::new("New BYOK provider", AnnouncementKind::NewFeature, "product")
            .body("We now support customer-managed keys via Azure Key Vault.")
            .tag("byok")
            .build()
            .unwrap()
    }

    #[test]
    fn build_creates_announcement() {
        let a = ann();
        assert_eq!(a.kind, AnnouncementKind::NewFeature);
        assert!(a.active);
    }

    #[test]
    fn empty_title_errors() {
        let r = AnnouncementBuilder::new("", AnnouncementKind::NewFeature, "x").build();
        assert!(r.is_err());
    }

    #[test]
    fn publish_records() {
        let r = AnnouncementRegistry::new();
        let id = r.publish(ann()).unwrap();
        assert!(r.get(id).is_some());
    }

    #[test]
    fn set_active_works() {
        let r = AnnouncementRegistry::new();
        let id = r.publish(ann()).unwrap();
        r.set_active(id, false).unwrap();
        assert!(!r.get(id).unwrap().active);
    }

    #[test]
    fn set_active_unknown_errors() {
        let r = AnnouncementRegistry::new();
        assert!(r.set_active(Uuid::now_v7(), false).is_err());
    }

    #[test]
    fn visible_for_all_audience() {
        let r = AnnouncementRegistry::new();
        r.publish(ann()).unwrap();
        // No audience restriction → visible to all.
        let v = r.visible_for("FAB", OffsetDateTime::now_utc());
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn visible_filters_by_audience() {
        let r = AnnouncementRegistry::new();
        let mut a = ann();
        a.audience_tenants = Some(vec!["FAB".into()]);
        r.publish(a).unwrap();
        assert_eq!(r.visible_for("FAB", OffsetDateTime::now_utc()).len(), 1);
        assert!(r.visible_for("ENBD", OffsetDateTime::now_utc()).is_empty());
    }

    #[test]
    fn future_publish_invisible() {
        let r = AnnouncementRegistry::new();
        let a = AnnouncementBuilder::new("future", AnnouncementKind::NewFeature, "x")
            .publish_at(OffsetDateTime::now_utc() + time::Duration::days(7))
            .build()
            .unwrap();
        r.publish(a).unwrap();
        assert!(r.visible_for("FAB", OffsetDateTime::now_utc()).is_empty());
    }

    #[test]
    fn past_expiry_invisible() {
        let r = AnnouncementRegistry::new();
        let a = AnnouncementBuilder::new("expired", AnnouncementKind::NewFeature, "x")
            .expires_at(OffsetDateTime::now_utc() - time::Duration::days(1))
            .build()
            .unwrap();
        r.publish(a).unwrap();
        assert!(r.visible_for("FAB", OffsetDateTime::now_utc()).is_empty());
    }

    #[test]
    fn inactive_invisible() {
        let r = AnnouncementRegistry::new();
        let id = r.publish(ann()).unwrap();
        r.set_active(id, false).unwrap();
        assert!(r.visible_for("FAB", OffsetDateTime::now_utc()).is_empty());
    }

    #[test]
    fn by_kind_filters() {
        let r = AnnouncementRegistry::new();
        r.publish(ann()).unwrap();
        let mut a2 = ann();
        a2.kind = AnnouncementKind::Maintenance;
        r.publish(a2).unwrap();
        assert_eq!(r.by_kind(AnnouncementKind::NewFeature).len(), 1);
        assert_eq!(r.by_kind(AnnouncementKind::Maintenance).len(), 1);
    }

    #[test]
    fn announcement_serde() {
        let a = ann();
        let j = serde_json::to_string(&a).unwrap();
        let p: Announcement = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn kind_serde() {
        for k in [
            AnnouncementKind::NewFeature,
            AnnouncementKind::Deprecation,
            AnnouncementKind::BreakingChange,
            AnnouncementKind::SecurityAdvisory,
            AnnouncementKind::Maintenance,
            AnnouncementKind::Compliance,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: AnnouncementKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn registry_count_tracks() {
        let r = AnnouncementRegistry::new();
        assert!(r.is_empty());
        r.publish(ann()).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = AnnouncementRegistry::new();
        assert!(r.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn tag_dedupes() {
        let a = AnnouncementBuilder::new("x", AnnouncementKind::NewFeature, "y")
            .tag("a")
            .tag("a")
            .build()
            .unwrap();
        assert_eq!(a.tags.len(), 1);
    }

    #[test]
    fn many_announcements_aggregate() {
        let r = AnnouncementRegistry::new();
        for _ in 0..20 {
            r.publish(ann()).unwrap();
        }
        assert_eq!(r.len(), 20);
    }

    #[test]
    fn audience_empty_list_excludes_all() {
        let r = AnnouncementRegistry::new();
        let mut a = ann();
        a.audience_tenants = Some(vec![]);
        r.publish(a).unwrap();
        assert!(r.visible_for("anyone", OffsetDateTime::now_utc()).is_empty());
    }
}
