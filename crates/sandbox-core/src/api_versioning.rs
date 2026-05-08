//! API version compatibility tracking for the Aethelred enterprise surface.
//!
//! Public APIs (HTTP, gRPC, SDK shape, seal wire format) evolve over time and
//! enterprise customers need a predictable lifecycle:
//!
//! - **[`VersionStage::Active`]** — fully supported.
//! - **[`VersionStage::Deprecated`]** — still callable but emits warnings; a
//!   sunset date is announced.
//! - **[`VersionStage::Sunset`]** — sunset date passed; calls return errors
//!   but the version metadata is still listed.
//! - **[`VersionStage::Removed`]** — fully removed; calls 404. The registry
//!   keeps the entry so audits can reconstruct historical timelines.
//!
//! The registry is intentionally conservative: lifecycle moves forward only.
//! Re-activating a sunset version requires registering a new version (with a
//! new id), preserving an immutable audit trail of supported versions.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// VersionStage
// =============================================================================

/// Lifecycle stage of an API version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStage {
    /// Currently supported.
    Active,
    /// Deprecation announced, sunset date scheduled.
    Deprecated,
    /// Sunset date passed; calls hard-fail.
    Sunset,
    /// Fully removed; only metadata retained for audit.
    Removed,
}

impl VersionStage {
    /// Whether requests against this stage should be served.
    pub fn is_callable(self) -> bool {
        matches!(self, Self::Active | Self::Deprecated)
    }

    /// Whether the stage represents an end-of-life condition.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Sunset | Self::Removed)
    }
}

// =============================================================================
// CompatibilityKind
// =============================================================================

/// How a version relates to its predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityKind {
    /// Wire-compatible, additive change only.
    BackwardCompatible,
    /// Breaking change to existing fields/endpoints.
    Breaking,
    /// First version of the surface.
    Initial,
}

// =============================================================================
// VersionEntry
// =============================================================================

/// One registered API version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VersionEntry {
    /// Semver-style identifier ("v1", "2024-05-01", "v2.1.0", ...).
    pub version: String,
    /// Surface name ("seal-wire", "http-api", "sdk-rust", ...).
    pub surface: String,
    /// Current lifecycle stage.
    pub stage: VersionStage,
    /// How this version compares to the prior one.
    pub compatibility: CompatibilityKind,
    /// RFC 3339 — version became active.
    pub released_at: String,
    /// RFC 3339 — when the version was deprecated, if any.
    pub deprecated_at: Option<String>,
    /// RFC 3339 — sunset date announced (or executed) for this version.
    pub sunset_at: Option<String>,
    /// RFC 3339 — when the version was fully removed, if any.
    pub removed_at: Option<String>,
    /// Optional successor version that callers should migrate to.
    pub successor: Option<String>,
    /// Optional changelog / migration notes URL.
    pub changelog_url: Option<String>,
    /// Free-form tags (e.g., "ga", "preview", "internal").
    pub tags: Vec<String>,
}

impl VersionEntry {
    /// New active version.
    pub fn new(
        version: impl Into<String>,
        surface: impl Into<String>,
        compatibility: CompatibilityKind,
        released_at: impl Into<String>,
    ) -> Self {
        Self {
            version: version.into(),
            surface: surface.into(),
            stage: VersionStage::Active,
            compatibility,
            released_at: released_at.into(),
            deprecated_at: None,
            sunset_at: None,
            removed_at: None,
            successor: None,
            changelog_url: None,
            tags: Vec::new(),
        }
    }

    /// Composite key as used by the registry.
    pub fn key(&self) -> (String, String) {
        (self.surface.clone(), self.version.clone())
    }
}

// =============================================================================
// CompatibilityCheck
// =============================================================================

/// Outcome of validating a client request against a registered version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompatibilityCheck {
    /// The requested version.
    pub requested: String,
    /// The matching surface.
    pub surface: String,
    /// Stage at the moment of the check.
    pub stage: VersionStage,
    /// True if the request should be served.
    pub allowed: bool,
    /// Warning text (e.g., deprecation notice).
    pub warning: Option<String>,
    /// Suggested successor.
    pub suggested_successor: Option<String>,
}

// =============================================================================
// ApiVersionRegistry
// =============================================================================

/// Thread-safe registry of API versions per surface.
#[derive(Debug, Default)]
pub struct ApiVersionRegistry {
    inner: RwLock<HashMap<(String, String), VersionEntry>>,
}

impl ApiVersionRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new version. Errors if `(surface, version)` already exists.
    pub fn register(&self, entry: VersionEntry) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("api version registry poisoned".into()))?;
        let key = entry.key();
        if g.contains_key(&key) {
            return Err(SandboxError::Other(format!(
                "api version already registered: {}/{}",
                key.0, key.1
            )));
        }
        g.insert(key, entry);
        Ok(())
    }

    /// Mark a version Deprecated. Optionally announce a sunset date.
    pub fn deprecate(
        &self,
        surface: &str,
        version: &str,
        deprecated_at: impl Into<String>,
        sunset_at: Option<String>,
        successor: Option<String>,
    ) -> SandboxResult<VersionEntry> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("api version registry poisoned".into()))?;
        let entry = g
            .get_mut(&(surface.to_string(), version.to_string()))
            .ok_or_else(|| SandboxError::Other(format!("unknown version {surface}/{version}")))?;
        if !matches!(entry.stage, VersionStage::Active) {
            return Err(SandboxError::Other(format!(
                "cannot deprecate {surface}/{version}: stage is {:?}",
                entry.stage
            )));
        }
        entry.stage = VersionStage::Deprecated;
        entry.deprecated_at = Some(deprecated_at.into());
        if let Some(sunset) = sunset_at {
            entry.sunset_at = Some(sunset);
        }
        if let Some(s) = successor {
            entry.successor = Some(s);
        }
        Ok(entry.clone())
    }

    /// Move a version to Sunset. Allowed from Deprecated only.
    pub fn sunset(
        &self,
        surface: &str,
        version: &str,
        sunset_at: impl Into<String>,
    ) -> SandboxResult<VersionEntry> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("api version registry poisoned".into()))?;
        let entry = g
            .get_mut(&(surface.to_string(), version.to_string()))
            .ok_or_else(|| SandboxError::Other(format!("unknown version {surface}/{version}")))?;
        if !matches!(entry.stage, VersionStage::Deprecated) {
            return Err(SandboxError::Other(format!(
                "cannot sunset {surface}/{version}: stage is {:?} (must be Deprecated)",
                entry.stage
            )));
        }
        entry.stage = VersionStage::Sunset;
        entry.sunset_at = Some(sunset_at.into());
        Ok(entry.clone())
    }

    /// Move a version to Removed. Allowed from Sunset only.
    pub fn remove_version(
        &self,
        surface: &str,
        version: &str,
        removed_at: impl Into<String>,
    ) -> SandboxResult<VersionEntry> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("api version registry poisoned".into()))?;
        let entry = g
            .get_mut(&(surface.to_string(), version.to_string()))
            .ok_or_else(|| SandboxError::Other(format!("unknown version {surface}/{version}")))?;
        if !matches!(entry.stage, VersionStage::Sunset) {
            return Err(SandboxError::Other(format!(
                "cannot remove {surface}/{version}: stage is {:?} (must be Sunset)",
                entry.stage
            )));
        }
        entry.stage = VersionStage::Removed;
        entry.removed_at = Some(removed_at.into());
        Ok(entry.clone())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, surface: &str, version: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("api version registry poisoned".into()))?;
        let entry = g
            .get_mut(&(surface.to_string(), version.to_string()))
            .ok_or_else(|| SandboxError::Other(format!("unknown version {surface}/{version}")))?;
        let tag = tag.into();
        if !entry.tags.contains(&tag) {
            entry.tags.push(tag);
        }
        Ok(())
    }

    /// Set the changelog URL.
    pub fn set_changelog(
        &self,
        surface: &str,
        version: &str,
        url: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("api version registry poisoned".into()))?;
        let entry = g
            .get_mut(&(surface.to_string(), version.to_string()))
            .ok_or_else(|| SandboxError::Other(format!("unknown version {surface}/{version}")))?;
        entry.changelog_url = Some(url.into());
        Ok(())
    }

    /// Look up a version.
    pub fn get(&self, surface: &str, version: &str) -> Option<VersionEntry> {
        let g = self.inner.read().ok()?;
        g.get(&(surface.to_string(), version.to_string())).cloned()
    }

    /// All versions for a surface, sorted by released_at ascending.
    pub fn for_surface(&self, surface: &str) -> Vec<VersionEntry> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<VersionEntry> = g
            .values()
            .filter(|v| v.surface == surface)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.released_at.cmp(&b.released_at));
        out
    }

    /// All versions across all surfaces.
    pub fn all(&self) -> Vec<VersionEntry> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All currently callable (Active or Deprecated) versions of a surface.
    pub fn callable_for_surface(&self, surface: &str) -> Vec<VersionEntry> {
        self.for_surface(surface)
            .into_iter()
            .filter(|e| e.stage.is_callable())
            .collect()
    }

    /// Latest active version for a surface, if any.
    pub fn latest_active(&self, surface: &str) -> Option<VersionEntry> {
        self.for_surface(surface)
            .into_iter()
            .filter(|e| matches!(e.stage, VersionStage::Active))
            .last()
    }

    /// Validate a client request. The `now` argument is RFC 3339 — used to
    /// compare against announced sunset dates so that a Deprecated version
    /// past its sunset date is treated as not callable.
    pub fn check(&self, surface: &str, version: &str, now: &str) -> CompatibilityCheck {
        let entry = self.get(surface, version);
        match entry {
            None => CompatibilityCheck {
                requested: version.to_string(),
                surface: surface.to_string(),
                stage: VersionStage::Removed,
                allowed: false,
                warning: Some(format!("unknown version {surface}/{version}")),
                suggested_successor: self.latest_active(surface).map(|e| e.version),
            },
            Some(e) => {
                let mut allowed = e.stage.is_callable();
                let mut warning = None;
                if matches!(e.stage, VersionStage::Deprecated) {
                    warning = Some(format!(
                        "{surface}/{version} is deprecated{}",
                        e.sunset_at
                            .as_ref()
                            .map(|s| format!(", sunset {s}"))
                            .unwrap_or_default()
                    ));
                    if let Some(sunset) = &e.sunset_at {
                        if now >= sunset.as_str() {
                            allowed = false;
                            warning = Some(format!(
                                "{surface}/{version} sunset on {sunset}; not callable"
                            ));
                        }
                    }
                } else if matches!(e.stage, VersionStage::Sunset) {
                    warning = Some(format!(
                        "{surface}/{version} sunset on {}",
                        e.sunset_at.as_deref().unwrap_or("unknown")
                    ));
                } else if matches!(e.stage, VersionStage::Removed) {
                    warning = Some(format!("{surface}/{version} removed"));
                }
                CompatibilityCheck {
                    requested: version.to_string(),
                    surface: surface.to_string(),
                    stage: e.stage,
                    allowed,
                    warning,
                    suggested_successor: e
                        .successor
                        .clone()
                        .or_else(|| self.latest_active(surface).map(|x| x.version)),
                }
            }
        }
    }

    /// Number of registered entries.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

/// Convenience: current RFC 3339 timestamp in UTC.
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(v: &str, surface: &str, when: &str) -> VersionEntry {
        VersionEntry::new(v, surface, CompatibilityKind::Initial, when)
    }

    #[test]
    fn register_and_get() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "seal-wire", "2024-01-01T00:00:00Z"))
            .unwrap();
        let got = r.get("seal-wire", "v1").unwrap();
        assert_eq!(got.stage, VersionStage::Active);
        assert!(got.deprecated_at.is_none());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        let err = r
            .register(entry("v1", "http", "2024-02-01T00:00:00Z"))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn deprecate_active() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        let e = r
            .deprecate(
                "http",
                "v1",
                "2024-06-01T00:00:00Z",
                Some("2025-06-01T00:00:00Z".to_string()),
                Some("v2".to_string()),
            )
            .unwrap();
        assert_eq!(e.stage, VersionStage::Deprecated);
        assert_eq!(e.successor.as_deref(), Some("v2"));
        assert_eq!(e.sunset_at.as_deref(), Some("2025-06-01T00:00:00Z"));
    }

    #[test]
    fn cannot_deprecate_sunset() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.deprecate("http", "v1", "2024-06-01T00:00:00Z", None, None)
            .unwrap();
        r.sunset("http", "v1", "2025-06-01T00:00:00Z").unwrap();
        let err = r
            .deprecate("http", "v1", "2024-06-01T00:00:00Z", None, None)
            .unwrap_err();
        assert!(format!("{err}").contains("cannot deprecate"));
    }

    #[test]
    fn sunset_requires_deprecated() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        let err = r.sunset("http", "v1", "2025-06-01T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("must be Deprecated"));
    }

    #[test]
    fn remove_requires_sunset() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.deprecate("http", "v1", "2024-06-01T00:00:00Z", None, None)
            .unwrap();
        let err = r
            .remove_version("http", "v1", "2025-12-01T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("must be Sunset"));
    }

    #[test]
    fn full_lifecycle() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.deprecate(
            "http",
            "v1",
            "2024-06-01T00:00:00Z",
            Some("2025-06-01T00:00:00Z".into()),
            None,
        )
        .unwrap();
        r.sunset("http", "v1", "2025-06-01T00:00:00Z").unwrap();
        let removed = r
            .remove_version("http", "v1", "2025-12-01T00:00:00Z")
            .unwrap();
        assert_eq!(removed.stage, VersionStage::Removed);
        assert_eq!(removed.removed_at.as_deref(), Some("2025-12-01T00:00:00Z"));
    }

    #[test]
    fn unknown_version_errors() {
        let r = ApiVersionRegistry::new();
        let err = r
            .deprecate("http", "v9", "2024-06-01T00:00:00Z", None, None)
            .unwrap_err();
        assert!(format!("{err}").contains("unknown version"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.add_tag("http", "v1", "ga").unwrap();
        r.add_tag("http", "v1", "ga").unwrap();
        r.add_tag("http", "v1", "stable").unwrap();
        let e = r.get("http", "v1").unwrap();
        assert_eq!(e.tags, vec!["ga", "stable"]);
    }

    #[test]
    fn set_changelog() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.set_changelog("http", "v1", "https://example.com/changelog")
            .unwrap();
        let e = r.get("http", "v1").unwrap();
        assert_eq!(
            e.changelog_url.as_deref(),
            Some("https://example.com/changelog")
        );
    }

    #[test]
    fn for_surface_sorted() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v2", "http", "2024-06-01T00:00:00Z")).unwrap();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v3", "http", "2025-01-01T00:00:00Z")).unwrap();
        let v = r.for_surface("http");
        assert_eq!(v[0].version, "v1");
        assert_eq!(v[1].version, "v2");
        assert_eq!(v[2].version, "v3");
    }

    #[test]
    fn for_surface_filters_surface() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v1", "grpc", "2024-01-01T00:00:00Z")).unwrap();
        assert_eq!(r.for_surface("http").len(), 1);
        assert_eq!(r.for_surface("grpc").len(), 1);
        assert_eq!(r.for_surface("zzz").len(), 0);
    }

    #[test]
    fn latest_active_picks_newest_active() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v2", "http", "2024-06-01T00:00:00Z")).unwrap();
        r.deprecate("http", "v1", "2024-06-01T00:00:00Z", None, None)
            .unwrap();
        let latest = r.latest_active("http").unwrap();
        assert_eq!(latest.version, "v2");
    }

    #[test]
    fn callable_excludes_terminal() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v2", "http", "2024-06-01T00:00:00Z")).unwrap();
        r.register(entry("v3", "http", "2025-01-01T00:00:00Z")).unwrap();
        r.deprecate("http", "v1", "2024-06-01T00:00:00Z", None, None)
            .unwrap();
        r.sunset("http", "v1", "2025-06-01T00:00:00Z").unwrap();
        let callable = r.callable_for_surface("http");
        assert_eq!(callable.len(), 2);
        assert!(callable.iter().all(|e| e.version != "v1"));
    }

    #[test]
    fn check_active_allows() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        let c = r.check("http", "v1", "2024-12-01T00:00:00Z");
        assert!(c.allowed);
        assert_eq!(c.stage, VersionStage::Active);
        assert!(c.warning.is_none());
    }

    #[test]
    fn check_unknown_disallows() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        let c = r.check("http", "v9", "2024-12-01T00:00:00Z");
        assert!(!c.allowed);
        assert!(c.warning.is_some());
        assert_eq!(c.suggested_successor.as_deref(), Some("v1"));
    }

    #[test]
    fn check_deprecated_warns_but_allows() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.deprecate(
            "http",
            "v1",
            "2024-06-01T00:00:00Z",
            Some("2025-06-01T00:00:00Z".into()),
            Some("v2".into()),
        )
        .unwrap();
        let c = r.check("http", "v1", "2024-12-01T00:00:00Z");
        assert!(c.allowed);
        assert_eq!(c.stage, VersionStage::Deprecated);
        assert!(c.warning.unwrap().contains("deprecated"));
        assert_eq!(c.suggested_successor.as_deref(), Some("v2"));
    }

    #[test]
    fn check_deprecated_past_sunset_disallows() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.deprecate(
            "http",
            "v1",
            "2024-06-01T00:00:00Z",
            Some("2025-06-01T00:00:00Z".into()),
            None,
        )
        .unwrap();
        let c = r.check("http", "v1", "2025-07-01T00:00:00Z");
        assert!(!c.allowed);
        assert!(c.warning.unwrap().contains("sunset"));
    }

    #[test]
    fn check_sunset_disallows() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        r.deprecate("http", "v1", "2024-06-01T00:00:00Z", None, None)
            .unwrap();
        r.sunset("http", "v1", "2025-06-01T00:00:00Z").unwrap();
        let c = r.check("http", "v1", "2025-07-01T00:00:00Z");
        assert!(!c.allowed);
        assert_eq!(c.stage, VersionStage::Sunset);
    }

    #[test]
    fn stage_callable_helpers() {
        assert!(VersionStage::Active.is_callable());
        assert!(VersionStage::Deprecated.is_callable());
        assert!(!VersionStage::Sunset.is_callable());
        assert!(!VersionStage::Removed.is_callable());
        assert!(VersionStage::Sunset.is_terminal());
        assert!(VersionStage::Removed.is_terminal());
        assert!(!VersionStage::Active.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = ApiVersionRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(entry("v1", "a", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v1", "b", "2024-01-01T00:00:00Z")).unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn entry_serde() {
        let e = entry("v1", "http", "2024-01-01T00:00:00Z");
        let s = serde_json::to_string(&e).unwrap();
        let back: VersionEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn check_serde() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "http", "2024-01-01T00:00:00Z")).unwrap();
        let c = r.check("http", "v1", "2024-12-01T00:00:00Z");
        let s = serde_json::to_string(&c).unwrap();
        let back: CompatibilityCheck = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn compatibility_kind_serde() {
        for k in [
            CompatibilityKind::Initial,
            CompatibilityKind::Breaking,
            CompatibilityKind::BackwardCompatible,
        ] {
            let s = serde_json::to_string(&k).unwrap();
            let back: CompatibilityKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn now_rfc3339_format() {
        let s = now_rfc3339();
        assert!(s.len() >= 19);
        assert!(s.contains('T'));
    }

    #[test]
    fn all_returns_everything() {
        let r = ApiVersionRegistry::new();
        r.register(entry("v1", "a", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v1", "b", "2024-01-01T00:00:00Z")).unwrap();
        r.register(entry("v2", "a", "2024-06-01T00:00:00Z")).unwrap();
        assert_eq!(r.all().len(), 3);
    }
}
