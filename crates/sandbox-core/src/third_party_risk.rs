//! Third-party / vendor risk register.
//!
//! OCC 2013-29, FFIEC IT Handbook, EBA Outsourcing Guidelines, and most
//! enterprise procurement processes require a maintained vendor inventory
//! covering:
//!
//! - Tier of criticality / data access.
//! - Last assessment date.
//! - Compliance certifications (SOC 2, ISO 27001, PCI, HIPAA, etc.).
//! - Open issues / findings.
//! - Contract / SLA references.
//! - Termination plan.
//!
//! This module is the canonical place to record that. Each [`Vendor`] entry
//! is mutable through structured methods so the audit trail of changes is
//! recorded automatically.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// VendorTier
// =============================================================================

/// Vendor criticality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorTier {
    /// Critical — material reliance.
    Critical,
    /// High — significant dependency.
    High,
    /// Medium — moderate.
    Medium,
    /// Low — limited.
    Low,
}

impl VendorTier {
    /// Required reassessment interval in days.
    pub fn reassessment_interval_days(self) -> i64 {
        match self {
            Self::Critical => 365,
            Self::High => 365 * 2,
            Self::Medium => 365 * 3,
            Self::Low => 365 * 5,
        }
    }
}

// =============================================================================
// DataAccessLevel
// =============================================================================

/// What customer data the vendor accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataAccessLevel {
    /// No customer data access.
    None,
    /// Aggregated / pseudonymous.
    Aggregated,
    /// PII access.
    Pii,
    /// Sensitive / financial / health.
    Sensitive,
}

// =============================================================================
// Certification
// =============================================================================

/// Compliance certification held by the vendor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certification {
    /// Name (`"SOC2 Type II"`, `"ISO 27001"`, etc.).
    pub name: String,
    /// Issuing body.
    pub issuer: String,
    /// RFC 3339 valid from.
    pub valid_from: String,
    /// RFC 3339 valid until.
    pub valid_until: String,
    /// Optional URL for the certificate.
    pub url: Option<String>,
}

// =============================================================================
// VendorIssueSeverity / VendorIssue
// =============================================================================

/// Severity of an open issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorIssueSeverity {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
}

/// One open vendor issue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VendorIssue {
    /// Stable id.
    pub issue_id: Uuid,
    /// Severity.
    pub severity: VendorIssueSeverity,
    /// Free-text description.
    pub description: String,
    /// `true` if open.
    pub is_open: bool,
    /// RFC 3339 raised at.
    pub raised_at: String,
    /// RFC 3339 closed at.
    pub closed_at: Option<String>,
}

impl VendorIssue {
    /// New open issue.
    pub fn open(severity: VendorIssueSeverity, desc: impl Into<String>) -> Self {
        Self {
            issue_id: Uuid::now_v7(),
            severity,
            description: desc.into(),
            is_open: true,
            raised_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            closed_at: None,
        }
    }
}

// =============================================================================
// Vendor
// =============================================================================

/// Vendor / third-party.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vendor {
    /// Stable id.
    pub vendor_id: String,
    /// Display name.
    pub name: String,
    /// Vendor relationship owner (internal).
    pub relationship_owner: String,
    /// Tier.
    pub tier: VendorTier,
    /// Data access level.
    pub data_access: DataAccessLevel,
    /// Country of incorporation.
    pub country: String,
    /// Service description.
    pub service_description: String,
    /// Certifications.
    pub certifications: Vec<Certification>,
    /// Open + closed issues.
    pub issues: Vec<VendorIssue>,
    /// RFC 3339 last-assessed at.
    pub last_assessed_at: Option<String>,
    /// RFC 3339 contract end.
    pub contract_end_at: Option<String>,
    /// `true` if a documented exit / termination plan exists.
    pub has_exit_plan: bool,
    /// RFC 3339 first-registered.
    pub registered_at: String,
}

impl Vendor {
    /// Open issues.
    pub fn open_issues(&self) -> Vec<&VendorIssue> {
        self.issues.iter().filter(|i| i.is_open).collect()
    }

    /// `true` if reassessment is overdue as of `now`.
    pub fn is_overdue(&self, now: OffsetDateTime) -> bool {
        let last = match &self.last_assessed_at {
            Some(s) => match OffsetDateTime::parse(
                s,
                &time::format_description::well_known::Rfc3339,
            ) {
                Ok(t) => t,
                Err(_) => return true,
            },
            None => return true,
        };
        let interval = time::Duration::days(self.tier.reassessment_interval_days());
        now > last + interval
    }

    /// `true` if any current certification covers `now`.
    pub fn has_current_certification(&self, name: &str, now: OffsetDateTime) -> bool {
        for c in &self.certifications {
            if c.name != name {
                continue;
            }
            let from = OffsetDateTime::parse(
                &c.valid_from,
                &time::format_description::well_known::Rfc3339,
            )
            .ok();
            let until = OffsetDateTime::parse(
                &c.valid_until,
                &time::format_description::well_known::Rfc3339,
            )
            .ok();
            if let (Some(f), Some(u)) = (from, until) {
                if f <= now && now <= u {
                    return true;
                }
            }
        }
        false
    }
}

// =============================================================================
// VendorRegistry
// =============================================================================

#[derive(Default)]
struct State {
    vendors: HashMap<String, Vendor>,
}

/// Registry of vendors.
pub struct VendorRegistry {
    state: RwLock<State>,
}

impl Default for VendorRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for VendorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VendorRegistry")
            .field("vendors", &self.len())
            .finish()
    }
}

impl VendorRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Onboard a vendor.
    pub fn onboard(
        &self,
        vendor_id: impl Into<String>,
        name: impl Into<String>,
        owner: impl Into<String>,
        tier: VendorTier,
        access: DataAccessLevel,
        country: impl Into<String>,
    ) -> SandboxResult<Vendor> {
        let id = vendor_id.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("vendor registry poisoned".into()))?;
        if g.vendors.contains_key(&id) {
            return Err(SandboxError::Other(format!(
                "vendor {} already onboarded",
                id
            )));
        }
        let v = Vendor {
            vendor_id: id.clone(),
            name: name.into(),
            relationship_owner: owner.into(),
            tier,
            data_access: access,
            country: country.into(),
            service_description: String::new(),
            certifications: Vec::new(),
            issues: Vec::new(),
            last_assessed_at: None,
            contract_end_at: None,
            has_exit_plan: false,
            registered_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        g.vendors.insert(id, v.clone());
        Ok(v)
    }

    /// Record an assessment now.
    pub fn record_assessment(&self, vendor_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("vendor registry poisoned".into()))?;
        let v = g.vendors.get_mut(vendor_id).ok_or_else(|| {
            SandboxError::Other(format!("vendor {} not found", vendor_id))
        })?;
        v.last_assessed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Add a certification.
    pub fn add_certification(&self, vendor_id: &str, c: Certification) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("vendor registry poisoned".into()))?;
        let v = g.vendors.get_mut(vendor_id).ok_or_else(|| {
            SandboxError::Other(format!("vendor {} not found", vendor_id))
        })?;
        v.certifications.push(c);
        Ok(())
    }

    /// Add an issue.
    pub fn add_issue(&self, vendor_id: &str, issue: VendorIssue) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("vendor registry poisoned".into()))?;
        let v = g.vendors.get_mut(vendor_id).ok_or_else(|| {
            SandboxError::Other(format!("vendor {} not found", vendor_id))
        })?;
        v.issues.push(issue);
        Ok(())
    }

    /// Close an issue.
    pub fn close_issue(&self, vendor_id: &str, issue_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("vendor registry poisoned".into()))?;
        let v = g.vendors.get_mut(vendor_id).ok_or_else(|| {
            SandboxError::Other(format!("vendor {} not found", vendor_id))
        })?;
        let i = v.issues.iter_mut().find(|i| i.issue_id == issue_id).ok_or_else(|| {
            SandboxError::Other(format!(
                "issue {} not in vendor {}",
                issue_id, vendor_id
            ))
        })?;
        i.is_open = false;
        i.closed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Mark exit plan as documented.
    pub fn mark_exit_plan(&self, vendor_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("vendor registry poisoned".into()))?;
        let v = g.vendors.get_mut(vendor_id).ok_or_else(|| {
            SandboxError::Other(format!("vendor {} not found", vendor_id))
        })?;
        v.has_exit_plan = true;
        Ok(())
    }

    /// Lookup.
    pub fn vendor(&self, id: &str) -> Option<Vendor> {
        self.state.read().ok()?.vendors.get(id).cloned()
    }
    /// All vendors.
    pub fn all(&self) -> Vec<Vendor> {
        self.state
            .read()
            .map(|g| g.vendors.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Filter by tier.
    pub fn by_tier(&self, t: VendorTier) -> Vec<Vendor> {
        self.all().into_iter().filter(|v| v.tier == t).collect()
    }
    /// Vendors overdue for reassessment.
    pub fn overdue(&self, now: OffsetDateTime) -> Vec<Vendor> {
        self.all().into_iter().filter(|v| v.is_overdue(now)).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.vendors.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> VendorRegistry {
        let r = VendorRegistry::new();
        r.onboard(
            "v1",
            "Acme HSM Inc",
            "ciso",
            VendorTier::Critical,
            DataAccessLevel::Sensitive,
            "US",
        )
        .unwrap();
        r
    }

    #[test]
    fn onboard_creates_record() {
        let r = reg();
        assert_eq!(r.len(), 1);
        let v = r.vendor("v1").unwrap();
        assert_eq!(v.tier, VendorTier::Critical);
    }

    #[test]
    fn duplicate_onboard_errors() {
        let r = reg();
        assert!(r
            .onboard(
                "v1",
                "x",
                "y",
                VendorTier::Low,
                DataAccessLevel::None,
                "US",
            )
            .is_err());
    }

    #[test]
    fn record_assessment_sets_timestamp() {
        let r = reg();
        r.record_assessment("v1").unwrap();
        let v = r.vendor("v1").unwrap();
        assert!(v.last_assessed_at.is_some());
    }

    #[test]
    fn assessment_unknown_errors() {
        let r = reg();
        assert!(r.record_assessment("ghost").is_err());
    }

    #[test]
    fn add_certification_records_it() {
        let r = reg();
        r.add_certification(
            "v1",
            Certification {
                name: "SOC2 Type II".into(),
                issuer: "BIG4".into(),
                valid_from: "2026-01-01T00:00:00Z".into(),
                valid_until: "2027-01-01T00:00:00Z".into(),
                url: None,
            },
        )
        .unwrap();
        let v = r.vendor("v1").unwrap();
        assert_eq!(v.certifications.len(), 1);
    }

    #[test]
    fn has_current_certification() {
        let r = reg();
        r.add_certification(
            "v1",
            Certification {
                name: "SOC2 Type II".into(),
                issuer: "x".into(),
                valid_from: "2025-01-01T00:00:00Z".into(),
                valid_until: "2030-01-01T00:00:00Z".into(),
                url: None,
            },
        )
        .unwrap();
        let v = r.vendor("v1").unwrap();
        assert!(v.has_current_certification(
            "SOC2 Type II",
            OffsetDateTime::parse(
                "2026-06-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339
            )
            .unwrap()
        ));
    }

    #[test]
    fn certification_outside_window_not_current() {
        let r = reg();
        r.add_certification(
            "v1",
            Certification {
                name: "SOC2".into(),
                issuer: "x".into(),
                valid_from: "2020-01-01T00:00:00Z".into(),
                valid_until: "2022-01-01T00:00:00Z".into(),
                url: None,
            },
        )
        .unwrap();
        let v = r.vendor("v1").unwrap();
        assert!(!v.has_current_certification(
            "SOC2",
            OffsetDateTime::parse(
                "2026-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339
            )
            .unwrap()
        ));
    }

    #[test]
    fn add_issue_and_close() {
        let r = reg();
        let i = VendorIssue::open(VendorIssueSeverity::High, "patched late");
        let id = i.issue_id;
        r.add_issue("v1", i).unwrap();
        assert_eq!(r.vendor("v1").unwrap().open_issues().len(), 1);
        r.close_issue("v1", id).unwrap();
        assert_eq!(r.vendor("v1").unwrap().open_issues().len(), 0);
    }

    #[test]
    fn close_unknown_issue_errors() {
        let r = reg();
        assert!(r.close_issue("v1", Uuid::now_v7()).is_err());
    }

    #[test]
    fn mark_exit_plan_works() {
        let r = reg();
        r.mark_exit_plan("v1").unwrap();
        assert!(r.vendor("v1").unwrap().has_exit_plan);
    }

    #[test]
    fn overdue_when_never_assessed() {
        let r = reg();
        assert_eq!(r.overdue(OffsetDateTime::now_utc()).len(), 1);
    }

    #[test]
    fn not_overdue_after_recent_assessment() {
        let r = reg();
        r.record_assessment("v1").unwrap();
        assert_eq!(r.overdue(OffsetDateTime::now_utc()).len(), 0);
    }

    #[test]
    fn overdue_after_one_year_for_critical() {
        let r = reg();
        r.record_assessment("v1").unwrap();
        let future = OffsetDateTime::now_utc() + time::Duration::days(400);
        assert_eq!(r.overdue(future).len(), 1);
    }

    #[test]
    fn by_tier_filters() {
        let r = VendorRegistry::new();
        r.onboard(
            "v1",
            "x",
            "y",
            VendorTier::Critical,
            DataAccessLevel::Pii,
            "US",
        )
        .unwrap();
        r.onboard(
            "v2",
            "x",
            "y",
            VendorTier::Low,
            DataAccessLevel::None,
            "EU",
        )
        .unwrap();
        assert_eq!(r.by_tier(VendorTier::Critical).len(), 1);
        assert_eq!(r.by_tier(VendorTier::Low).len(), 1);
    }

    #[test]
    fn reassessment_intervals() {
        assert_eq!(VendorTier::Critical.reassessment_interval_days(), 365);
        assert_eq!(VendorTier::High.reassessment_interval_days(), 730);
    }

    #[test]
    fn vendor_serde() {
        let r = reg();
        let v = r.vendor("v1").unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let p: Vendor = serde_json::from_str(&j).unwrap();
        assert_eq!(p, v);
    }

    #[test]
    fn certification_serde() {
        let c = Certification {
            name: "x".into(),
            issuer: "y".into(),
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
            url: Some("https://example.test/cert.pdf".into()),
        };
        let j = serde_json::to_string(&c).unwrap();
        let p: Certification = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn issue_serde() {
        let i = VendorIssue::open(VendorIssueSeverity::Critical, "data leak");
        let j = serde_json::to_string(&i).unwrap();
        let p: VendorIssue = serde_json::from_str(&j).unwrap();
        assert_eq!(p, i);
    }

    #[test]
    fn tier_serde() {
        for t in [
            VendorTier::Critical,
            VendorTier::High,
            VendorTier::Medium,
            VendorTier::Low,
        ] {
            let j = serde_json::to_string(&t).unwrap();
            let p: VendorTier = serde_json::from_str(&j).unwrap();
            assert_eq!(p, t);
        }
    }

    #[test]
    fn data_access_serde() {
        for d in [
            DataAccessLevel::None,
            DataAccessLevel::Aggregated,
            DataAccessLevel::Pii,
            DataAccessLevel::Sensitive,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let p: DataAccessLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, d);
        }
    }

    #[test]
    fn issue_severity_serde() {
        for s in [
            VendorIssueSeverity::Critical,
            VendorIssueSeverity::High,
            VendorIssueSeverity::Medium,
            VendorIssueSeverity::Low,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: VendorIssueSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = reg();
        assert!(r.vendor("ghost").is_none());
    }

    #[test]
    fn all_returns_all_vendors() {
        let r = reg();
        r.onboard(
            "v2",
            "x",
            "y",
            VendorTier::Low,
            DataAccessLevel::None,
            "EU",
        )
        .unwrap();
        assert_eq!(r.all().len(), 2);
    }
}
