//! Compliance-certification lifecycle tracker.
//!
//! Tracks the validity windows of compliance certifications the *organization
//! itself* holds (SOC 2 Type II, ISO 27001, PCI-DSS, HIPAA, FedRAMP). For
//! each certification:
//!
//! - Issue + expiry dates.
//! - Renewal lead-time tracking ("alert N days before expiry").
//! - Audit history.
//! - Linked controls / policy ids.
//! - Status transitions (Active / RenewalDue / Expired / Revoked).
//!
//! Distinct from [`crate::third_party_risk`] which tracks *vendor*
//! certifications.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// CertStatus
// =============================================================================

/// Lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    /// Active.
    Active,
    /// Within renewal lead time (deadline approaching).
    RenewalDue,
    /// Past expiry.
    Expired,
    /// Revoked early.
    Revoked,
    /// In progress (not yet issued).
    Pending,
}

// =============================================================================
// AuditPass
// =============================================================================

/// One historical audit pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPass {
    /// Stable id.
    pub audit_id: Uuid,
    /// RFC 3339 conducted at.
    pub conducted_at: String,
    /// Auditor.
    pub auditor: String,
    /// `true` if passed.
    pub passed: bool,
    /// Number of findings.
    pub findings_count: u32,
    /// Optional report url.
    pub report_url: Option<String>,
}

// =============================================================================
// Certification
// =============================================================================

/// One certification we hold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certification {
    /// Stable id.
    pub cert_id: String,
    /// Name (e.g. `"SOC 2 Type II"`).
    pub name: String,
    /// Standard (e.g. `"AICPA TSC 2017"`).
    pub standard: String,
    /// Issuing body.
    pub issuer: String,
    /// RFC 3339 issued.
    pub issued_at: String,
    /// RFC 3339 expires.
    pub expires_at: String,
    /// Days before expiry to flag as RenewalDue.
    pub renewal_lead_days: i64,
    /// Linked policy ids.
    pub policy_ids: Vec<String>,
    /// Audit pass history.
    pub audit_history: Vec<AuditPass>,
    /// Override status (if Revoked).
    pub manual_status: Option<CertStatus>,
}

impl Certification {
    /// Compute current status as of `now`.
    pub fn status_at(&self, now: OffsetDateTime) -> CertStatus {
        if let Some(s) = self.manual_status {
            return s;
        }
        let exp = match OffsetDateTime::parse(
            &self.expires_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(t) => t,
            Err(_) => return CertStatus::Pending,
        };
        let issued = OffsetDateTime::parse(
            &self.issued_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok();
        if let Some(i) = issued {
            if now < i {
                return CertStatus::Pending;
            }
        }
        if now >= exp {
            return CertStatus::Expired;
        }
        let lead = time::Duration::days(self.renewal_lead_days);
        if exp - now <= lead {
            return CertStatus::RenewalDue;
        }
        CertStatus::Active
    }

    /// Days until expiry as of `now` (negative if past).
    pub fn days_until_expiry(&self, now: OffsetDateTime) -> Option<i64> {
        let exp = OffsetDateTime::parse(
            &self.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        Some((exp - now).whole_days())
    }

    /// Latest audit (by conducted_at).
    pub fn latest_audit(&self) -> Option<&AuditPass> {
        self.audit_history
            .iter()
            .max_by(|a, b| a.conducted_at.cmp(&b.conducted_at))
    }
}

// =============================================================================
// CertificationRegistry
// =============================================================================

#[derive(Default)]
struct State {
    certs: HashMap<String, Certification>,
}

/// Registry.
pub struct CertificationRegistry {
    state: RwLock<State>,
}

impl Default for CertificationRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for CertificationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificationRegistry")
            .field("certs", &self.len())
            .finish()
    }
}

impl CertificationRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a certification.
    pub fn register(&self, c: Certification) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("certification registry poisoned".into()))?;
        if g.certs.contains_key(&c.cert_id) {
            return Err(SandboxError::Other(format!(
                "certification {} already registered",
                c.cert_id
            )));
        }
        g.certs.insert(c.cert_id.clone(), c);
        Ok(())
    }

    /// Add an audit pass.
    pub fn record_audit(&self, cert_id: &str, pass: AuditPass) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("certification registry poisoned".into()))?;
        let c = g.certs.get_mut(cert_id).ok_or_else(|| {
            SandboxError::Other(format!("certification {} not found", cert_id))
        })?;
        c.audit_history.push(pass);
        Ok(())
    }

    /// Manually revoke.
    pub fn revoke(&self, cert_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("certification registry poisoned".into()))?;
        let c = g.certs.get_mut(cert_id).ok_or_else(|| {
            SandboxError::Other(format!("certification {} not found", cert_id))
        })?;
        c.manual_status = Some(CertStatus::Revoked);
        Ok(())
    }

    /// Replace expiry (renewal).
    pub fn renew_until(&self, cert_id: &str, new_expires_at: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("certification registry poisoned".into()))?;
        let c = g.certs.get_mut(cert_id).ok_or_else(|| {
            SandboxError::Other(format!("certification {} not found", cert_id))
        })?;
        c.expires_at = new_expires_at.into();
        c.manual_status = None; // Clear any override.
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, cert_id: &str) -> Option<Certification> {
        self.state.read().ok()?.certs.get(cert_id).cloned()
    }

    /// All certifications.
    pub fn all(&self) -> Vec<Certification> {
        self.state
            .read()
            .map(|g| g.certs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Certifications matching a status as of `now`.
    pub fn by_status(&self, now: OffsetDateTime, status: CertStatus) -> Vec<Certification> {
        self.all()
            .into_iter()
            .filter(|c| c.status_at(now) == status)
            .collect()
    }

    /// Renewal-due (within lead-time).
    pub fn renewal_due(&self, now: OffsetDateTime) -> Vec<Certification> {
        self.by_status(now, CertStatus::RenewalDue)
    }

    /// Expired (or revoked).
    pub fn expired_or_revoked(&self, now: OffsetDateTime) -> Vec<Certification> {
        self.all()
            .into_iter()
            .filter(|c| {
                let s = c.status_at(now);
                s == CertStatus::Expired || s == CertStatus::Revoked
            })
            .collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.certs.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(id: &str, issued: &str, expires: &str, lead: i64) -> Certification {
        Certification {
            cert_id: id.into(),
            name: "SOC 2".into(),
            standard: "AICPA".into(),
            issuer: "BIG4".into(),
            issued_at: issued.into(),
            expires_at: expires.into(),
            renewal_lead_days: lead,
            policy_ids: vec![],
            audit_history: vec![],
            manual_status: None,
        }
    }

    fn now_at(iso: &str) -> OffsetDateTime {
        OffsetDateTime::parse(iso, &time::format_description::well_known::Rfc3339).unwrap()
    }

    #[test]
    fn active_status_within_window() {
        let c = cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        );
        assert_eq!(
            c.status_at(now_at("2026-06-01T00:00:00Z")),
            CertStatus::Active
        );
    }

    #[test]
    fn expired_after_expires() {
        let c = cert(
            "x",
            "2020-01-01T00:00:00Z",
            "2022-01-01T00:00:00Z",
            30,
        );
        assert_eq!(
            c.status_at(now_at("2026-01-01T00:00:00Z")),
            CertStatus::Expired
        );
    }

    #[test]
    fn renewal_due_within_lead() {
        let c = cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2026-06-30T00:00:00Z",
            30,
        );
        // 10 days before expiry.
        assert_eq!(
            c.status_at(now_at("2026-06-25T00:00:00Z")),
            CertStatus::RenewalDue
        );
    }

    #[test]
    fn pending_before_issue() {
        let c = cert(
            "x",
            "2030-01-01T00:00:00Z",
            "2032-01-01T00:00:00Z",
            30,
        );
        assert_eq!(
            c.status_at(now_at("2025-01-01T00:00:00Z")),
            CertStatus::Pending
        );
    }

    #[test]
    fn manual_revoke_overrides() {
        let mut c = cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        );
        c.manual_status = Some(CertStatus::Revoked);
        assert_eq!(
            c.status_at(now_at("2026-06-01T00:00:00Z")),
            CertStatus::Revoked
        );
    }

    #[test]
    fn days_until_expiry_positive() {
        let c = cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
            30,
        );
        let d = c.days_until_expiry(now_at("2026-01-01T00:00:00Z")).unwrap();
        assert!(d > 0);
    }

    #[test]
    fn days_until_expiry_negative_after_expiry() {
        let c = cert(
            "x",
            "2020-01-01T00:00:00Z",
            "2022-01-01T00:00:00Z",
            30,
        );
        let d = c.days_until_expiry(now_at("2026-01-01T00:00:00Z")).unwrap();
        assert!(d < 0);
    }

    #[test]
    fn registry_register_and_get() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        assert!(r.get("x").is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = CertificationRegistry::new();
        let c = cert("x", "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z", 30);
        r.register(c.clone()).unwrap();
        assert!(r.register(c).is_err());
    }

    #[test]
    fn record_audit_appends() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        r.record_audit(
            "x",
            AuditPass {
                audit_id: Uuid::now_v7(),
                conducted_at: "2026-01-01T00:00:00Z".into(),
                auditor: "BIG4".into(),
                passed: true,
                findings_count: 0,
                report_url: None,
            },
        )
        .unwrap();
        let c = r.get("x").unwrap();
        assert_eq!(c.audit_history.len(), 1);
    }

    #[test]
    fn record_audit_unknown_errors() {
        let r = CertificationRegistry::new();
        let p = AuditPass {
            audit_id: Uuid::now_v7(),
            conducted_at: "x".into(),
            auditor: "x".into(),
            passed: true,
            findings_count: 0,
            report_url: None,
        };
        assert!(r.record_audit("ghost", p).is_err());
    }

    #[test]
    fn revoke_sets_manual_status() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        r.revoke("x").unwrap();
        let c = r.get("x").unwrap();
        assert_eq!(c.manual_status, Some(CertStatus::Revoked));
    }

    #[test]
    fn renew_clears_manual_status() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        r.revoke("x").unwrap();
        r.renew_until("x", "2030-01-01T00:00:00Z").unwrap();
        let c = r.get("x").unwrap();
        assert_eq!(c.expires_at, "2030-01-01T00:00:00Z");
        assert!(c.manual_status.is_none());
    }

    #[test]
    fn renewal_due_filter() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2026-06-30T00:00:00Z",
            30,
        ))
        .unwrap();
        let due = r.renewal_due(now_at("2026-06-25T00:00:00Z"));
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn expired_or_revoked_filter() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2020-01-01T00:00:00Z",
            "2022-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        r.register(cert(
            "y",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        r.revoke("y").unwrap();
        let v = r.expired_or_revoked(now_at("2026-01-01T00:00:00Z"));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn latest_audit_picks_newest() {
        let r = CertificationRegistry::new();
        r.register(cert(
            "x",
            "2025-01-01T00:00:00Z",
            "2030-01-01T00:00:00Z",
            30,
        ))
        .unwrap();
        r.record_audit(
            "x",
            AuditPass {
                audit_id: Uuid::now_v7(),
                conducted_at: "2025-01-01T00:00:00Z".into(),
                auditor: "a".into(),
                passed: true,
                findings_count: 1,
                report_url: None,
            },
        )
        .unwrap();
        r.record_audit(
            "x",
            AuditPass {
                audit_id: Uuid::now_v7(),
                conducted_at: "2026-06-01T00:00:00Z".into(),
                auditor: "b".into(),
                passed: false,
                findings_count: 5,
                report_url: None,
            },
        )
        .unwrap();
        let c = r.get("x").unwrap();
        let latest = c.latest_audit().unwrap();
        assert!(!latest.passed);
    }

    #[test]
    fn cert_serde() {
        let c = cert("x", "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z", 30);
        let j = serde_json::to_string(&c).unwrap();
        let p: Certification = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn audit_pass_serde() {
        let a = AuditPass {
            audit_id: Uuid::now_v7(),
            conducted_at: "x".into(),
            auditor: "y".into(),
            passed: true,
            findings_count: 0,
            report_url: Some("z".into()),
        };
        let j = serde_json::to_string(&a).unwrap();
        let p: AuditPass = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn cert_status_serde() {
        for s in [
            CertStatus::Active,
            CertStatus::RenewalDue,
            CertStatus::Expired,
            CertStatus::Revoked,
            CertStatus::Pending,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CertStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn malformed_expires_returns_pending() {
        let mut c = cert("x", "2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z", 30);
        c.expires_at = "not-a-date".into();
        assert_eq!(
            c.status_at(now_at("2026-01-01T00:00:00Z")),
            CertStatus::Pending
        );
    }

    #[test]
    fn registry_empty() {
        let r = CertificationRegistry::new();
        assert!(r.is_empty());
    }

    #[test]
    fn lookup_unknown_none() {
        let r = CertificationRegistry::new();
        assert!(r.get("ghost").is_none());
    }

    #[test]
    fn renew_unknown_errors() {
        let r = CertificationRegistry::new();
        assert!(r.renew_until("ghost", "2030-01-01T00:00:00Z").is_err());
    }
}
