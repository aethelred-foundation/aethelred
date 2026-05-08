//! Evidence packaging — sign + bundle for regulator submissions.
//!
//! When a regulator opens an investigation or a customer requests a SOC 2
//! evidence package, the operator needs to deliver a *single, tamper-evident
//! artifact* that contains:
//!
//! - The seals (or seal subset) under examination.
//! - Their Merkle proofs against a chain root.
//! - The compliance-control mapping.
//! - The workspace audit log relevant to the period.
//! - A signed manifest tying it all together.
//!
//! This module produces such a bundle. It does **not** ship a ZIP encoder —
//! the on-disk format is left to deployment (often a tarball or a signed
//! S3 object). What this module produces is the canonical [`EvidencePackage`]
//! Rust value with a stable JSON serialization that any tarball/zip writer
//! can ingest. Each package includes a [`PackageManifest`] whose hash chain
//! seals the entire contents.

use crate::audit::AuditFormat;
use crate::compliance_report::ComplianceReport;
use crate::evidence::EvidenceBundle;
use crate::hashing::{Hasher, Sha256Digest};
use crate::seal::DigitalSeal;
use crate::workspace_audit::WorkspaceAuditEntry;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// PackageRecipient
// =============================================================================

/// Who the package is for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageRecipient {
    /// Recipient name (e.g., `"HKMA — Banking Supervision"`).
    pub name: String,
    /// Optional case / matter id.
    pub case_id: Option<String>,
    /// Jurisdiction code (e.g., `"HK"`, `"EU"`, `"AE"`).
    pub jurisdiction: String,
}

// =============================================================================
// EvidenceFile — one file in the package
// =============================================================================

/// One file in the package — JSON or text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFile {
    /// Logical path inside the package (e.g., `"seals/seals.json"`).
    pub path: String,
    /// MIME type.
    pub mime_type: String,
    /// SHA-256 of the file contents.
    pub content_hash: Sha256Digest,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Optional human description.
    pub description: Option<String>,
    /// Inline content (UTF-8). For binary content callers must base64-encode
    /// before passing.
    pub content_utf8: String,
}

impl EvidenceFile {
    /// Build a UTF-8 evidence file from arbitrary bytes/string.
    pub fn from_text(
        path: impl Into<String>,
        mime_type: impl Into<String>,
        content: impl Into<String>,
        description: Option<String>,
    ) -> Self {
        let content = content.into();
        let content_hash = Hasher::sha256(content.as_bytes());
        let size = content.len() as u64;
        Self {
            path: path.into(),
            mime_type: mime_type.into(),
            content_hash,
            size_bytes: size,
            description,
            content_utf8: content,
        }
    }
}

// =============================================================================
// PackageManifest
// =============================================================================

/// Manifest sealing the package contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageManifest {
    /// Package id.
    pub package_id: Uuid,
    /// Recipient.
    pub recipient: PackageRecipient,
    /// Tenant scope (None for cross-tenant).
    pub tenant_id: Option<String>,
    /// Time window covered (RFC 3339).
    pub window_from: Option<String>,
    /// Time window covered (RFC 3339).
    pub window_to: Option<String>,
    /// Per-file digest list (path → hash).
    pub files: Vec<EvidenceFile>,
    /// Aggregate hash of the manifest contents (computed last).
    pub manifest_hash: Sha256Digest,
    /// RFC 3339 issue timestamp.
    pub issued_at: String,
    /// Operator who built the package.
    pub issued_by: String,
}

impl PackageManifest {
    fn compute_hash(
        package_id: &Uuid,
        recipient: &PackageRecipient,
        tenant_id: Option<&str>,
        window_from: Option<&str>,
        window_to: Option<&str>,
        files: &[EvidenceFile],
        issued_at: &str,
        issued_by: &str,
    ) -> Sha256Digest {
        let mut input = Vec::new();
        input.extend_from_slice(package_id.as_bytes());
        input.extend_from_slice(recipient.name.as_bytes());
        input.push(0);
        input.extend_from_slice(recipient.jurisdiction.as_bytes());
        input.push(0);
        if let Some(c) = &recipient.case_id {
            input.extend_from_slice(c.as_bytes());
        }
        input.push(0);
        if let Some(t) = tenant_id {
            input.extend_from_slice(t.as_bytes());
        }
        input.push(0);
        if let Some(w) = window_from {
            input.extend_from_slice(w.as_bytes());
        }
        input.push(0);
        if let Some(w) = window_to {
            input.extend_from_slice(w.as_bytes());
        }
        input.push(0);
        for f in files {
            input.extend_from_slice(f.path.as_bytes());
            input.push(0);
            input.extend_from_slice(&f.content_hash.0);
            input.extend_from_slice(&f.size_bytes.to_le_bytes());
        }
        input.extend_from_slice(issued_at.as_bytes());
        input.push(0);
        input.extend_from_slice(issued_by.as_bytes());
        Hasher::sha256(&input)
    }
}

// =============================================================================
// EvidencePackage
// =============================================================================

/// One regulator-ready evidence package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePackage {
    /// The manifest (also embedded as a file inside the bundle).
    pub manifest: PackageManifest,
    /// All evidence files.
    pub files: Vec<EvidenceFile>,
}

impl EvidencePackage {
    /// Verify the package: every file hash matches its declared content
    /// hash, and the manifest hash matches the recomputed manifest hash.
    pub fn verify(&self) -> SandboxResult<()> {
        // Per-file hashes.
        for f in &self.files {
            let h = Hasher::sha256(f.content_utf8.as_bytes());
            if h != f.content_hash {
                return Err(SandboxError::Other(format!(
                    "evidence file {} hash mismatch",
                    f.path
                )));
            }
        }
        // Manifest hash.
        let m = &self.manifest;
        let recomputed = PackageManifest::compute_hash(
            &m.package_id,
            &m.recipient,
            m.tenant_id.as_deref(),
            m.window_from.as_deref(),
            m.window_to.as_deref(),
            &m.files,
            &m.issued_at,
            &m.issued_by,
        );
        if recomputed != m.manifest_hash {
            return Err(SandboxError::Other("manifest hash mismatch".into()));
        }
        // Files inside package match files in manifest.
        if m.files.len() != self.files.len() {
            return Err(SandboxError::Other(
                "manifest file count != package file count".into(),
            ));
        }
        for (mf, pf) in m.files.iter().zip(self.files.iter()) {
            if mf.content_hash != pf.content_hash {
                return Err(SandboxError::Other(format!(
                    "manifest hash for {} doesn't match package file",
                    mf.path
                )));
            }
        }
        Ok(())
    }
}

// =============================================================================
// EvidencePackager — builder
// =============================================================================

/// Builder for [`EvidencePackage`].
pub struct EvidencePackager {
    recipient: PackageRecipient,
    tenant_id: Option<String>,
    window_from: Option<String>,
    window_to: Option<String>,
    issued_by: String,
    files: Vec<EvidenceFile>,
}

impl EvidencePackager {
    /// New builder.
    pub fn new(recipient: PackageRecipient, issued_by: impl Into<String>) -> Self {
        Self {
            recipient,
            tenant_id: None,
            window_from: None,
            window_to: None,
            issued_by: issued_by.into(),
            files: Vec::new(),
        }
    }

    /// Builder: set tenant scope.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant.into());
        self
    }

    /// Builder: set time window.
    pub fn window(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.window_from = Some(from.into());
        self.window_to = Some(to.into());
        self
    }

    /// Add a raw file.
    pub fn add_file(mut self, file: EvidenceFile) -> Self {
        self.files.push(file);
        self
    }

    /// Add seals as a JSON file.
    pub fn add_seals(mut self, seals: &[DigitalSeal]) -> SandboxResult<Self> {
        let json = serde_json::to_string_pretty(seals).map_err(|e| {
            SandboxError::Other(format!("seals serialize failed: {e}"))
        })?;
        self.files.push(EvidenceFile::from_text(
            "seals/seals.json",
            "application/json",
            json,
            Some(format!("{} seals", seals.len())),
        ));
        Ok(self)
    }

    /// Add an evidence bundle.
    pub fn add_evidence_bundle(mut self, bundle: &EvidenceBundle) -> SandboxResult<Self> {
        let json = serde_json::to_string_pretty(bundle).map_err(|e| {
            SandboxError::Other(format!("evidence bundle serialize failed: {e}"))
        })?;
        self.files.push(EvidenceFile::from_text(
            "evidence/bundle.json",
            "application/json",
            json,
            Some("Merkle-anchored evidence bundle".into()),
        ));
        Ok(self)
    }

    /// Add a compliance report.
    pub fn add_compliance_report(mut self, report: &ComplianceReport) -> SandboxResult<Self> {
        let json = serde_json::to_string_pretty(report).map_err(|e| {
            SandboxError::Other(format!("compliance report serialize failed: {e}"))
        })?;
        self.files.push(EvidenceFile::from_text(
            "compliance/report.json",
            "application/json",
            json,
            Some("Compliance control mapping report".into()),
        ));
        Ok(self)
    }

    /// Add workspace audit entries.
    pub fn add_workspace_audit(
        mut self,
        entries: &[WorkspaceAuditEntry],
    ) -> SandboxResult<Self> {
        let json = serde_json::to_string_pretty(entries).map_err(|e| {
            SandboxError::Other(format!("workspace audit serialize failed: {e}"))
        })?;
        self.files.push(EvidenceFile::from_text(
            "workspace/audit.json",
            "application/json",
            json,
            Some(format!("{} workspace-audit entries", entries.len())),
        ));
        Ok(self)
    }

    /// Add a rendered audit-trail file in any format.
    pub fn add_rendered_audit(self, content: String, format: AuditFormat) -> Self {
        let (path, mime) = match format {
            AuditFormat::PlainText => ("audit/audit.txt", "text/plain"),
            AuditFormat::Markdown => ("audit/audit.md", "text/markdown"),
            AuditFormat::Csv => ("audit/audit.csv", "text/csv"),
        };
        let mut s = self;
        s.files.push(EvidenceFile::from_text(
            path,
            mime,
            content,
            Some("Rendered audit trail".into()),
        ));
        s
    }

    /// Finalize the package.
    pub fn build(self) -> SandboxResult<EvidencePackage> {
        let package_id = Uuid::now_v7();
        let issued_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let manifest_hash = PackageManifest::compute_hash(
            &package_id,
            &self.recipient,
            self.tenant_id.as_deref(),
            self.window_from.as_deref(),
            self.window_to.as_deref(),
            &self.files,
            &issued_at,
            &self.issued_by,
        );
        let manifest = PackageManifest {
            package_id,
            recipient: self.recipient,
            tenant_id: self.tenant_id,
            window_from: self.window_from,
            window_to: self.window_to,
            files: self.files.clone(),
            manifest_hash,
            issued_at,
            issued_by: self.issued_by,
        };
        Ok(EvidencePackage {
            manifest,
            files: self.files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_audit::{
        WorkspaceAuditEvent, WorkspaceAuditEventKind, WorkspaceAuditLog,
    };

    fn recipient() -> PackageRecipient {
        PackageRecipient {
            name: "HKMA Banking Supervision".into(),
            case_id: Some("CASE-2026-001".into()),
            jurisdiction: "HK".into(),
        }
    }

    #[test]
    fn empty_package_builds() {
        let pkg = EvidencePackager::new(recipient(), "ops@aethelred")
            .build()
            .unwrap();
        assert!(pkg.files.is_empty());
        assert_eq!(pkg.manifest.recipient.jurisdiction, "HK");
    }

    #[test]
    fn package_with_one_file_verifies() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text(
                "test.txt",
                "text/plain",
                "hello",
                None,
            ))
            .build()
            .unwrap();
        pkg.verify().unwrap();
    }

    #[test]
    fn package_with_seals() {
        // Use empty seals slice to avoid pulling in fixtures here.
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_seals(&[])
            .unwrap()
            .build()
            .unwrap();
        pkg.verify().unwrap();
        assert_eq!(pkg.files.len(), 1);
        assert_eq!(pkg.files[0].path, "seals/seals.json");
    }

    #[test]
    fn package_with_workspace_audit() {
        let log = WorkspaceAuditLog::new();
        log.record_simple(
            "alice",
            WorkspaceAuditEvent::new(WorkspaceAuditEventKind::KeyRotated, "rot"),
        )
        .unwrap();
        let entries = log.entries();
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_workspace_audit(&entries)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(pkg.files.len(), 1);
        assert_eq!(pkg.files[0].path, "workspace/audit.json");
    }

    #[test]
    fn tampered_file_fails_verification() {
        let mut pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text(
                "x.txt",
                "text/plain",
                "v1",
                None,
            ))
            .build()
            .unwrap();
        pkg.files[0].content_utf8 = "v2".to_string();
        assert!(pkg.verify().is_err());
    }

    #[test]
    fn tampered_manifest_hash_fails() {
        let mut pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text(
                "x.txt",
                "text/plain",
                "v",
                None,
            ))
            .build()
            .unwrap();
        // Mutate package_id without recomputing hash.
        pkg.manifest.package_id = Uuid::now_v7();
        assert!(pkg.verify().is_err());
    }

    #[test]
    fn tampered_files_count_fails() {
        let mut pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text(
                "x.txt",
                "text/plain",
                "v",
                None,
            ))
            .build()
            .unwrap();
        pkg.files.push(EvidenceFile::from_text(
            "y.txt",
            "text/plain",
            "z",
            None,
        ));
        assert!(pkg.verify().is_err());
    }

    #[test]
    fn package_window_recorded() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .window("2026-01-01T00:00:00Z", "2026-03-31T23:59:59Z")
            .build()
            .unwrap();
        assert_eq!(pkg.manifest.window_from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(pkg.manifest.window_to.as_deref(), Some("2026-03-31T23:59:59Z"));
    }

    #[test]
    fn package_tenant_recorded() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .tenant("FAB")
            .build()
            .unwrap();
        assert_eq!(pkg.manifest.tenant_id.as_deref(), Some("FAB"));
    }

    #[test]
    fn rendered_audit_chooses_path_by_format() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_rendered_audit("hi".into(), AuditFormat::Markdown)
            .build()
            .unwrap();
        assert_eq!(pkg.files[0].path, "audit/audit.md");
        assert_eq!(pkg.files[0].mime_type, "text/markdown");
    }

    #[test]
    fn rendered_audit_csv() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_rendered_audit("a,b\n".into(), AuditFormat::Csv)
            .build()
            .unwrap();
        assert_eq!(pkg.files[0].path, "audit/audit.csv");
    }

    #[test]
    fn rendered_audit_plain() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_rendered_audit("hello".into(), AuditFormat::PlainText)
            .build()
            .unwrap();
        assert_eq!(pkg.files[0].path, "audit/audit.txt");
    }

    #[test]
    fn evidence_file_size_matches_content() {
        let f = EvidenceFile::from_text("p", "t", "abcd", None);
        assert_eq!(f.size_bytes, 4);
    }

    #[test]
    fn evidence_file_hash_deterministic() {
        let f1 = EvidenceFile::from_text("p", "t", "x", None);
        let f2 = EvidenceFile::from_text("p", "t", "x", None);
        assert_eq!(f1.content_hash, f2.content_hash);
    }

    #[test]
    fn package_serde_round_trip() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text("p", "t/p", "c", None))
            .build()
            .unwrap();
        let j = serde_json::to_string(&pkg).unwrap();
        let p: EvidencePackage = serde_json::from_str(&j).unwrap();
        assert_eq!(p, pkg);
    }

    #[test]
    fn manifest_includes_files_metadata() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text("a.txt", "text/plain", "x", None))
            .add_file(EvidenceFile::from_text("b.txt", "text/plain", "y", None))
            .build()
            .unwrap();
        assert_eq!(pkg.manifest.files.len(), 2);
        assert_eq!(pkg.manifest.files[0].path, "a.txt");
    }

    #[test]
    fn many_files_package_verifies() {
        let mut p = EvidencePackager::new(recipient(), "ops");
        for i in 0..20 {
            p = p.add_file(EvidenceFile::from_text(
                format!("file-{i}.txt"),
                "text/plain",
                format!("content-{i}"),
                None,
            ));
        }
        let pkg = p.build().unwrap();
        pkg.verify().unwrap();
        assert_eq!(pkg.files.len(), 20);
    }

    #[test]
    fn package_recipient_serde() {
        let r = recipient();
        let j = serde_json::to_string(&r).unwrap();
        let p: PackageRecipient = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn manifest_hash_changes_with_recipient() {
        let pkg1 = EvidencePackager::new(recipient(), "ops").build().unwrap();
        let pkg2 = EvidencePackager::new(
            PackageRecipient {
                name: "Other".into(),
                case_id: None,
                jurisdiction: "EU".into(),
            },
            "ops",
        )
        .build()
        .unwrap();
        assert_ne!(pkg1.manifest.manifest_hash, pkg2.manifest.manifest_hash);
    }

    #[test]
    fn manifest_issued_by_in_hash() {
        let pkg1 = EvidencePackager::new(recipient(), "alice").build().unwrap();
        let pkg2 = EvidencePackager::new(recipient(), "bob").build().unwrap();
        assert_ne!(pkg1.manifest.manifest_hash, pkg2.manifest.manifest_hash);
    }

    #[test]
    fn verify_after_serde_round_trip() {
        let pkg = EvidencePackager::new(recipient(), "ops")
            .add_file(EvidenceFile::from_text("p", "t/p", "data", None))
            .build()
            .unwrap();
        let j = serde_json::to_string(&pkg).unwrap();
        let p: EvidencePackage = serde_json::from_str(&j).unwrap();
        p.verify().unwrap();
    }

    #[test]
    fn evidence_file_serde_round_trip() {
        let f = EvidenceFile::from_text("p", "t/p", "x", Some("d".into()));
        let j = serde_json::to_string(&f).unwrap();
        let p: EvidenceFile = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }
}
