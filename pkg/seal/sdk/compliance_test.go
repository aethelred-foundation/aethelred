package sdk

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	auditpkg "github.com/aethelred/aethelred/pkg/audit"
	auditexport "github.com/aethelred/aethelred/pkg/audit/export"
	"github.com/aethelred/aethelred/pkg/evidence"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestNewTrustCompliancePackageAttachment(t *testing.T) {
	doc := auditexport.BuildPouwTrustComplianceExport(
		"2026-04-14T14:00:00Z",
		&pouwkeeper.QueryModuleStatusResponse{BlockHeight: 42, CurrentEpoch: 7, TotalUWU: 99},
		&pouwkeeper.EnterpriseAuditTrustRegistryStatus{Configured: true, Version: "2026.04.14", Source: "pouw_governance"},
		&pouwkeeper.EnterpriseAuditTrustRegistry{
			Version: "2026.04.14",
			Source:  "pouw_governance",
		},
		[]pouwkeeper.AuditRecord{{Sequence: 1, Action: "enterprise_audit_trust_registry_updated", Actor: "gov-authority", Timestamp: "2026-04-14T13:00:00Z"}},
		&pouwkeeper.ComplianceReport{
			Generated:   "2026-04-14T14:00:00Z",
			TotalCount:  1,
			MappedCount: 1,
			CoverageP:   100.0,
			Controls: []pouwkeeper.ComplianceControl{
				{Regulation: "HIPAA", ControlID: "164.312(a)(1)", ControlName: "Access Control", Artifact: "x/pouw/keeper/keeper.go", EvidenceType: "code", Status: pouwkeeper.ComplianceStatusMapped},
			},
		},
	)

	payload, err := auditexport.ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceJSON returned error: %v", err)
	}
	pkg, err := auditexport.CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(10 + i)
	}
	if err := pkg.SignEd25519(ed25519.NewKeyFromSeed(seed), "validator:test-attachment"); err != nil {
		t.Fatalf("SignEd25519 returned error: %v", err)
	}
	pkg.AuditAnchor = &pouwkeeper.AuditRecord{
		Sequence:    9,
		Action:      "trust_compliance_export_anchored",
		Actor:       "validator:test-attachment",
		Timestamp:   "2026-04-14T14:00:05Z",
		BlockHeight: 42,
		Details: map[string]string{
			"package_hash":  pkg.Manifest.PackageHash,
			"payload_hash":  pkg.Manifest.PayloadHash,
			"document_hash": pkg.Manifest.DocumentHash,
		},
	}
	pkg.AuditAnchor.RecordHash = auditpkg.ComputeRecordHash(*pkg.AuditAnchor)

	attachment, err := NewTrustCompliancePackageAttachment(pkg)
	if err != nil {
		t.Fatalf("NewTrustCompliancePackageAttachment returned error: %v", err)
	}
	if attachment.Type != EvidenceTypeTrustCompliancePackage {
		t.Fatalf("expected trust compliance package evidence type, got %s", attachment.Type)
	}
	if attachment.Signer != "validator:test-attachment" {
		t.Fatalf("unexpected signer %q", attachment.Signer)
	}
	var artifact evidence.TrustCompliancePackageEvidence
	if err := json.Unmarshal(attachment.Data, &artifact); err != nil {
		t.Fatalf("unmarshal attachment data: %v", err)
	}
	if artifact.PackageHash != pkg.Manifest.PackageHash || artifact.AuditAnchor == nil {
		t.Fatalf("expected canonical artifact in attachment, got %+v", artifact)
	}

	pkg.AuditAnchor.Details["package_hash"] = "tampered"
	if _, err := NewTrustCompliancePackageAttachment(pkg); err == nil {
		t.Fatal("expected tampered audit anchor to fail attachment creation")
	}
}
