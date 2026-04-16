package export

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	auditpkg "github.com/aethelred/aethelred/pkg/audit"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestPouwTrustCompliancePackage_VerifyUnsigned(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceCSV(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceCSV returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "csv", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}
	if pkg.Manifest.PackageHash == "" || pkg.Manifest.PayloadHash == "" || pkg.Manifest.DocumentHash == "" {
		t.Fatalf("expected manifest hashes to be populated, got %+v", pkg.Manifest)
	}
	if len(pkg.ChainOfCustody) < 2 {
		t.Fatalf("expected custody chain entries, got %+v", pkg.ChainOfCustody)
	}
	if err := VerifyPouwTrustCompliancePackage(pkg); err != nil {
		t.Fatalf("VerifyPouwTrustCompliancePackage returned error: %v", err)
	}
}

func TestPouwTrustCompliancePackage_SignAndVerify(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceOSCAL(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceOSCAL returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "oscal", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	if err := pkg.SignEd25519(privateKey, "validator:test-signer"); err != nil {
		t.Fatalf("SignEd25519 returned error: %v", err)
	}
	if pkg.Signature == nil || pkg.Signature.Algorithm != "ed25519" {
		t.Fatalf("expected ed25519 signature metadata, got %+v", pkg.Signature)
	}
	if len(pkg.VerificationKeys) != 1 {
		t.Fatalf("expected one verification key, got %+v", pkg.VerificationKeys)
	}
	if err := VerifyPouwTrustCompliancePackage(pkg); err != nil {
		t.Fatalf("VerifyPouwTrustCompliancePackage returned error: %v", err)
	}
}

func TestPouwTrustCompliancePackage_VerifyAuditAnchor(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceJSON returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}
	pkg.AuditAnchor = &pouwkeeper.AuditRecord{
		Sequence:     5,
		PreviousHash: "prev-hash",
		Category:     pouwkeeper.AuditCategoryGovernance,
		Severity:     pouwkeeper.AuditSeverityInfo,
		Action:       "trust_compliance_export_anchored",
		BlockHeight:  42,
		Timestamp:    "2026-04-14T14:00:00Z",
		Actor:        "pouw_api",
		Details: map[string]string{
			"package_hash":  pkg.Manifest.PackageHash,
			"payload_hash":  pkg.Manifest.PayloadHash,
			"document_hash": pkg.Manifest.DocumentHash,
		},
	}
	pkg.AuditAnchor.RecordHash = auditpkg.ComputeRecordHash(*pkg.AuditAnchor)

	if err := VerifyPouwTrustCompliancePackage(pkg); err != nil {
		t.Fatalf("VerifyPouwTrustCompliancePackage returned error: %v", err)
	}

	pkg.AuditAnchor.Details["package_hash"] = "tampered"
	if err := VerifyPouwTrustCompliancePackage(pkg); err == nil {
		t.Fatal("expected audit anchor tampering to fail verification")
	}
}

func TestPouwTrustCompliancePackage_VerifyTamperedPayload(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceJSON returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}
	pkg.Payload = hex.EncodeToString([]byte("tampered"))

	if err := VerifyPouwTrustCompliancePackage(pkg); err == nil {
		t.Fatal("expected tampered payload verification to fail")
	}
}

func TestSummarizePouwTrustComplianceExportAnchor(t *testing.T) {
	record := pouwkeeper.AuditRecord{
		Sequence:    9,
		Action:      "trust_compliance_export_anchored",
		Timestamp:   "2026-04-14T14:10:00Z",
		BlockHeight: 55,
		Actor:       "validator:test-signer",
		Details: map[string]string{
			"package_hash":               "pkg-anchor-1",
			"payload_hash":               "payload-anchor-1",
			"document_hash":              "document-anchor-1",
			"format":                     "oscal",
			"export_version":             "1.0.0",
			"generated_at":               "2026-04-14T14:00:00Z",
			"history_count":              "2",
			"signed":                     "true",
			"signer":                     "validator:test-signer",
			"signature_key_id":           "key-1",
			"signature_algorithm":        "ed25519",
			"custody_entries":            "3",
			"trust_registry_version":     "2026.04.14",
			"trust_registry_source":      "pouw_governance",
			"compliance_total_controls":  "12",
			"compliance_mapped_controls": "10",
			"compliance_gap_controls":    "2",
		},
	}

	summary, err := SummarizePouwTrustComplianceExportAnchor(record)
	if err != nil {
		t.Fatalf("SummarizePouwTrustComplianceExportAnchor returned error: %v", err)
	}
	if summary.PackageHash != "pkg-anchor-1" || summary.Format != "oscal" {
		t.Fatalf("unexpected anchor summary %+v", summary)
	}
	if !summary.Signed || summary.CustodyEntries != 3 || summary.ComplianceGap != 2 {
		t.Fatalf("unexpected normalized anchor fields %+v", summary)
	}
}

func TestVerifyPouwTrustCompliancePackageDetailed(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceJSON returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}
	result := VerifyPouwTrustCompliancePackageDetailed(pkg)
	if result == nil || !result.Valid {
		t.Fatalf("expected valid detailed verification result, got %+v", result)
	}
	if result.Summary == nil || result.Summary.PackageHash != pkg.Manifest.PackageHash {
		t.Fatalf("expected package summary in verification result, got %+v", result)
	}

	pkg.Manifest.PayloadHash = "tampered"
	result = VerifyPouwTrustCompliancePackageDetailed(pkg)
	if result == nil || result.Valid {
		t.Fatalf("expected invalid detailed verification result, got %+v", result)
	}
	if len(result.Errors) == 0 {
		t.Fatalf("expected verification errors, got %+v", result)
	}
}

func TestToEvidenceTrustCompliancePackage(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceJSON returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}
	pkg.AuditAnchor = &pouwkeeper.AuditRecord{
		Sequence:     8,
		PreviousHash: "prev-hash",
		Category:     pouwkeeper.AuditCategoryGovernance,
		Severity:     pouwkeeper.AuditSeverityInfo,
		Action:       "trust_compliance_export_anchored",
		BlockHeight:  42,
		Timestamp:    "2026-04-14T14:00:00Z",
		Actor:        "pouw_api",
		Details: map[string]string{
			"package_hash":  pkg.Manifest.PackageHash,
			"payload_hash":  pkg.Manifest.PayloadHash,
			"document_hash": pkg.Manifest.DocumentHash,
		},
	}
	pkg.AuditAnchor.RecordHash = auditpkg.ComputeRecordHash(*pkg.AuditAnchor)

	artifact, err := ToEvidenceTrustCompliancePackage(pkg)
	if err != nil {
		t.Fatalf("ToEvidenceTrustCompliancePackage returned error: %v", err)
	}
	if artifact.ID == "" || artifact.PackageHash != pkg.Manifest.PackageHash {
		t.Fatalf("unexpected evidence artifact %+v", artifact)
	}
	if artifact.AuditAnchor == nil || artifact.AuditAnchor.Sequence != 8 {
		t.Fatalf("expected audit anchor to survive evidence conversion, got %+v", artifact.AuditAnchor)
	}
}

func TestPouwTrustCompliancePackage_PayloadBytes(t *testing.T) {
	doc := testPouwTrustComplianceDocument()
	payload, err := ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceJSON returned error: %v", err)
	}

	pkg, err := CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("CreatePouwTrustCompliancePackage returned error: %v", err)
	}

	decoded, err := pkg.PayloadBytes()
	if err != nil {
		t.Fatalf("PayloadBytes returned error: %v", err)
	}
	if !strings.Contains(string(decoded), "\"export_version\"") {
		t.Fatalf("unexpected decoded payload %q", string(decoded))
	}
}

func testPouwTrustComplianceDocument() *PouwTrustComplianceExport {
	return BuildPouwTrustComplianceExport(
		"2026-04-14T14:00:00Z",
		testModuleStatus(),
		testTrustStatus(),
		testTrustRegistry(),
		testTrustHistory(),
		testComplianceReport(),
	)
}

func testModuleStatus() *pouwkeeper.QueryModuleStatusResponse {
	return &pouwkeeper.QueryModuleStatusResponse{
		BlockHeight:  42,
		CurrentEpoch: 7,
		TotalUWU:     99,
	}
}

func testTrustStatus() *pouwkeeper.EnterpriseAuditTrustRegistryStatus {
	return &pouwkeeper.EnterpriseAuditTrustRegistryStatus{
		Configured:              true,
		Version:                 "2026.04.14",
		Source:                  "pouw_governance",
		PolicySignerCount:       1,
		ActivePolicySignerCount: 1,
	}
}

func testTrustRegistry() *pouwkeeper.EnterpriseAuditTrustRegistry {
	return &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		Source:               "pouw_governance",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:          "did:aethelred:policy-gateway-1",
			PublicKeyHex: "abc123",
			Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
	}
}

func testTrustHistory() []pouwkeeper.AuditRecord {
	return []pouwkeeper.AuditRecord{
		{Sequence: 1, Action: "enterprise_audit_trust_registry_updated", Actor: "gov-authority", Timestamp: "2026-04-14T13:00:00Z"},
	}
}

func testComplianceReport() *pouwkeeper.ComplianceReport {
	return &pouwkeeper.ComplianceReport{
		Generated:   "2026-04-14T14:00:00Z",
		TotalCount:  1,
		MappedCount: 1,
		CoverageP:   100.0,
		Controls: []pouwkeeper.ComplianceControl{
			{Regulation: "HIPAA", ControlID: "164.312(a)(1)", ControlName: "Access Control", Artifact: "x/pouw/keeper/keeper.go", EvidenceType: "code", Status: pouwkeeper.ComplianceStatusMapped},
		},
	}
}
