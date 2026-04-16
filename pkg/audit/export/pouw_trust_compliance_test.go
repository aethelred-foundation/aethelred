package export

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestBuildPouwTrustComplianceExport(t *testing.T) {
	doc := BuildPouwTrustComplianceExport(
		"2026-04-14T14:00:00Z",
		&pouwkeeper.QueryModuleStatusResponse{
			BlockHeight:  42,
			CurrentEpoch: 7,
			TotalUWU:     99,
		},
		&pouwkeeper.EnterpriseAuditTrustRegistryStatus{
			Configured:              true,
			Version:                 "2026.04.14",
			Source:                  "pouw_governance",
			PolicySignerCount:       2,
			ActivePolicySignerCount: 1,
			AllowedSponsorCount:     1,
			ActiveSponsorCount:      1,
		},
		&pouwkeeper.EnterpriseAuditTrustRegistry{
			Version:              "2026.04.14",
			Source:               "pouw_governance",
			RequiredAction:       "audit.control_ledger.write",
			RequiredJurisdiction: "UAE",
		},
		[]pouwkeeper.AuditRecord{
			{Sequence: 1, Action: "enterprise_audit_trust_registry_updated", Actor: "gov-authority", Timestamp: "2026-04-14T13:00:00Z"},
			{Sequence: 2, Action: "enterprise_audit_trust_registry_cleared", Actor: "gov-authority", Timestamp: "2026-04-14T13:30:00Z"},
		},
		&pouwkeeper.ComplianceReport{
			Generated:   "2026-04-14T14:00:00Z",
			TotalCount:  2,
			MappedCount: 1,
			GapCount:    1,
			CoverageP:   50.0,
			Controls: []pouwkeeper.ComplianceControl{
				{Regulation: "HIPAA", ControlID: "164.312(a)(1)", ControlName: "Access Control", Artifact: "x/pouw/keeper/keeper.go", EvidenceType: "code", Status: pouwkeeper.ComplianceStatusMapped},
				{Regulation: "GDPR", ControlID: "Art 35", ControlName: "DPIA", EvidenceType: "doc", Status: pouwkeeper.ComplianceStatusUnmapped},
			},
		},
	)

	if doc.ExportVersion != PouwTrustComplianceExportVersion {
		t.Fatalf("unexpected export version %q", doc.ExportVersion)
	}
	if doc.HistorySummary == nil || doc.HistorySummary.TotalRecords != 2 || doc.HistorySummary.LatestAction != "enterprise_audit_trust_registry_cleared" {
		t.Fatalf("unexpected history summary %+v", doc.HistorySummary)
	}
	if doc.ComplianceSummary == nil || doc.ComplianceSummary.TotalControls != 2 || len(doc.ComplianceSummary.RegulationBreakdown) != 2 {
		t.Fatalf("unexpected compliance summary %+v", doc.ComplianceSummary)
	}
}

func TestExportPouwTrustComplianceCSV(t *testing.T) {
	doc := BuildPouwTrustComplianceExport(
		"2026-04-14T14:00:00Z",
		&pouwkeeper.QueryModuleStatusResponse{BlockHeight: 42, CurrentEpoch: 7, TotalUWU: 99},
		&pouwkeeper.EnterpriseAuditTrustRegistryStatus{Configured: true, Version: "2026.04.14", Source: "pouw_governance"},
		&pouwkeeper.EnterpriseAuditTrustRegistry{
			PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
				DID:          "did:aethelred:policy-gateway-1",
				PublicKeyHex: "abc123",
				Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
			}},
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

	payload, err := ExportPouwTrustComplianceCSV(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceCSV returned error: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(string(payload))).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) < 5 {
		t.Fatalf("expected multiple csv rows, got %d", len(rows))
	}
	body := string(payload)
	if !strings.Contains(body, "compliance_summary") || !strings.Contains(body, "regulation_summary") || !strings.Contains(body, "compliance_control") {
		t.Fatalf("expected compliance csv rows, got %q", body)
	}
}

func TestExportPouwTrustComplianceOSCAL(t *testing.T) {
	doc := BuildPouwTrustComplianceExport(
		"2026-04-14T14:00:00Z",
		&pouwkeeper.QueryModuleStatusResponse{BlockHeight: 42, CurrentEpoch: 7, TotalUWU: 99},
		&pouwkeeper.EnterpriseAuditTrustRegistryStatus{
			Configured:              true,
			Version:                 "2026.04.14",
			Source:                  "pouw_governance",
			PolicySignerCount:       1,
			ActivePolicySignerCount: 1,
		},
		&pouwkeeper.EnterpriseAuditTrustRegistry{
			Version: "2026.04.14",
			Source:  "pouw_governance",
			PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
				DID:          "did:aethelred:policy-gateway-1",
				PublicKeyHex: "abc123",
				Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
			}},
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

	payload, err := ExportPouwTrustComplianceOSCAL(doc)
	if err != nil {
		t.Fatalf("ExportPouwTrustComplianceOSCAL returned error: %v", err)
	}

	var decoded OSCALAssessmentResult
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal oscal payload: %v", err)
	}
	if decoded.AssessmentResults.Metadata.Title == "" || len(decoded.AssessmentResults.Results) != 1 {
		t.Fatalf("unexpected oscal payload %+v", decoded)
	}
	result := decoded.AssessmentResults.Results[0]
	if len(result.Findings) != 1 || result.Findings[0].Target.TargetID != "164.312(a)(1)" {
		t.Fatalf("unexpected oscal findings %+v", result.Findings)
	}
	if len(result.Observations) < 2 {
		t.Fatalf("expected trust observations in oscal payload, got %+v", result.Observations)
	}
}

func TestNormalizePouwTrustComplianceFormat(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "", want: "json"},
		{input: "json", want: "json"},
		{input: "csv", want: "csv"},
		{input: "oscal", want: "oscal"},
	} {
		got, err := NormalizePouwTrustComplianceFormat(tc.input)
		if err != nil {
			t.Fatalf("NormalizePouwTrustComplianceFormat(%q) returned error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizePouwTrustComplianceFormat(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}

	if _, err := NormalizePouwTrustComplianceFormat("yaml"); err == nil {
		t.Fatal("expected unsupported format error")
	}
}
