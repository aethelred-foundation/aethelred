package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestAuditServer_GetEnterpriseTrustRegistryStatus(t *testing.T) {
	server := NewAuditServer(nil, nil)
	server.SetEnterpriseTrustRegistryService(newTestEnterpriseTrustRegistryService(newTestEnterpriseTrustRegistry()))

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetEnterpriseTrustRegistryStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Status == nil || !resp.Status.Configured {
		t.Fatalf("expected configured trust-registry status, got %+v", resp.Status)
	}
	if resp.Status.PolicySignerCount != 1 || resp.Status.AllowedSponsorCount != 1 {
		t.Fatalf("unexpected trust-registry counts: %+v", resp.Status)
	}
}

func TestAuditServer_GetEnterpriseTrustRegistryNotConfigured(t *testing.T) {
	server := NewAuditServer(nil, nil)
	server.SetEnterpriseTrustRegistryService(newTestEnterpriseTrustRegistryService(nil))

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
}

func TestAuditServer_PutEnterpriseTrustRegistryRequiresAdminToken(t *testing.T) {
	server := NewAuditServer(nil, nil)
	server.SetEnterpriseTrustRegistryService(newTestEnterpriseTrustRegistryService(nil))
	authorizer, err := NewStaticBearerTokenRequestAuthorizer("trust-admin-token")
	if err != nil {
		t.Fatalf("new request authorizer: %v", err)
	}
	server.SetTrustRegistryAdminAuthorizer(authorizer)

	body, err := json.Marshal(PutEnterpriseTrustRegistryRequest{Registry: newTestEnterpriseTrustRegistry()})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/audit/trust-registry", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestAuditServer_PutEnterpriseTrustRegistryAcceptsRawRegistryPayload(t *testing.T) {
	server := NewAuditServer(nil, nil)
	service := newTestEnterpriseTrustRegistryService(nil)
	server.SetEnterpriseTrustRegistryService(service)
	authorizer, err := NewStaticBearerTokenRequestAuthorizer("trust-admin-token")
	if err != nil {
		t.Fatalf("new request authorizer: %v", err)
	}
	server.SetTrustRegistryAdminAuthorizer(authorizer)

	body, err := json.Marshal(newTestEnterpriseTrustRegistry())
	if err != nil {
		t.Fatalf("marshal registry: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/audit/trust-registry", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer trust-admin-token")
	req.Header.Set("X-Aethelred-Actor", "did:aethelred:ops-admin")
	req.Header.Set("X-Aethelred-Reason", "activate trust plane")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if service.lastActor != "did:aethelred:ops-admin" {
		t.Fatalf("expected actor to propagate from header, got %q", service.lastActor)
	}
	if service.lastReason != "activate trust plane" {
		t.Fatalf("expected reason to propagate from header, got %q", service.lastReason)
	}

	var resp PutEnterpriseTrustRegistryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Registry == nil || resp.Registry.Version != "2026.04.14" {
		t.Fatalf("unexpected registry response: %+v", resp.Registry)
	}
	if resp.Status == nil || !resp.Status.Configured {
		t.Fatalf("expected configured status, got %+v", resp.Status)
	}
}

func TestAuditServer_DeleteEnterpriseTrustRegistry(t *testing.T) {
	server := NewAuditServer(nil, nil)
	service := newTestEnterpriseTrustRegistryService(newTestEnterpriseTrustRegistry())
	server.SetEnterpriseTrustRegistryService(service)
	authorizer, err := NewStaticBearerTokenRequestAuthorizer("trust-admin-token")
	if err != nil {
		t.Fatalf("new request authorizer: %v", err)
	}
	server.SetTrustRegistryAdminAuthorizer(authorizer)

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/audit/trust-registry", strings.NewReader(`{"actor":"did:aethelred:ops-admin","reason":"containment drill"}`))
	req.Header.Set("Authorization", "Bearer trust-admin-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp DeleteEnterpriseTrustRegistryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Cleared {
		t.Fatalf("expected cleared=true, got %+v", resp)
	}
	if resp.Status == nil || resp.Status.Configured {
		t.Fatalf("expected unconfigured status after delete, got %+v", resp.Status)
	}
	if service.lastActor != "did:aethelred:ops-admin" || service.lastReason != "containment drill" {
		t.Fatalf("unexpected mutation metadata actor=%q reason=%q", service.lastActor, service.lastReason)
	}
}

func TestAuditServer_GetEnterpriseTrustRegistryHistory(t *testing.T) {
	recordUpdated := makeTestRecord(
		1,
		"genesis",
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityWarning,
		"enterprise_audit_trust_registry_updated",
		"gov-authority",
		100,
		"2026-04-14T10:00:00Z",
		map[string]string{"requested_by": "did:aethelred:ops-admin"},
	)
	recordParams := makeTestRecord(
		2,
		recordUpdated.RecordHash,
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityWarning,
		"params_updated",
		"gov-authority",
		101,
		"2026-04-14T10:05:00Z",
		nil,
	)
	recordCleared := makeTestRecord(
		3,
		recordParams.RecordHash,
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityWarning,
		"enterprise_audit_trust_registry_cleared",
		"gov-authority",
		102,
		"2026-04-14T10:10:00Z",
		map[string]string{"requested_by": "did:aethelred:ops-admin"},
	)

	studio, err := NewStudio(Config{
		LogSource: &mockLogSource{records: []keeper.AuditRecord{
			recordUpdated,
			recordParams,
			recordCleared,
		}},
	})
	if err != nil {
		t.Fatalf("new studio: %v", err)
	}

	server := NewAuditServer(studio, nil)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry/history?actor=gov-authority", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetEnterpriseTrustRegistryHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 2 || len(resp.Records) != 2 {
		t.Fatalf("expected exactly two trust-registry governance records, got total=%d len=%d", resp.Total, len(resp.Records))
	}
	if resp.Records[0].Action != "enterprise_audit_trust_registry_updated" {
		t.Fatalf("expected first history action to be update, got %q", resp.Records[0].Action)
	}
	if resp.Records[1].Action != "enterprise_audit_trust_registry_cleared" {
		t.Fatalf("expected second history action to be clear, got %q", resp.Records[1].Action)
	}
	if resp.Records[0].Details["requested_by"] != "did:aethelred:ops-admin" {
		t.Fatalf("expected requested_by detail to survive in history response, got %+v", resp.Records[0].Details)
	}
}

func TestAuditServer_GetTrustComplianceExportAnchors(t *testing.T) {
	recordAnchor := makeTestRecord(
		1,
		"genesis",
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityInfo,
		"trust_compliance_export_anchored",
		"validator:abc123",
		200,
		"2026-04-14T11:00:00Z",
		map[string]string{
			"package_hash": "pkg-1",
			"format":       "oscal",
			"signed":       "true",
		},
	)
	recordRegistry := makeTestRecord(
		2,
		recordAnchor.RecordHash,
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityWarning,
		"enterprise_audit_trust_registry_updated",
		"gov-authority",
		201,
		"2026-04-14T11:05:00Z",
		nil,
	)

	studio, err := NewStudio(Config{
		LogSource: &mockLogSource{records: []keeper.AuditRecord{
			recordAnchor,
			recordRegistry,
		}},
	})
	if err != nil {
		t.Fatalf("new studio: %v", err)
	}

	server := NewAuditServer(studio, nil)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-compliance-exports?actor=validator:abc123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetTrustComplianceExportAnchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 1 || len(resp.Records) != 1 {
		t.Fatalf("expected exactly one anchored export record, got total=%d len=%d", resp.Total, len(resp.Records))
	}
	if resp.Records[0].Action != "trust_compliance_export_anchored" {
		t.Fatalf("expected anchored export action, got %q", resp.Records[0].Action)
	}
	if resp.Records[0].Details["package_hash"] != "pkg-1" {
		t.Fatalf("expected package hash detail to survive, got %+v", resp.Records[0].Details)
	}
}

func TestAuditServer_GetControlLedger(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected application/json content type, got %q", got)
	}

	var resp GetControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Bundle == nil {
		t.Fatal("expected ledger payload in response")
	}
	if resp.Ledger.Bundle.ID != ledger.Bundle.ID {
		t.Fatalf("expected ledger id %q, got %q", ledger.Bundle.ID, resp.Ledger.Bundle.ID)
	}
}

func TestAuditServer_ExportControlLedgerFormats(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	tests := []struct {
		name               string
		url                string
		wantContentTypeSub string
		assert             func(t *testing.T, body []byte)
	}{
		{
			name:               "json",
			url:                "/api/v1/audit/control-ledgers/" + ledger.Bundle.ID + "/export?format=json",
			wantContentTypeSub: "application/json",
			assert: func(t *testing.T, body []byte) {
				t.Helper()
				var doc map[string]any
				if err := json.Unmarshal(body, &doc); err != nil {
					t.Fatalf("unmarshal json export: %v", err)
				}
				if doc["ledger_id"] != ledger.Bundle.ID {
					t.Fatalf("expected ledger_id %q, got %v", ledger.Bundle.ID, doc["ledger_id"])
				}
			},
		},
		{
			name:               "csv",
			url:                "/api/v1/audit/control-ledgers/" + ledger.Bundle.ID + "/export?format=csv",
			wantContentTypeSub: "text/csv",
			assert: func(t *testing.T, body []byte) {
				t.Helper()
				rows, err := csv.NewReader(strings.NewReader(string(body))).ReadAll()
				if err != nil {
					t.Fatalf("read csv export: %v", err)
				}
				if len(rows) < 2 || rows[0][0] != "row_type" || rows[1][0] != "summary" {
					t.Fatalf("unexpected csv export rows: %v", rows)
				}
			},
		},
		{
			name:               "oscal",
			url:                "/api/v1/audit/control-ledgers/" + ledger.Bundle.ID + "/export?format=oscal",
			wantContentTypeSub: "application/json",
			assert: func(t *testing.T, body []byte) {
				t.Helper()
				var doc map[string]any
				if err := json.Unmarshal(body, &doc); err != nil {
					t.Fatalf("unmarshal oscal export: %v", err)
				}
				if _, ok := doc["assessment-results"]; !ok {
					t.Fatalf("expected assessment-results root, got %v", doc)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); !strings.Contains(got, tt.wantContentTypeSub) {
				t.Fatalf("expected content type containing %q, got %q", tt.wantContentTypeSub, got)
			}
			tt.assert(t, rec.Body.Bytes())
		})
	}
}

func TestAuditServer_GetPortableControlLedgerPackage(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID+"/package?include_verification_keys=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var pkg evidence.PortableControlLedgerPackage
	if err := json.Unmarshal(rec.Body.Bytes(), &pkg); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if pkg.PackageHash == "" || pkg.Ledger == nil || pkg.Ledger.Bundle == nil {
		t.Fatalf("expected portable control ledger package, got %+v", pkg)
	}
	if pkg.Ledger.Summary.TotalTrustCompliancePackages != 1 {
		t.Fatalf("expected trust compliance package to survive export, got %+v", pkg.Ledger.Summary)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(&pkg); err != nil {
		t.Fatalf("verify portable control ledger package: %v", err)
	}
}

func TestAuditServer_GetPortableControlLedgerPackageSignedAndAnchored(t *testing.T) {
	server, studio := newTestAuditServerWithStudio(t)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 10)
	}
	server.SetPortableControlLedgerPackageSigner(NewEd25519PortableControlLedgerPackageSigner(ed25519.NewKeyFromSeed(seed), "validator:test-audit-api"))
	server.SetPortableControlLedgerPackageAnchorer(func(_ context.Context, pkg *evidence.PortableControlLedgerPackage) error {
		logSource := studio.source.(*mockLogSource)
		record := logSource.Append(makeTestRecord(
			uint64(len(logSource.records)+1),
			"",
			keeper.AuditCategoryGovernance,
			keeper.AuditSeverityInfo,
			"control_ledger_package_anchored",
			"validator:test-audit-api",
			321,
			"2026-04-14T12:05:00Z",
			pkg.AnchorDetails(),
		))
		pkg.AuditAnchor = &evidence.PortableControlLedgerPackageAuditAnchor{
			Sequence:     record.Sequence,
			RecordHash:   record.RecordHash,
			PreviousHash: record.PreviousHash,
			Category:     string(record.Category),
			Severity:     string(record.Severity),
			Action:       record.Action,
			BlockHeight:  record.BlockHeight,
			Timestamp:    record.Timestamp,
			Actor:        record.Actor,
			Details:      record.Details,
		}
		return nil
	})

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID+"/package?include_verification_keys=true&sign=true&anchor=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var pkg evidence.PortableControlLedgerPackage
	if err := json.Unmarshal(rec.Body.Bytes(), &pkg); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if pkg.Signature == nil || pkg.AuditAnchor == nil {
		t.Fatalf("expected signed and anchored package, got %+v", pkg)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(&pkg); err != nil {
		t.Fatalf("verify portable control ledger package: %v", err)
	}
}

func TestAuditServer_GetControlLedgerTrustCompliancePackages(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID+"/trust-compliance-packages", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetControlLedgerTrustCompliancePackagesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 1 || len(resp.Packages) != 1 {
		t.Fatalf("expected one trust compliance package, got total=%d len=%d", resp.Total, len(resp.Packages))
	}
	if resp.Packages[0].PackageHash == "" || resp.Packages[0].AuditAnchor == nil {
		t.Fatalf("expected canonical trust compliance artifact, got %+v", resp.Packages[0])
	}
}

func TestAuditServer_GetControlLedgerApproverAttestations(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID+"/approver-attestations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetControlLedgerApproverAttestationsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 1 || len(resp.Attestations) != 1 {
		t.Fatalf("expected one approver attestation, got total=%d len=%d", resp.Total, len(resp.Attestations))
	}
	if resp.Attestations[0].ApproverDID == "" || resp.Attestations[0].PolicyReceiptID == "" {
		t.Fatalf("expected canonical approver attestation artifact, got %+v", resp.Attestations[0])
	}
}

func TestAuditServer_GetControlLedgerValueSettlements(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID+"/value-settlements", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetControlLedgerValueSettlementsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 1 || len(resp.Settlements) != 1 {
		t.Fatalf("expected one value settlement, got total=%d len=%d", resp.Total, len(resp.Settlements))
	}
	if resp.Settlements[0].PolicyReceiptID == "" || resp.Settlements[0].SealID == "" {
		t.Fatalf("expected canonical value settlement artifact, got %+v", resp.Settlements[0])
	}
}

func TestAuditServer_VerifyPortableControlLedgerPackage(t *testing.T) {
	server := NewAuditServer(nil, nil)
	pkg, err := evidence.PackagePortableControlLedger(newTestControlLedger(t), true)
	if err != nil {
		t.Fatalf("package portable control ledger: %v", err)
	}
	body, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers/package/verify", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp VerifyPortableControlLedgerPackageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Valid || resp.Summary == nil || resp.Summary.TotalTrustCompliancePackages != 1 {
		t.Fatalf("expected valid verification response, got %+v", resp)
	}
	if resp.AnchorMatchCount != 0 || len(resp.AnchorMatches) != 0 {
		t.Fatalf("expected no anchor matches without a studio-backed audit server, got %+v", resp)
	}

	pkg.Ledger.Bundle.TrustCompliancePackages[0].PackageHash = "tampered"
	body, err = json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal tampered package: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers/package/verify", strings.NewReader(string(body)))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 for invalid verification response, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal invalid response: %v", err)
	}
	if resp.Valid || resp.Error == "" {
		t.Fatalf("expected invalid verification response, got %+v", resp)
	}
}

func TestAuditServer_GetControlLedgerPackageAnchors(t *testing.T) {
	recordAnchor := makeTestRecord(
		1,
		"genesis",
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityInfo,
		"control_ledger_package_anchored",
		"validator:ledger-abc123",
		210,
		"2026-04-14T11:00:00Z",
		map[string]string{
			"package_hash": "ledger-pkg-1",
			"ledger_id":    "ledger-001",
		},
	)
	recordTrust := makeTestRecord(
		2,
		recordAnchor.RecordHash,
		keeper.AuditCategoryGovernance,
		keeper.AuditSeverityInfo,
		"trust_compliance_export_anchored",
		"validator:trust-abc123",
		211,
		"2026-04-14T11:05:00Z",
		nil,
	)

	studio, err := NewStudio(Config{
		LogSource: &mockLogSource{records: []keeper.AuditRecord{
			recordAnchor,
			recordTrust,
		}},
	})
	if err != nil {
		t.Fatalf("new studio: %v", err)
	}

	server := NewAuditServer(studio, nil)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledger-packages/anchors?actor=validator:ledger-abc123", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp GetControlLedgerPackageAnchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 1 || len(resp.Records) != 1 || len(resp.Anchors) != 1 {
		t.Fatalf("expected exactly one anchored ledger-package record, got total=%d records=%d anchors=%d", resp.Total, len(resp.Records), len(resp.Anchors))
	}
	if resp.Records[0].Details["package_hash"] != "ledger-pkg-1" {
		t.Fatalf("expected package hash detail to survive, got %+v", resp.Records[0].Details)
	}
	if resp.Anchors[0].Summary == nil || resp.Anchors[0].Summary.PackageHash != "ledger-pkg-1" || resp.Anchors[0].Summary.LedgerID != "ledger-001" {
		t.Fatalf("expected normalized anchor summary, got %+v", resp.Anchors[0])
	}
}

func TestAuditServer_ExportControlLedgerInvalidFormat(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledger := newTestControlLedger(t)
	if err := server.StoreControlLedger(ledger); err != nil {
		t.Fatalf("store control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/"+ledger.Bundle.ID+"/export?format=xml", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestAuditServer_ListControlLedgers(t *testing.T) {
	server := NewAuditServer(nil, nil)
	ledgerA := newTestControlLedger(t)
	ledgerB := newTestControlLedger(t)
	ledgerB.Bundle.ID = "finance-control-ledger-b"

	if err := server.StoreControlLedger(ledgerA); err != nil {
		t.Fatalf("store first control ledger: %v", err)
	}
	if err := server.StoreControlLedger(ledgerB); err != nil {
		t.Fatalf("store second control ledger: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp ListControlLedgersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total != 2 || len(resp.Ledgers) != 2 {
		t.Fatalf("expected 2 ledgers, got total=%d len=%d", resp.Total, len(resp.Ledgers))
	}
}

func TestAuditServer_PostControlLedger(t *testing.T) {
	server := NewAuditServer(nil, nil)

	body, err := json.Marshal(PutControlLedgerRequest{Ledger: newTestControlLedger(t)})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var resp PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Bundle == nil {
		t.Fatal("expected persisted ledger in response")
	}
	if resp.Ledger.Bundle.ContentHash == "" {
		t.Fatal("expected stored ledger to be finalized")
	}
}

func TestAuditServer_PostControlLedgerInvalidPayload(t *testing.T) {
	server := NewAuditServer(nil, nil)

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(`{"ledger":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestAuditServer_PostControlLedgerRequiresBearerToken(t *testing.T) {
	server := NewAuditServer(nil, nil)
	authorizer, err := NewStaticBearerTokenAuthorizer("super-secret-token")
	if err != nil {
		t.Fatalf("new bearer-token authorizer: %v", err)
	}
	server.SetControlLedgerWriteAuthorizer(authorizer)

	body, err := json.Marshal(PutControlLedgerRequest{Ledger: newTestControlLedger(t)})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}

func TestAuditServer_PostControlLedgerAcceptsBearerToken(t *testing.T) {
	server := NewAuditServer(nil, nil)
	authorizer, err := NewStaticBearerTokenAuthorizer("super-secret-token")
	if err != nil {
		t.Fatalf("new bearer-token authorizer: %v", err)
	}
	server.SetControlLedgerWriteAuthorizer(authorizer)

	body, err := json.Marshal(PutControlLedgerRequest{Ledger: newTestControlLedger(t)})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}
}

func TestAuditServer_PostControlLedgerDisabled(t *testing.T) {
	server := NewAuditServer(nil, nil)
	server.SetControlLedgerWriteAuthorizer(NewDisabledWriteAuthorizer("writes disabled for this environment"))

	body, err := json.Marshal(PutControlLedgerRequest{Ledger: newTestControlLedger(t)})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}
}

func TestAuditServer_GetControlLedgerRejectsTraversalID(t *testing.T) {
	server, err := NewPersistentAuditServer(nil, nil, t.TempDir())
	if err != nil {
		t.Fatalf("new persistent audit server: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/..unsafe-ledger", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}
}

func TestAuditServer_GetControlLedgerCorruptStoreReturnsInternalError(t *testing.T) {
	dir := t.TempDir()
	server, err := NewPersistentAuditServer(nil, nil, dir)
	if err != nil {
		t.Fatalf("new persistent audit server: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "corrupt-ledger.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("write corrupt ledger file: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/control-ledgers/corrupt-ledger", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
}

func newTestControlLedger(t *testing.T) *evidence.ControlLedger {
	t.Helper()

	ledger := evidence.NewControlLedger("finance-control-ledger")
	ledger.WithMetadata("jurisdiction", "UAE")
	ledger.AddRecord(evidence.Record{
		ID:        "record-001",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     "did:aethelred:agent-001",
		Timestamp: "2026-04-14T10:00:00Z",
	})
	ledger.AddAgentPassport(evidence.AgentPassportEvidence{
		DID:              "did:aethelred:agent-001",
		Issuer:           "did:aethelred:issuer-001",
		PublicKeyHash:    "abcd",
		HumanOwner:       "alice.chen",
		JurisdictionTags: []string{"UAE"},
		AllowedTools:     []string{"payments.release"},
		IssuedAt:         "2026-04-14T10:00:00Z",
	})
	if err := ledger.AddApproverAttestation(evidence.ApproverAttestationEvidence{
		ID:                "approver-attestation:api-ledger-001",
		ApprovalRecordID:  "record-001",
		Approver:          "alice.chen",
		ApproverDID:       "did:aethelred:agent-001",
		PassportDID:       "did:aethelred:agent-001",
		PolicyReceiptID:   "receipt-001",
		PolicyReceiptHash: "hash-001",
		Action:            "payments.release.approve",
		Resource:          "acct:treasury-main",
		Decision:          "allow",
		TraceLinkID:       "link-001",
		SealID:            "seal-001",
		AuthorizedAt:      "2026-04-14T10:01:30Z",
		Comment:           "Approved by treasury controller",
		Metadata: map[string]string{
			"approval_stage": "final",
		},
	}); err != nil {
		t.Fatalf("adding approver attestation: %v", err)
	}
	ledger.AddPolicyReceipt(evidence.PolicyReceiptEvidence{
		ID:          "receipt-001",
		RequestID:   "req-001",
		Actor:       "did:aethelred:agent-001",
		Action:      "payments.release",
		Resource:    "acct:treasury-main",
		Decision:    "allow",
		AuditTrail:  "trace-001",
		Signer:      "did:aethelred:policy-gateway-1",
		ContentHash: "hash-001",
		EvaluatedAt: "2026-04-14T10:01:00Z",
	})
	if err := ledger.AddValueSettlement(evidence.ValueSettlementEvidence{
		ID:                "settlement:api-ledger-001",
		SettlementID:      "settlement-001",
		WorkflowID:        "workflow-001",
		Network:           "aethelred",
		Method:            "stablecoin",
		Counterparty:      "Acme Supplier",
		Beneficiary:       "Acme Supplier",
		FiatAmount:        5000,
		FiatCurrency:      "USD",
		TokenAmount:       5000,
		TokenDenomination: "USDC",
		ExchangeRate:      1,
		Status:            "settled",
		ReasonCode:        "payroll_release",
		Reference:         "treasury-release:workflow-001",
		TxHash:            "tx-001",
		PolicyReceiptID:   "receipt-001",
		PolicyReceiptHash: "hash-001",
		SealID:            "seal-001",
		SettledAt:         "2026-04-14T10:01:45Z",
		Metadata: map[string]string{
			"jurisdiction": "UAE",
		},
	}); err != nil {
		t.Fatalf("adding value settlement: %v", err)
	}
	ledger.AddSeal(evidence.Seal{
		SealID:         "seal-001",
		JobID:          "job-001",
		OutputHash:     "out-001",
		ValidatorCount: 4,
		BlockHeight:    123,
		Timestamp:      "2026-04-14T10:02:00Z",
	})
	ledger.AddTraceLink(evidence.TraceLink{
		ID:                "link-001",
		AgentDID:          "did:aethelred:agent-001",
		PolicyReceiptID:   "receipt-001",
		PolicyReceiptHash: "hash-001",
		SealID:            "seal-001",
		OutputHash:        "out-001",
		LinkedAt:          "2026-04-14T10:03:00Z",
		Description:       "Treasury approval trace chain",
	})
	if err := ledger.AddTrustCompliancePackage(evidence.TrustCompliancePackageEvidence{
		ID:            "trust-compliance-package:api-ledger-001",
		PackageHash:   evidence.EvidenceHashHex([]byte("api-ledger-package")),
		PayloadHash:   evidence.EvidenceHashHex([]byte("api-ledger-payload")),
		DocumentHash:  evidence.EvidenceHashHex([]byte("api-ledger-document")),
		Format:        "json",
		ExportVersion: "1.0.0",
		GeneratedAt:   "2026-04-14T10:04:00Z",
		Signed:        true,
		Signature: &evidence.TrustComplianceSignatureEvidence{
			Signer:    "validator:test-signer",
			KeyID:     "key-1",
			Algorithm: "ed25519",
			SignedAt:  "2026-04-14T10:04:01Z",
		},
		AuditAnchor: &evidence.TrustComplianceAuditAnchorEvidence{
			Sequence:    7,
			RecordHash:  evidence.EvidenceHashHex([]byte("api-ledger-anchor")),
			Action:      "trust_compliance_export_anchored",
			Actor:       "validator:test-signer",
			Timestamp:   "2026-04-14T10:04:05Z",
			BlockHeight: 123,
		},
	}); err != nil {
		t.Fatalf("adding trust compliance package: %v", err)
	}
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CTRL-001",
		ControlName: "Treasury Release Approval",
		Status:      evidence.ControlSatisfied,
		Description: "Release requires policy and execution proof.",
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs:                 []string{"record-001"},
			ApproverAttestationIDs:    []string{"approver-attestation:api-ledger-001"},
			ValueSettlementIDs:        []string{"settlement:api-ledger-001"},
			PolicyReceiptIDs:          []string{"receipt-001"},
			SealIDs:                   []string{"seal-001"},
			TraceLinkIDs:              []string{"link-001"},
			TrustCompliancePackageIDs: []string{"trust-compliance-package:api-ledger-001"},
		},
	}); err != nil {
		t.Fatalf("adding control: %v", err)
	}

	return ledger
}

func newTestAuditServerWithStudio(t *testing.T) (*AuditServer, *Studio) {
	t.Helper()

	logSource := &mockLogSource{}
	studio, err := NewStudio(Config{LogSource: logSource})
	if err != nil {
		t.Fatalf("new studio: %v", err)
	}
	return NewAuditServer(studio, nil), studio
}

func newTestEnterpriseTrustRegistry() *EnterpriseControlLedgerTrustRegistry {
	return &EnterpriseControlLedgerTrustRegistry{
		Version:              "2026.04.14",
		Source:               "runtime_registry",
		UpdatedAt:            "2026-04-14T10:30:00Z",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []EnterprisePolicySignerTrustEntry{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  "021f0cc2ad3d8a3ab1c5b64c5a1cc6dd8f10d26b984d4e2b573b6629f5bff1f5df",
			Status:        TrustRegistryEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		AllowedSponsors: []EnterpriseSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        TrustRegistryEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
	}
}

type testEnterpriseTrustRegistryService struct {
	registry   *EnterpriseControlLedgerTrustRegistry
	lastActor  string
	lastReason string
}

func newTestEnterpriseTrustRegistryService(registry *EnterpriseControlLedgerTrustRegistry) *testEnterpriseTrustRegistryService {
	return &testEnterpriseTrustRegistryService{registry: cloneTestEnterpriseTrustRegistry(registry)}
}

func (s *testEnterpriseTrustRegistryService) GetEnterpriseTrustRegistry(_ context.Context, _ *GetEnterpriseTrustRegistryRequest) (*GetEnterpriseTrustRegistryResponse, error) {
	if s.registry == nil {
		return nil, ErrTrustRegistryNotConfigured
	}
	return &GetEnterpriseTrustRegistryResponse{Registry: cloneTestEnterpriseTrustRegistry(s.registry)}, nil
}

func (s *testEnterpriseTrustRegistryService) GetEnterpriseTrustRegistryStatus(_ context.Context, _ *GetEnterpriseTrustRegistryStatusRequest) (*GetEnterpriseTrustRegistryStatusResponse, error) {
	status := &EnterpriseControlLedgerTrustRegistryStatus{}
	if s.registry != nil {
		status.Configured = true
		status.Version = s.registry.Version
		status.Source = s.registry.Source
		status.UpdatedAt = s.registry.UpdatedAt
		status.RequiredAction = s.registry.RequiredAction
		status.RequiredJurisdiction = s.registry.RequiredJurisdiction
		status.PolicySignerCount = len(s.registry.PolicySigners)
		status.ActivePolicySignerCount = len(s.registry.PolicySigners)
		status.AllowedSponsorCount = len(s.registry.AllowedSponsors)
		status.ActiveSponsorCount = len(s.registry.AllowedSponsors)
	}
	return &GetEnterpriseTrustRegistryStatusResponse{Status: status}, nil
}

func (s *testEnterpriseTrustRegistryService) PutEnterpriseTrustRegistry(_ context.Context, req *PutEnterpriseTrustRegistryRequest) (*PutEnterpriseTrustRegistryResponse, error) {
	if req == nil || req.Registry == nil {
		return nil, ErrInvalidInput
	}
	s.registry = cloneTestEnterpriseTrustRegistry(req.Registry)
	s.lastActor = req.Actor
	s.lastReason = req.Reason
	status, _ := s.GetEnterpriseTrustRegistryStatus(context.Background(), &GetEnterpriseTrustRegistryStatusRequest{})
	return &PutEnterpriseTrustRegistryResponse{
		Registry: cloneTestEnterpriseTrustRegistry(s.registry),
		Status:   status.Status,
	}, nil
}

func (s *testEnterpriseTrustRegistryService) DeleteEnterpriseTrustRegistry(_ context.Context, req *DeleteEnterpriseTrustRegistryRequest) (*DeleteEnterpriseTrustRegistryResponse, error) {
	if req != nil {
		s.lastActor = req.Actor
		s.lastReason = req.Reason
	}
	cleared := s.registry != nil
	s.registry = nil
	return &DeleteEnterpriseTrustRegistryResponse{
		Cleared: cleared,
		Status:  &EnterpriseControlLedgerTrustRegistryStatus{},
	}, nil
}

func cloneTestEnterpriseTrustRegistry(registry *EnterpriseControlLedgerTrustRegistry) *EnterpriseControlLedgerTrustRegistry {
	if registry == nil {
		return nil
	}
	out := &EnterpriseControlLedgerTrustRegistry{
		Version:              registry.Version,
		Source:               registry.Source,
		UpdatedAt:            registry.UpdatedAt,
		RequiredAction:       registry.RequiredAction,
		RequiredJurisdiction: registry.RequiredJurisdiction,
		PolicySigners:        append([]EnterprisePolicySignerTrustEntry(nil), registry.PolicySigners...),
		AllowedSponsors:      append([]EnterpriseSponsorTrustEntry(nil), registry.AllowedSponsors...),
	}
	return out
}
