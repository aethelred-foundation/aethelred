package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"

	audithttp "github.com/aethelred/aethelred/pkg/audit"
	auditexport "github.com/aethelred/aethelred/pkg/audit/export"
	"github.com/aethelred/aethelred/pkg/evidence"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestPouwModuleStatusHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwModuleStatusHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/module-status", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwModuleStatusHandler_Get(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/module-status", nil)
	rec := httptest.NewRecorder()

	app.PouwModuleStatusHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var status struct {
		JobCount                          uint64 `json:"job_count"`
		PendingJobCount                   int    `json:"pending_job_count"`
		CurrentEpoch                      uint64 `json:"current_epoch"`
		TotalUWU                          uint64 `json:"total_uwu"`
		EnterpriseTrustRegistryConfigured bool   `json:"enterprise_trust_registry_configured"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if status.JobCount != 0 || status.PendingJobCount != 0 {
		t.Fatalf("expected empty pouw status on fresh app, got %+v", status)
	}
	if status.EnterpriseTrustRegistryConfigured {
		t.Fatalf("expected trust registry to be unconfigured on fresh app, got %+v", status)
	}
}

func TestPouwTrustRegistryHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwTrustRegistryHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/trust-registry", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwTrustRegistryHandler_Get(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	ctx := app.NewContext(true).WithBlockHeight(321).WithBlockTime(time.Date(2026, 4, 14, 12, 0, 0, 0, time.UTC))
	err := app.PouwKeeper.SetEnterpriseAuditTrustRegistry(ctx, &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		Source:               "pouw_governance",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:           "did:aethelred:policy-gateway-1",
			PublicKeyHex:  "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:        pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		AllowedSponsors: []pouwkeeper.EnterpriseAuditSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
	})
	if err != nil {
		t.Fatalf("set enterprise audit trust registry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry", nil)
	rec := httptest.NewRecorder()
	app.PouwTrustRegistryHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp struct {
		Configured bool                                           `json:"configured"`
		Status     *pouwkeeper.EnterpriseAuditTrustRegistryStatus `json:"status"`
		Registry   *pouwkeeper.EnterpriseAuditTrustRegistry       `json:"registry"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Configured || resp.Status == nil || resp.Registry == nil {
		t.Fatalf("expected configured trust registry response, got %+v", resp)
	}
	if resp.Status.ActivePolicySignerCount != 1 || resp.Status.ActiveSponsorCount != 1 {
		t.Fatalf("unexpected trust registry status counts: %+v", resp.Status)
	}
	if resp.Registry.Source != "pouw_governance" || len(resp.Registry.PolicySigners) != 1 {
		t.Fatalf("unexpected trust registry payload: %+v", resp.Registry)
	}
}

func TestPouwTrustRegistryHistoryHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwTrustRegistryHistoryHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/trust-registry/history", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwTrustRegistryHistoryHandler_Get(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	authority := app.PouwKeeper.GetAuthority()
	ctx := app.NewContext(true).WithBlockHeight(400).WithBlockTime(time.Date(2026, 4, 14, 13, 0, 0, 0, time.UTC))

	_, err := app.PouwKeeper.SetEnterpriseAuditTrustRegistryByAuthority(ctx, authority, &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:          "did:aethelred:policy-gateway-1",
			PublicKeyHex: "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
	}, "activate trust registry", "did:aethelred:ops-admin")
	if err != nil {
		t.Fatalf("set governed trust registry: %v", err)
	}
	_, err = app.PouwKeeper.ClearEnterpriseAuditTrustRegistryByAuthority(ctx, authority, "containment drill", "did:aethelred:ops-admin")
	if err != nil {
		t.Fatalf("clear governed trust registry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/history?actor="+authority+"&limit=10", nil)
	rec := httptest.NewRecorder()
	app.PouwTrustRegistryHistoryHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp audithttp.GetEnterpriseTrustRegistryHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Total < 2 || len(resp.Records) < 2 {
		t.Fatalf("expected at least two trust-registry history records, got %+v", resp)
	}
	actions := []string{resp.Records[0].Action, resp.Records[1].Action}
	joined := strings.Join(actions, ",")
	if !strings.Contains(joined, "enterprise_audit_trust_registry_updated") || !strings.Contains(joined, "enterprise_audit_trust_registry_cleared") {
		t.Fatalf("unexpected trust-registry history actions: %v", actions)
	}
}

func TestPouwControlLedgerPackageAnchorsHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwControlLedgerPackageAnchorsHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/control-ledger-packages/anchors", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwControlLedgerPackageAnchorsHandler_Get(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	ctx := app.NewContext(true).WithBlockHeight(441).WithBlockTime(time.Date(2026, 4, 14, 13, 35, 0, 0, time.UTC))
	record := app.PouwKeeper.AuditLogger().AuditControlLedgerPackage(ctx, "validator:abc123", map[string]string{
		"package_hash":                    "ledger-pkg-1",
		"ledger_id":                       "runtime-ledger-1",
		"format_version":                  "1.0.0",
		"packaged_at":                     "2026-04-14T13:35:00Z",
		"framework":                       "aethelred-runtime",
		"bundle_content_hash":             "bundle-hash-1",
		"controls_total":                  "4",
		"trust_compliance_packages_total": "1",
		"verification_key_count":          "1",
		"trust_anchor_count":              "0",
		"signed":                          "true",
		"signer":                          "validator:abc123",
		"signature_key_id":                "key-1",
		"signature_algorithm":             "ed25519",
		"signed_at":                       "2026-04-14T13:35:01Z",
	})
	if record == nil {
		t.Fatal("expected anchored control ledger package audit record")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/control-ledger-packages/anchors?ledger_id=runtime-ledger-1&signed=true&package_hash=ledger-pkg-1", nil)
	rec := httptest.NewRecorder()
	app.PouwControlLedgerPackageAnchorsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp audithttp.GetControlLedgerPackageAnchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal anchor response: %v", err)
	}
	if resp.Total != 1 || len(resp.Anchors) != 1 {
		t.Fatalf("expected one anchored package, got %+v", resp)
	}
	if resp.Anchors[0].Summary == nil || resp.Anchors[0].Summary.PackageHash != "ledger-pkg-1" {
		t.Fatalf("expected normalized package anchor summary, got %+v", resp.Anchors[0])
	}
	if resp.Anchors[0].Summary.LedgerID != "runtime-ledger-1" || !resp.Anchors[0].Summary.Signed {
		t.Fatalf("unexpected anchor summary %+v", resp.Anchors[0].Summary)
	}
}

func TestPouwTrustComplianceExportAnchorsHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwTrustComplianceExportAnchorsHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/trust-registry/compliance-export/anchors", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwTrustComplianceExportAnchorsHandler_Get(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	ctx := app.NewContext(true).WithBlockHeight(440).WithBlockTime(time.Date(2026, 4, 14, 13, 30, 0, 0, time.UTC))
	record := app.PouwKeeper.AuditLogger().AuditTrustComplianceExport(ctx, "validator:abc123", map[string]string{
		"package_hash":    "pkg-anchor-1",
		"payload_hash":    "payload-anchor-1",
		"document_hash":   "document-anchor-1",
		"format":          "oscal",
		"export_version":  "1.0.0",
		"generated_at":    "2026-04-14T13:30:00Z",
		"history_count":   "3",
		"signed":          "true",
		"signer":          "validator:abc123",
		"custody_entries": "2",
	})
	if record == nil {
		t.Fatal("expected anchored export audit record")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/compliance-export/anchors?format=oscal&signed=true&package_hash=pkg-anchor-1", nil)
	rec := httptest.NewRecorder()
	app.PouwTrustComplianceExportAnchorsHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp auditexport.PouwTrustComplianceExportAnchorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal anchor response: %v", err)
	}
	if resp.Total != 1 || len(resp.Anchors) != 1 {
		t.Fatalf("expected one anchored export, got %+v", resp)
	}
	if resp.Anchors[0].Summary == nil || resp.Anchors[0].Summary.PackageHash != "pkg-anchor-1" {
		t.Fatalf("expected normalized anchor summary, got %+v", resp.Anchors[0])
	}
	if !resp.Anchors[0].Summary.Signed || resp.Anchors[0].Summary.Format != "oscal" {
		t.Fatalf("unexpected anchor summary %+v", resp.Anchors[0].Summary)
	}
}

func TestPouwTrustComplianceExportHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwTrustComplianceExportHandler()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/trust-registry/compliance-export", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwTrustComplianceExportHandler_JSON(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	authority := app.PouwKeeper.GetAuthority()
	ctx := app.NewContext(true).WithBlockHeight(450).WithBlockTime(time.Date(2026, 4, 14, 14, 0, 0, 0, time.UTC))

	_, err := app.PouwKeeper.SetEnterpriseAuditTrustRegistryByAuthority(ctx, authority, &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:          "did:aethelred:policy-gateway-1",
			PublicKeyHex: "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
		AllowedSponsors: []pouwkeeper.EnterpriseAuditSponsorTrustEntry{{
			DID:    "did:aethelred:sponsor-bank",
			Status: pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
	}, "activate trust registry", "did:aethelred:ops-admin")
	if err != nil {
		t.Fatalf("set governed trust registry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/compliance-export?format=json&actor="+authority, nil)
	rec := httptest.NewRecorder()
	app.PouwTrustComplianceExportHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp auditexport.PouwTrustComplianceExport
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal compliance export: %v", err)
	}
	if resp.GeneratedAt == "" || resp.ExportVersion == "" || resp.ModuleStatus == nil || resp.TrustRegistryStatus == nil || resp.TrustRegistry == nil {
		t.Fatalf("expected populated compliance export, got %+v", resp)
	}
	if !resp.TrustRegistryStatus.Configured || resp.TrustRegistryStatus.Source != "pouw_governance" {
		t.Fatalf("unexpected trust registry status: %+v", resp.TrustRegistryStatus)
	}
	if resp.HistorySummary == nil || resp.HistorySummary.TotalRecords < 1 || resp.HistorySummary.LatestAction == "" || len(resp.History) < 1 {
		t.Fatalf("expected history in compliance export, got %+v", resp)
	}
	if resp.ComplianceSummary == nil || resp.ComplianceSummary.TotalControls == 0 || resp.ComplianceSummary.CoveragePct == 0 {
		t.Fatalf("expected compliance summary in export, got %+v", resp.ComplianceSummary)
	}
	if resp.ComplianceReport == nil || len(resp.ComplianceReport.Controls) == 0 {
		t.Fatalf("expected compliance report controls in export, got %+v", resp.ComplianceReport)
	}
}

func TestPouwTrustComplianceExportHandler_CSV(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	authority := app.PouwKeeper.GetAuthority()
	ctx := app.NewContext(true).WithBlockHeight(451).WithBlockTime(time.Date(2026, 4, 14, 14, 5, 0, 0, time.UTC))

	_, err := app.PouwKeeper.SetEnterpriseAuditTrustRegistryByAuthority(ctx, authority, &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:          "did:aethelred:policy-gateway-1",
			PublicKeyHex: "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
	}, "activate trust registry", "did:aethelred:ops-admin")
	if err != nil {
		t.Fatalf("set governed trust registry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/compliance-export?format=csv", nil)
	rec := httptest.NewRecorder()
	app.PouwTrustComplianceExportHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "text/csv") {
		t.Fatalf("expected csv content type, got %q", contentType)
	}

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(rows) < 3 {
		t.Fatalf("expected multiple csv rows, got %v", rows)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "summary") || !strings.Contains(body, "history_summary") || !strings.Contains(body, "history_record") {
		t.Fatalf("expected compliance csv row types, got %q", body)
	}
	if !strings.Contains(body, "compliance_summary") || !strings.Contains(body, "regulation_summary") || !strings.Contains(body, "compliance_control") {
		t.Fatalf("expected compliance coverage csv rows, got %q", body)
	}
}

func TestPouwTrustComplianceExportHandler_OSCAL(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	authority := app.PouwKeeper.GetAuthority()
	ctx := app.NewContext(true).WithBlockHeight(452).WithBlockTime(time.Date(2026, 4, 14, 14, 10, 0, 0, time.UTC))

	_, err := app.PouwKeeper.SetEnterpriseAuditTrustRegistryByAuthority(ctx, authority, &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:          "did:aethelred:policy-gateway-1",
			PublicKeyHex: "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
	}, "activate trust registry", "did:aethelred:ops-admin")
	if err != nil {
		t.Fatalf("set governed trust registry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/compliance-export?format=oscal", nil)
	rec := httptest.NewRecorder()
	app.PouwTrustComplianceExportHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected json content type for oscal export, got %q", contentType)
	}

	var payload auditexport.OSCALAssessmentResult
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal oscal payload: %v", err)
	}
	if payload.AssessmentResults.Metadata.Title == "" || len(payload.AssessmentResults.Results) != 1 {
		t.Fatalf("unexpected oscal payload: %+v", payload)
	}
	if !strings.Contains(payload.AssessmentResults.Metadata.Title, "PoUW Trust Compliance") {
		t.Fatalf("unexpected oscal title %q", payload.AssessmentResults.Metadata.Title)
	}
	if len(payload.AssessmentResults.Results[0].Findings) == 0 {
		t.Fatalf("expected compliance findings in oscal payload, got %+v", payload.AssessmentResults.Results[0])
	}
}

func TestPouwTrustComplianceExportHandler_PackageSigned(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatalf("set validator private key: %v", err)
	}

	authority := app.PouwKeeper.GetAuthority()
	ctx := app.NewContext(true).WithBlockHeight(453).WithBlockTime(time.Date(2026, 4, 14, 14, 15, 0, 0, time.UTC))
	_, err := app.PouwKeeper.SetEnterpriseAuditTrustRegistryByAuthority(ctx, authority, &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              "2026.04.14",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:          "did:aethelred:policy-gateway-1",
			PublicKeyHex: "025f3c7a3bb5d7584ff6d09b13d616f6c9778f4d3146ef4740db9f9c0fdb8724e3",
			Status:       pouwkeeper.EnterpriseAuditTrustEntryStatusActive,
		}},
	}, "activate trust registry", "did:aethelred:ops-admin")
	if err != nil {
		t.Fatalf("set governed trust registry: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/compliance-export?format=oscal&package=true", nil)
	rec := httptest.NewRecorder()
	app.PouwTrustComplianceExportHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.Contains(contentType, "application/json") {
		t.Fatalf("expected json content type, got %q", contentType)
	}

	var pkg auditexport.PouwTrustCompliancePackage
	if err := json.Unmarshal(rec.Body.Bytes(), &pkg); err != nil {
		t.Fatalf("unmarshal package payload: %v", err)
	}
	if pkg.Signature == nil {
		t.Fatalf("expected signed compliance package, got %+v", pkg)
	}
	if pkg.Manifest.Format != "oscal" || pkg.Manifest.PackageHash == "" {
		t.Fatalf("unexpected package manifest %+v", pkg.Manifest)
	}
	if len(pkg.ChainOfCustody) < 2 {
		t.Fatalf("expected chain of custody in package, got %+v", pkg.ChainOfCustody)
	}
	if pkg.AuditAnchor == nil || pkg.AuditAnchor.Action != "trust_compliance_export_anchored" {
		t.Fatalf("expected audit anchor in package, got %+v", pkg.AuditAnchor)
	}
	if pkg.AuditAnchor.Details["package_hash"] != pkg.Manifest.PackageHash {
		t.Fatalf("expected audit anchor package hash to match manifest, got %+v", pkg.AuditAnchor.Details)
	}
	if err := auditexport.VerifyPouwTrustCompliancePackage(&pkg); err != nil {
		t.Fatalf("VerifyPouwTrustCompliancePackage returned error: %v", err)
	}
	records := app.PouwKeeper.AuditLogger().GetRecords()
	found := false
	for _, record := range records {
		if record.Action == "trust_compliance_export_anchored" && record.Details["package_hash"] == pkg.Manifest.PackageHash {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected package hash to be anchored in keeper audit history, records=%+v", records)
	}
}

func TestPouwTrustCompliancePackageVerifyHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwTrustCompliancePackageVerifyHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/trust-registry/compliance-export/verify", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwPortableControlLedgerPackageVerifyHandler_MethodNotAllowed(t *testing.T) {
	handler := (&AethelredApp{}).PouwPortableControlLedgerPackageVerifyHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pouw/control-ledger-packages/verify", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestPouwPortableControlLedgerPackageVerifyHandler_VerifiedAndAnchored(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":              "simulated",
		"aethelred.audit.api.write_token": "audit-write-token",
		flags.FlagHome:                    t.TempDir(),
	})

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatalf("set validator private key: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(mustMarshalControlLedger(t)))
	req.Header.Set("Authorization", "Bearer audit-write-token")
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var writeResp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &writeResp); err != nil {
		t.Fatalf("unmarshal write response: %v", err)
	}
	if writeResp.Ledger == nil || writeResp.Ledger.Bundle == nil {
		t.Fatal("expected persisted control ledger")
	}

	req = httptest.NewRequest(
		http.MethodGet,
		"/api/v1/audit/control-ledgers/"+writeResp.Ledger.Bundle.ID+"/package?include_verification_keys=true&sign=true&anchor=true",
		nil,
	)
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var pkg evidence.PortableControlLedgerPackage
	if err := json.Unmarshal(rec.Body.Bytes(), &pkg); err != nil {
		t.Fatalf("unmarshal package response: %v", err)
	}
	body, err := pkg.Marshal()
	if err != nil {
		t.Fatalf("marshal portable control ledger package: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/pouw/control-ledger-packages/verify", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	app.PouwPortableControlLedgerPackageVerifyHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp audithttp.VerifyPortableControlLedgerPackageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal verify response: %v", err)
	}
	if !resp.Valid || resp.PackageHash != pkg.PackageHash {
		t.Fatalf("expected valid portable package verification, got %+v", resp)
	}
	if resp.AnchorMatchCount != 1 || len(resp.AnchorMatches) != 1 {
		t.Fatalf("expected one anchor match, got %+v", resp)
	}
	if resp.AnchorMatches[0].Summary == nil || resp.AnchorMatches[0].Summary.PackageHash != pkg.PackageHash {
		t.Fatalf("expected matching anchor summary, got %+v", resp.AnchorMatches[0])
	}
}

func TestPouwTrustCompliancePackageVerifyHandler_VerifiedAndAnchored(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	doc := auditexport.BuildPouwTrustComplianceExport(
		"2026-04-14T15:00:00Z",
		&pouwkeeper.QueryModuleStatusResponse{BlockHeight: 500, CurrentEpoch: 9, TotalUWU: 42},
		&pouwkeeper.EnterpriseAuditTrustRegistryStatus{Configured: true, Version: "2026.04.14", Source: "pouw_governance"},
		nil,
		nil,
		nil,
	)
	payload, err := auditexport.ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("export json: %v", err)
	}
	pkg, err := auditexport.CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("create package: %v", err)
	}

	ctx := app.NewContext(true).WithBlockHeight(500).WithBlockTime(time.Date(2026, 4, 14, 15, 0, 0, 0, time.UTC))
	record := app.PouwKeeper.AuditLogger().AuditTrustComplianceExport(ctx, "validator:abc123", map[string]string{
		"package_hash":    pkg.Manifest.PackageHash,
		"payload_hash":    pkg.Manifest.PayloadHash,
		"document_hash":   pkg.Manifest.DocumentHash,
		"format":          pkg.Manifest.Format,
		"export_version":  pkg.Manifest.ExportVersion,
		"generated_at":    pkg.Manifest.GeneratedAt,
		"history_count":   "0",
		"signed":          "false",
		"custody_entries": "2",
	})
	if record == nil {
		t.Fatal("expected anchored export audit record")
	}
	pkg.AuditAnchor = record

	body, err := pkg.Marshal()
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/trust-registry/compliance-export/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.PouwTrustCompliancePackageVerifyHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp auditexport.PouwTrustCompliancePackageVerificationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal verify response: %v", err)
	}
	if resp.Verification == nil || !resp.Verification.Valid {
		t.Fatalf("expected valid verification response, got %+v", resp.Verification)
	}
	if resp.AnchorMatchCount != 1 || len(resp.AnchorMatches) != 1 {
		t.Fatalf("expected one anchor match, got %+v", resp)
	}
	if resp.AnchorMatches[0].Summary == nil || resp.AnchorMatches[0].Summary.PackageHash != pkg.Manifest.PackageHash {
		t.Fatalf("expected matching package hash in anchor summary, got %+v", resp.AnchorMatches[0])
	}
}

func TestPouwTrustCompliancePackageVerifyHandler_TamperedPackage(t *testing.T) {
	homeDir := t.TempDir()
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	doc := auditexport.BuildPouwTrustComplianceExport(
		"2026-04-14T15:05:00Z",
		&pouwkeeper.QueryModuleStatusResponse{BlockHeight: 501},
		nil,
		nil,
		nil,
		nil,
	)
	payload, err := auditexport.ExportPouwTrustComplianceJSON(doc)
	if err != nil {
		t.Fatalf("export json: %v", err)
	}
	pkg, err := auditexport.CreatePouwTrustCompliancePackage(doc, "json", payload)
	if err != nil {
		t.Fatalf("create package: %v", err)
	}
	pkg.Manifest.PayloadHash = "tampered"

	body, err := pkg.Marshal()
	if err != nil {
		t.Fatalf("marshal package: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pouw/trust-registry/compliance-export/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.PouwTrustCompliancePackageVerifyHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp auditexport.PouwTrustCompliancePackageVerificationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal verify response: %v", err)
	}
	if resp.Verification == nil || resp.Verification.Valid {
		t.Fatalf("expected invalid verification response, got %+v", resp.Verification)
	}
	if len(resp.Verification.Errors) == 0 {
		t.Fatalf("expected verification errors, got %+v", resp.Verification)
	}
}
