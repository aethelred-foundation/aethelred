package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cosmossdk.io/log"
	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/testutil/sims"
	sdk "github.com/cosmos/cosmos-sdk/types"

	audithttp "github.com/aethelred/aethelred/pkg/audit"
	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	pouwkeeper "github.com/aethelred/aethelred/x/pouw/keeper"
)

func TestNewApp_AuditWritesDisabledByDefault(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       t.TempDir(),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(mustMarshalControlLedger(t)))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}
}

func TestNewApp_AuditWritesRequireConfiguredBearerToken(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":              "simulated",
		"aethelred.audit.api.write_token": "audit-write-token",
		flags.FlagHome:                    t.TempDir(),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(mustMarshalControlLedger(t)))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(mustMarshalControlLedger(t)))
	req.Header.Set("Authorization", "Bearer audit-write-token")
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var resp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Bundle == nil || resp.Ledger.Bundle.ContentHash == "" {
		t.Fatal("expected finalized persisted control ledger in response")
	}
}

func TestNewApp_AuditWritesAcceptEnterprisePolicyReceipt(t *testing.T) {
	payload, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger")
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                   "simulated",
		"aethelred.audit.api.enterprise_policy_signers":        signerConfig,
		"aethelred.audit.api.enterprise_allowed_sponsors":      "did:aethelred:sponsor-bank",
		"aethelred.audit.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var resp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Metadata["auth.mode"] != "enterprise_policy_receipt" {
		t.Fatal("expected enterprise authorization metadata in persisted ledger")
	}
	if resp.Ledger.Metadata["auth.sponsor_of_record"] != "did:aethelred:sponsor-bank" {
		t.Fatalf("expected sponsor_of_record metadata, got %q", resp.Ledger.Metadata["auth.sponsor_of_record"])
	}
}

func TestNewApp_PortableControlLedgerPackageSignedAndAnchored(t *testing.T) {
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
	if pkg.Signature == nil || pkg.AuditAnchor == nil {
		t.Fatalf("expected signed and anchored portable control ledger package, got %+v", pkg)
	}
	if err := evidence.VerifyPortableControlLedgerPackage(&pkg); err != nil {
		t.Fatalf("verify portable control ledger package: %v", err)
	}

	records := app.PouwKeeper.AuditLogger().GetRecordsByCategory(pouwkeeper.AuditCategoryGovernance)
	found := false
	for _, record := range records {
		if record.Action == "control_ledger_package_anchored" && record.Details["package_hash"] == pkg.PackageHash {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected portable package hash to be anchored in keeper audit history, records=%+v", records)
	}
}

func TestNewApp_AuditWritesAcceptEnterprisePolicyReceiptFromTrustRegistry(t *testing.T) {
	homeDir := t.TempDir()
	payload, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger-registry")
	registryPath := filepath.Join(homeDir, "config", "audit-enterprise-trust.json")
	if err := os.MkdirAll(filepath.Dir(registryPath), 0o755); err != nil {
		t.Fatalf("mkdir registry dir: %v", err)
	}
	if err := os.WriteFile(registryPath, mustMarshalEnterpriseTrustRegistry(t, signerConfig), 0o600); err != nil {
		t.Fatalf("write trust registry: %v", err)
	}

	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var resp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Metadata["auth.trust_source"] != "pouw_governance" {
		t.Fatalf("expected registry-backed trust source metadata, got %+v", resp.Ledger)
	}
	if resp.Ledger.Metadata["auth.trust_provider"] != "pouw_keeper" {
		t.Fatalf("expected startup bootstrap to promote trust into keeper-backed provider, got %q", resp.Ledger.Metadata["auth.trust_provider"])
	}
	if resp.Ledger.Metadata["auth.trust_registry_version"] != "2026.04.14" {
		t.Fatalf("expected registry version metadata, got %q", resp.Ledger.Metadata["auth.trust_registry_version"])
	}
}

func TestNewApp_BootstrapsFileTrustRegistryViaGovernanceOnStartup(t *testing.T) {
	homeDir := t.TempDir()
	_, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger-startup-bootstrap")
	registryPath := filepath.Join(homeDir, "config", "audit-enterprise-trust.json")
	if err := os.MkdirAll(filepath.Dir(registryPath), 0o755); err != nil {
		t.Fatalf("mkdir registry dir: %v", err)
	}
	if err := os.WriteFile(registryPath, mustMarshalEnterpriseTrustRegistry(t, signerConfig), 0o600); err != nil {
		t.Fatalf("write trust registry: %v", err)
	}

	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	})

	registry, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistry(app.NewContext(true))
	if err != nil {
		t.Fatalf("expected keeper trust registry after startup bootstrap, got error: %v", err)
	}
	if registry.Source != "pouw_governance" {
		t.Fatalf("expected startup bootstrap to persist through governance, got source %q", registry.Source)
	}
	if registry.Metadata["bootstrap_mode"] != "startup_file" {
		t.Fatalf("expected startup bootstrap metadata, got %+v", registry.Metadata)
	}
	if registry.Metadata["bootstrap_declared_source"] != "runtime_registry" {
		t.Fatalf("expected declared bootstrap source metadata, got %+v", registry.Metadata)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry/history", nil)
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on trust-registry history, got %d", rec.Code)
	}

	var historyResp audithttp.GetEnterpriseTrustRegistryHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &historyResp); err != nil {
		t.Fatalf("unmarshal trust-registry history response: %v", err)
	}
	if historyResp.Total < 1 || len(historyResp.Records) < 1 {
		t.Fatalf("expected at least one bootstrap governance history record, got %+v", historyResp)
	}
	lastRecord := historyResp.Records[len(historyResp.Records)-1]
	if lastRecord.Action != "enterprise_audit_trust_registry_updated" {
		t.Fatalf("expected startup bootstrap governance update record, got %q", lastRecord.Action)
	}
	if lastRecord.Details["requested_by"] != "audit_startup_bootstrap" {
		t.Fatalf("expected startup bootstrap requested_by detail, got %+v", lastRecord.Details)
	}
}

func TestNewApp_PromotesFileTrustRegistryIntoKeeperOnFirstEnterpriseWrite(t *testing.T) {
	homeDir := t.TempDir()
	payload, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger-bootstrap-only")
	registryPath := filepath.Join(homeDir, "config", "audit-enterprise-trust.json")
	if err := os.MkdirAll(filepath.Dir(registryPath), 0o755); err != nil {
		t.Fatalf("mkdir registry dir: %v", err)
	}
	if err := os.WriteFile(registryPath, mustMarshalEnterpriseTrustRegistry(t, signerConfig), 0o600); err != nil {
		t.Fatalf("write trust registry: %v", err)
	}

	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	registry, err := app.PouwKeeper.GetEnterpriseAuditTrustRegistry(app.NewContext(true))
	if err != nil {
		t.Fatalf("expected keeper trust registry to be promoted after first enterprise write, got error: %v", err)
	}
	if registry.Version != "2026.04.14" {
		t.Fatalf("expected bootstrapped registry version 2026.04.14, got %q", registry.Version)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry/status", nil)
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp audithttp.GetEnterpriseTrustRegistryStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Status == nil || !resp.Status.Configured {
		t.Fatalf("expected configured trust-registry status, got %+v", resp.Status)
	}
}

func TestNewApp_AuditWritesAcceptEnterprisePolicyReceiptFromKeeperTrust(t *testing.T) {
	payload, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger-keeper")
	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       t.TempDir(),
	}
	app := newAuditEnabledTestApp(t, opts)

	ctx := app.NewContext(true).WithBlockHeight(200).WithBlockTime(time.Date(2026, 4, 14, 11, 0, 0, 0, time.UTC))
	requireNoError(t, app.PouwKeeper.SetEnterpriseAuditTrustRegistry(ctx, mustEnterpriseAuditTrustRegistryFromSignerConfig(t, signerConfig, "pouw_keeper", "2026.04.15")))

	authorizer, _, _ := resolveAuditControlLedgerWriteAuthorizer(app, opts)
	app.auditServer.SetControlLedgerWriteAuthorizer(authorizer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var resp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Metadata["auth.trust_source"] != "pouw_keeper" {
		t.Fatalf("expected keeper-backed trust source metadata, got %+v", resp.Ledger)
	}
	if resp.Ledger.Metadata["auth.trust_registry_version"] != "2026.04.15" {
		t.Fatalf("expected keeper-backed registry version metadata, got %q", resp.Ledger.Metadata["auth.trust_registry_version"])
	}
}

func TestNewApp_AuditWritesPreferKeeperTrustOverFileRegistry(t *testing.T) {
	homeDir := t.TempDir()
	payload, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger-keeper-override")
	registryPath := filepath.Join(homeDir, "config", "audit-enterprise-trust.json")
	if err := os.MkdirAll(filepath.Dir(registryPath), 0o755); err != nil {
		t.Fatalf("mkdir registry dir: %v", err)
	}
	if err := os.WriteFile(registryPath, mustMarshalEnterpriseTrustRegistry(t, signerConfig), 0o600); err != nil {
		t.Fatalf("write trust registry: %v", err)
	}

	opts := sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	}
	app := newAuditEnabledTestApp(t, opts)

	ctx := app.NewContext(true).WithBlockHeight(201).WithBlockTime(time.Date(2026, 4, 14, 11, 5, 0, 0, time.UTC))
	requireNoError(t, app.PouwKeeper.SetEnterpriseAuditTrustRegistry(ctx, mustEnterpriseAuditTrustRegistryFromSignerConfig(t, signerConfig, "pouw_keeper", "2026.04.16")))

	authorizer, _, _ := resolveAuditControlLedgerWriteAuthorizer(app, opts)
	app.auditServer.SetControlLedgerWriteAuthorizer(authorizer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", rec.Code)
	}

	var resp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Ledger == nil || resp.Ledger.Metadata["auth.trust_source"] != "pouw_keeper" {
		t.Fatalf("expected keeper trust to override file registry, got %+v", resp.Ledger)
	}
	if resp.Ledger.Metadata["auth.trust_registry_version"] != "2026.04.16" {
		t.Fatalf("expected keeper registry version to win, got %q", resp.Ledger.Metadata["auth.trust_registry_version"])
	}
}

func TestNewApp_AuditTrustRegistryStatusIsReadableWithoutAdminToken(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       t.TempDir(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry/status", nil)
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp audithttp.GetEnterpriseTrustRegistryStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Status == nil || resp.Status.Configured {
		t.Fatalf("expected unconfigured trust-registry status, got %+v", resp.Status)
	}
}

func TestNewApp_AuditTrustRegistryAdminAPIActivatesEnterpriseWritesAndClearsThem(t *testing.T) {
	payload, signerConfig := mustMarshalEnterpriseControlLedgerWrite(t, "runtime-enterprise-ledger-managed-live")
	adminToken := "trust-registry-admin-token"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                             "simulated",
		"aethelred.audit.api.trust_registry_admin_token": adminToken,
		flags.FlagHome:                                   t.TempDir(),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec := httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 before registry activation, got %d", rec.Code)
	}

	registryPayload := mustMarshalEnterpriseTrustRegistry(t, signerConfig)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/audit/trust-registry", strings.NewReader(string(registryPayload)))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Aethelred-Actor", "did:aethelred:ops-admin")
	req.Header.Set("X-Aethelred-Reason", "activate live trust")
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on trust-registry put, got %d", rec.Code)
	}

	var putResp audithttp.PutEnterpriseTrustRegistryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("unmarshal trust-registry put response: %v", err)
	}
	if putResp.Status == nil || !putResp.Status.Configured {
		t.Fatalf("expected configured trust-registry status after put, got %+v", putResp.Status)
	}
	if putResp.Registry == nil || putResp.Registry.Version != "2026.04.14" {
		t.Fatalf("expected normalized persisted registry response, got %+v", putResp.Registry)
	}
	if putResp.Registry.Source != "pouw_governance" {
		t.Fatalf("expected governance-managed source in persisted registry response, got %q", putResp.Registry.Source)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201 after live registry activation, got %d", rec.Code)
	}

	var ledgerResp audithttp.PutControlLedgerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ledgerResp); err != nil {
		t.Fatalf("unmarshal control-ledger response: %v", err)
	}
	if ledgerResp.Ledger == nil || ledgerResp.Ledger.Metadata["auth.trust_provider"] != "pouw_keeper" {
		t.Fatalf("expected keeper-backed trust source metadata, got %+v", ledgerResp.Ledger)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/audit/trust-registry", strings.NewReader(`{"reason":"containment drill"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("X-Aethelred-Actor", "did:aethelred:ops-admin")
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on trust-registry delete, got %d", rec.Code)
	}

	var deleteResp audithttp.DeleteEnterpriseTrustRegistryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &deleteResp); err != nil {
		t.Fatalf("unmarshal trust-registry delete response: %v", err)
	}
	if !deleteResp.Cleared || deleteResp.Status == nil || deleteResp.Status.Configured {
		t.Fatalf("expected cleared unconfigured status after delete, got %+v", deleteResp)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/trust-registry/history", nil)
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 on trust-registry history, got %d", rec.Code)
	}

	var historyResp audithttp.GetEnterpriseTrustRegistryHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &historyResp); err != nil {
		t.Fatalf("unmarshal trust-registry history response: %v", err)
	}
	if historyResp.Total != 2 || len(historyResp.Records) != 2 {
		t.Fatalf("expected exactly two governance history records, got %+v", historyResp)
	}
	if historyResp.Records[0].Actor != app.PouwKeeper.GetAuthority() {
		t.Fatalf("expected governance authority actor in history, got %q", historyResp.Records[0].Actor)
	}
	if historyResp.Records[0].Details["requested_by"] != "did:aethelred:ops-admin" {
		t.Fatalf("expected requested_by detail in history, got %+v", historyResp.Records[0].Details)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(payload))
	rec = httptest.NewRecorder()
	app.auditServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503 after trust-registry clear, got %d", rec.Code)
	}

	governanceRecords := app.PouwKeeper.AuditLogger().GetRecordsByCategory(pouwkeeper.AuditCategoryGovernance)
	if !containsAuditAction(governanceRecords, "enterprise_audit_trust_registry_updated") {
		t.Fatalf("expected governance audit record for trust-registry update, got %+v", governanceRecords)
	}
	if !containsAuditAction(governanceRecords, "enterprise_audit_trust_registry_cleared") {
		t.Fatalf("expected governance audit record for trust-registry clear, got %+v", governanceRecords)
	}
}

func newAuditEnabledTestApp(t *testing.T, opts sims.AppOptionsMap) *AethelredApp {
	t.Helper()

	cfg := sdk.GetConfig()
	cfg.SetBech32PrefixForAccount(AccountAddressPrefix, AccountAddressPrefix+"pub")
	cfg.SetBech32PrefixForValidator(AccountAddressPrefix+"valoper", AccountAddressPrefix+"valoperpub")
	cfg.SetBech32PrefixForConsensusNode(AccountAddressPrefix+"valcons", AccountAddressPrefix+"valconspub")

	if _, ok := opts["aethelred.tee.mode"]; !ok {
		opts["aethelred.tee.mode"] = "mock"
	}
	if _, ok := opts["aethelred.secure_cells.confidential_execution.trusted_platforms"]; !ok {
		opts["aethelred.secure_cells.confidential_execution.trusted_platforms"] = "mock-tee"
	}
	if _, ok := opts["aethelred.finance.confidential_execution.trusted_platforms"]; !ok {
		opts["aethelred.finance.confidential_execution.trusted_platforms"] = "mock-tee"
	}

	app := New(log.NewNopLogger(), dbm.NewMemDB(), nil, true, opts)
	if app.auditServer == nil {
		t.Fatal("expected audit server to be initialized")
	}
	return app
}

func mustMarshalControlLedger(t *testing.T) string {
	t.Helper()

	ledger := evidence.NewControlLedger("Finance Control Ledger")
	ledger.Bundle.ID = "runtime-audit-ledger"
	ledger.WithMetadata("workflow", "treasury_release")
	ledger.AddRecord(evidence.Record{
		ID:        "record-runtime-001",
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     "did:aethelred:agent-runtime",
		Timestamp: "2026-04-14T10:00:00Z",
	})
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CTRL-RUNTIME-001",
		ControlName: "Runtime Treasury Release Approval",
		Status:      evidence.ControlSatisfied,
		Description: "Runtime POST path for persisted control-ledger evidence.",
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs: []string{"record-runtime-001"},
		},
	}); err != nil {
		t.Fatalf("add control: %v", err)
	}

	payload, err := json.Marshal(audithttp.PutControlLedgerRequest{Ledger: ledger})
	if err != nil {
		t.Fatalf("marshal control ledger: %v", err)
	}
	return string(payload)
}

func mustMarshalEnterpriseControlLedgerWrite(t *testing.T, ledgerID string) (string, string) {
	t.Helper()

	actorIdentity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{{Name: "audit.control_ledger.write", Version: "1.0"}},
		agent.EnterpriseIdentityOptions{
			SponsorChain: []agent.SponsorRecord{{
				SponsorDID:        "did:aethelred:sponsor-bank",
				SponsorName:       "Sponsor Bank",
				Jurisdiction:      "UAE",
				Role:              "operator",
				LiabilityAccepted: true,
				SignedAt:          time.Date(2026, 4, 14, 9, 0, 0, 0, time.UTC),
			}},
			Liability: &agent.LiabilityProfile{
				HumanOwner:      "alice.chen",
				SponsorOfRecord: "did:aethelred:sponsor-bank",
				LiabilityModel:  "enterprise_operator",
			},
			JurisdictionTags: []string{"UAE"},
			AllowedTools:     []string{"audit.control_ledger.write"},
		},
	)
	if err != nil {
		t.Fatalf("new enterprise agent identity: %v", err)
	}

	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	receipt, err := policy.CreateSignedPolicyReceipt(
		context.Background(),
		signerKey,
		"did:aethelred:policy-gateway-1",
		&policy.EvaluationRequest{
			Actor:    actorIdentity.AgentID(),
			Action:   "audit.control_ledger.write",
			Resource: "control-ledger:" + ledgerID,
			Context: map[string]string{
				"jurisdiction": "UAE",
			},
		},
		&policy.EvaluationResult{
			Decision:    policy.Allow,
			AuditTrail:  "runtime-enterprise-write",
			EvaluatedAt: time.Date(2026, 4, 14, 9, 5, 0, 0, time.UTC),
			RequestID:   "req-" + ledgerID,
		},
		"",
	)
	if err != nil {
		t.Fatalf("create signed policy receipt: %v", err)
	}

	ledger := evidence.NewControlLedger("Finance Control Ledger")
	ledger.Bundle.ID = ledgerID
	ledger.WithMetadata("workflow", "treasury_release")
	ledger.AddRecord(evidence.Record{
		ID:        "record-" + ledgerID,
		Type:      "governance",
		Action:    "payments.release.authorized",
		Actor:     actorIdentity.AgentID(),
		Timestamp: "2026-04-14T10:00:00Z",
	})
	if err := ledger.AddControl(evidence.LedgerControl{
		ControlID:   "CTRL-" + ledgerID,
		ControlName: "Runtime Enterprise Treasury Release Approval",
		Status:      evidence.ControlSatisfied,
		Description: "Runtime POST path with enterprise policy receipt auth.",
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs: []string{"record-" + ledgerID},
		},
	}); err != nil {
		t.Fatalf("add control: %v", err)
	}

	payload, err := json.Marshal(audithttp.PutControlLedgerRequest{
		Ledger: ledger,
		EnterpriseAuth: &audithttp.EnterpriseControlLedgerWriteAuthz{
			ActorIdentity: actorIdentity,
			PolicyReceipt: receipt,
		},
	})
	if err != nil {
		t.Fatalf("marshal enterprise control ledger request: %v", err)
	}

	signerPublicKeyHex := hex.EncodeToString(elliptic.MarshalCompressed(signerKey.PublicKey.Curve, signerKey.PublicKey.X, signerKey.PublicKey.Y))
	return string(payload), "did:aethelred:policy-gateway-1=" + signerPublicKeyHex
}

func mustMarshalEnterpriseTrustRegistry(t *testing.T, signerConfig string) []byte {
	t.Helper()

	parts := strings.SplitN(signerConfig, "=", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid signer config %q", signerConfig)
	}

	registry := audithttp.EnterpriseControlLedgerTrustRegistry{
		Version:              "2026.04.14",
		Source:               "runtime_registry",
		UpdatedAt:            "2026-04-14T10:30:00Z",
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []audithttp.EnterprisePolicySignerTrustEntry{{
			DID:           parts[0],
			PublicKeyHex:  parts[1],
			Status:        audithttp.TrustRegistryEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
		AllowedSponsors: []audithttp.EnterpriseSponsorTrustEntry{{
			DID:           "did:aethelred:sponsor-bank",
			Status:        audithttp.TrustRegistryEntryStatusActive,
			Actions:       []string{"audit.control_ledger.write"},
			Jurisdictions: []string{"UAE"},
		}},
	}

	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatalf("marshal trust registry: %v", err)
	}
	return data
}

func mustEnterpriseAuditTrustRegistryFromSignerConfig(t *testing.T, signerConfig string, source string, version string) *pouwkeeper.EnterpriseAuditTrustRegistry {
	t.Helper()

	parts := strings.SplitN(signerConfig, "=", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid signer config %q", signerConfig)
	}

	return &pouwkeeper.EnterpriseAuditTrustRegistry{
		Version:              version,
		Source:               source,
		RequiredAction:       "audit.control_ledger.write",
		RequiredJurisdiction: "UAE",
		PolicySigners: []pouwkeeper.EnterpriseAuditPolicySignerTrustEntry{{
			DID:           parts[0],
			PublicKeyHex:  parts[1],
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
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func containsAuditAction(records []pouwkeeper.AuditRecord, action string) bool {
	for _, record := range records {
		if record.Action == action {
			return true
		}
	}
	return false
}
