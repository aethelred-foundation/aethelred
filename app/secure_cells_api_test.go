package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/cosmos/cosmos-sdk/testutil/sims"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	securecellsintegration "github.com/aethelred/aethelred/pkg/integrations/securecells"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

func TestNewApp_InitializesSecureCellService(t *testing.T) {
	homeDir := t.TempDir()
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       homeDir,
	})

	if app.secureCellService == nil {
		t.Fatal("expected secure cell service to be initialized")
	}

	wantDir := filepath.Join(homeDir, "data", "secure-cells", "control-ledgers")
	if app.secureCellControlLedgerDir != wantDir {
		t.Fatalf("expected secure cell control ledger dir %q, got %q", wantDir, app.secureCellControlLedgerDir)
	}
}

func TestNewApp_InitializesSecureCellWriteAuth_DisabledByDefault(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		flags.FlagHome:       t.TempDir(),
	})

	body := mustMarshalSecureCellCreateRequest(t, mustSecureCellAppIdentity(t, "owner", []string{"UAE"}), []*agent.AgentIdentity{
		mustSecureCellAppIdentity(t, "reviewer", []string{"UAE"}),
	}, nil)
	req := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(body))
	rec := httptest.NewRecorder()

	app.SecureCellsCreateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	}
}

func TestSecureCellsHandlers_BearerCreateGetArtifactsFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE", "UK"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE", "UK"})
	body := mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participantA, participantB}, nil)

	req := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secure-cells-secret")
	rec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var createResp secureCellResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if createResp.Result == nil || createResp.Result.CellID == "" {
		t.Fatal("expected created secure cell result with ID")
	}
	if createResp.Result.Status != securecellsintegration.SecureCellStatusActive {
		t.Fatalf("expected active secure cell, got %+v", createResp.Result)
	}
	if createResp.Result.PortablePackage == nil || createResp.Result.PortablePackage.Signature == nil || createResp.Result.PortablePackage.AuditAnchor == nil {
		t.Fatal("expected signed and anchored portable package")
	}

	getReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+createResp.Result.CellID, nil)
	getRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, getRec.Code, getRec.Body.String())
	}

	var getResp secureCellResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("unmarshal get response: %v", err)
	}
	if getResp.Result == nil || getResp.Result.CellID != createResp.Result.CellID {
		t.Fatalf("unexpected get response: %+v", getResp.Result)
	}

	artifactReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+createResp.Result.CellID+"/artifacts", nil)
	artifactRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(artifactRec, artifactReq)
	if artifactRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, artifactRec.Code, artifactRec.Body.String())
	}

	var artifactResp secureCellArtifactsResponse
	if err := json.Unmarshal(artifactRec.Body.Bytes(), &artifactResp); err != nil {
		t.Fatalf("unmarshal artifact response: %v", err)
	}
	if artifactResp.ControlLedgerID == "" || artifactResp.PortablePackageHash == "" {
		t.Fatalf("expected artifact projection, got %+v", artifactResp)
	}
	if !artifactResp.PortablePackageSigned || !artifactResp.PortablePackageAnchored {
		t.Fatalf("expected signed and anchored artifact projection, got %+v", artifactResp)
	}
}

func TestSecureCellsCreateHandler_AcceptsEnterprisePolicyReceipt(t *testing.T) {
	policySignerKey := mustSecureCellPolicySignerKey(t)
	policySignerDID := "did:aethelred:secure-cells-policy"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		"aethelred.secure_cells.api.enterprise_policy_signers":        policySignerDID + "=" + mustSecureCellCompressedPublicKeyHex(t, &policySignerKey.PublicKey),
		"aethelred.secure_cells.api.enterprise_allowed_sponsors":      "did:aethelred:owner-sponsor",
		"aethelred.secure_cells.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	participant := mustSecureCellAppIdentity(t, "reviewer", []string{"UAE"})
	receipt := mustSecureCellSignedPolicyReceipt(t, policySignerKey, policySignerDID, owner, secureCellsAuthDefaultResource, "UAE")
	body := mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participant}, receipt)

	req := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, rec.Code, rec.Body.String())
	}
}

func TestSecureCellsCreateHandler_RejectsWrongEnterpriseJurisdiction(t *testing.T) {
	policySignerKey := mustSecureCellPolicySignerKey(t)
	policySignerDID := "did:aethelred:secure-cells-policy"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		"aethelred.secure_cells.api.enterprise_policy_signers":        policySignerDID + "=" + mustSecureCellCompressedPublicKeyHex(t, &policySignerKey.PublicKey),
		"aethelred.secure_cells.api.enterprise_allowed_sponsors":      "did:aethelred:owner-sponsor",
		"aethelred.secure_cells.api.enterprise_required_jurisdiction": "UK",
		flags.FlagHome: t.TempDir(),
	})

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	participant := mustSecureCellAppIdentity(t, "reviewer", []string{"UAE"})
	receipt := mustSecureCellSignedPolicyReceipt(t, policySignerKey, policySignerDID, owner, secureCellsAuthDefaultResource, "UAE")
	body := mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participant}, receipt)

	req := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusUnauthorized, rec.Code, rec.Body.String())
	}
}

func TestSecureCellsHandlers_BearerLifecycleMutationsFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE", "UK"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE", "UK"})

	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participantA}, nil)))
	createReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	createRec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createRec.Code, createRec.Body.String())
	}

	var createResp secureCellResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	cellID := createResp.Result.CellID

	admitReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/members", bytes.NewReader(mustMarshalSecureCellAdmitRequest(t, nil, participantB, nil)))
	admitReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	admitRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(admitRec, admitReq)
	if admitRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, admitRec.Code, admitRec.Body.String())
	}

	var admitResp secureCellResponse
	if err := json.Unmarshal(admitRec.Body.Bytes(), &admitResp); err != nil {
		t.Fatalf("unmarshal admit response: %v", err)
	}
	if admitResp.Result == nil || admitResp.Result.Status != securecellsintegration.SecureCellStatusActive {
		t.Fatalf("expected active cell after admit, got %+v", admitResp.Result)
	}
	if len(admitResp.Result.Transitions) != 3 {
		t.Fatalf("expected 3 transitions after admit, got %d", len(admitResp.Result.Transitions))
	}

	quarantinePath := secureCellsItemPrefix + cellID + "/members/" + participantB.AgentID() + "/quarantine"
	quarantineReq := httptest.NewRequest(http.MethodPost, quarantinePath, bytes.NewReader(mustMarshalSecureCellMemberMutationRequest(t, nil, participantB.AgentID(), "containment triggered", nil)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	var quarantineResp secureCellResponse
	if err := json.Unmarshal(quarantineRec.Body.Bytes(), &quarantineResp); err != nil {
		t.Fatalf("unmarshal quarantine response: %v", err)
	}
	if quarantineResp.Result == nil || quarantineResp.Result.Status != securecellsintegration.SecureCellStatusQuarantined {
		t.Fatalf("expected quarantined cell after quarantine, got %+v", quarantineResp.Result)
	}

	revokePath := secureCellsItemPrefix + cellID + "/members/" + participantB.AgentID() + "/revoke"
	revokeReq := httptest.NewRequest(http.MethodPost, revokePath, bytes.NewReader(mustMarshalSecureCellMemberMutationRequest(t, nil, participantB.AgentID(), "confirmed containment", nil)))
	revokeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	revokeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, revokeRec.Code, revokeRec.Body.String())
	}

	var revokeResp secureCellResponse
	if err := json.Unmarshal(revokeRec.Body.Bytes(), &revokeResp); err != nil {
		t.Fatalf("unmarshal revoke response: %v", err)
	}
	if revokeResp.Result == nil || revokeResp.Result.Status != securecellsintegration.SecureCellStatusActive {
		t.Fatalf("expected active cell after revoke, got %+v", revokeResp.Result)
	}
	if len(revokeResp.Result.Transitions) != 5 {
		t.Fatalf("expected 5 transitions after full lifecycle, got %d", len(revokeResp.Result.Transitions))
	}
	last := revokeResp.Result.Transitions[len(revokeResp.Result.Transitions)-1]
	if last.Action != "secure_cell.member_revoked" {
		t.Fatalf("expected revoke transition, got %+v", last)
	}

	artifactReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/artifacts", nil)
	artifactRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(artifactRec, artifactReq)
	if artifactRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, artifactRec.Code, artifactRec.Body.String())
	}

	var artifactResp secureCellArtifactsResponse
	if err := json.Unmarshal(artifactRec.Body.Bytes(), &artifactResp); err != nil {
		t.Fatalf("unmarshal artifact response: %v", err)
	}
	if artifactResp.Status != securecellsintegration.SecureCellStatusActive {
		t.Fatalf("expected active artifact projection after revoke, got %+v", artifactResp)
	}
	if len(artifactResp.Transitions) != 5 {
		t.Fatalf("expected 5 transitions in artifact projection, got %d", len(artifactResp.Transitions))
	}
	if !artifactResp.PortablePackageSigned || !artifactResp.PortablePackageAnchored {
		t.Fatalf("expected signed and anchored artifact projection, got %+v", artifactResp)
	}
}

func TestSecureCellsMutateHandler_AcceptsEnterpriseQuarantine(t *testing.T) {
	policySignerKey := mustSecureCellPolicySignerKey(t)
	policySignerDID := "did:aethelred:secure-cells-policy"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                          "simulated",
		"aethelred.secure_cells.api.write_token":                      "secure-cells-secret",
		"aethelred.secure_cells.api.enterprise_policy_signers":        policySignerDID + "=" + mustSecureCellCompressedPublicKeyHex(t, &policySignerKey.PublicKey),
		"aethelred.secure_cells.api.enterprise_allowed_sponsors":      "did:aethelred:owner-sponsor",
		"aethelred.secure_cells.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	participant := mustSecureCellAppIdentity(t, "reviewer", []string{"UAE"})

	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participant}, nil)))
	createReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	createRec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createRec.Code, createRec.Body.String())
	}

	var createResp secureCellResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	cellID := createResp.Result.CellID
	quarantinePath := secureCellsItemPrefix + cellID + "/members/" + participant.AgentID() + "/quarantine"
	receipt := mustSecureCellSignedPolicyReceiptForAction(t, policySignerKey, policySignerDID, owner, secureCellsAuthQuarantineAction, quarantinePath, "UAE")

	quarantineReq := httptest.NewRequest(http.MethodPost, quarantinePath, bytes.NewReader(mustMarshalSecureCellMemberMutationRequest(t, owner, participant.AgentID(), "risk hold", receipt)))
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	var quarantineResp secureCellResponse
	if err := json.Unmarshal(quarantineRec.Body.Bytes(), &quarantineResp); err != nil {
		t.Fatalf("unmarshal quarantine response: %v", err)
	}
	if quarantineResp.Result == nil || quarantineResp.Result.Status != securecellsintegration.SecureCellStatusQuarantined {
		t.Fatalf("expected quarantined cell, got %+v", quarantineResp.Result)
	}
	last := quarantineResp.Result.Transitions[len(quarantineResp.Result.Transitions)-1]
	if last.Action != "secure_cell.member_quarantined" {
		t.Fatalf("expected quarantine transition, got %+v", last)
	}
	if last.Metadata["auth.actor_did"] != owner.AgentID() {
		t.Fatalf("expected auth.actor_did metadata to be preserved, got %+v", last.Metadata)
	}
	if last.Metadata["auth.policy_receipt_id"] != receipt.ID {
		t.Fatalf("expected auth.policy_receipt_id metadata to be preserved, got %+v", last.Metadata)
	}
}

func TestSecureCellsHandlers_BearerReleasePauseResumeTerminateFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participant := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE", "UK"})

	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participant}, nil)))
	createReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	createRec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createRec.Code, createRec.Body.String())
	}

	var createResp secureCellResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	cellID := createResp.Result.CellID

	quarantinePath := secureCellsItemPrefix + cellID + "/members/" + participant.AgentID() + "/quarantine"
	expiry := time.Now().UTC().Add(15 * time.Minute)
	quarantineReq := httptest.NewRequest(http.MethodPost, quarantinePath, bytes.NewReader(mustMarshalSecureCellMemberMutationRequestWithExpiry(t, nil, participant.AgentID(), "risk hold", nil, &expiry)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	releasePath := secureCellsItemPrefix + cellID + "/members/" + participant.AgentID() + "/release"
	releaseReq := httptest.NewRequest(http.MethodPost, releasePath, bytes.NewReader(mustMarshalSecureCellMemberMutationRequest(t, nil, participant.AgentID(), "cleared to resume", nil)))
	releaseReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	releaseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(releaseRec, releaseReq)
	if releaseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, releaseRec.Code, releaseRec.Body.String())
	}

	pauseReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/pause", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, nil, "incident bridge", nil, nil)))
	pauseReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	pauseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(pauseRec, pauseReq)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, pauseRec.Code, pauseRec.Body.String())
	}

	resumeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/resume", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, nil, "incident resolved", nil, nil)))
	resumeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	resumeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(resumeRec, resumeReq)
	if resumeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, resumeRec.Code, resumeRec.Body.String())
	}

	terminateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/terminate", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, nil, "engagement closed", nil, nil)))
	terminateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	terminateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(terminateRec, terminateReq)
	if terminateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, terminateRec.Code, terminateRec.Body.String())
	}

	var terminateResp secureCellResponse
	if err := json.Unmarshal(terminateRec.Body.Bytes(), &terminateResp); err != nil {
		t.Fatalf("unmarshal terminate response: %v", err)
	}
	if terminateResp.Result == nil || terminateResp.Result.Status != securecellsintegration.SecureCellStatusTerminated {
		t.Fatalf("expected terminated secure cell, got %+v", terminateResp.Result)
	}
	if terminateResp.Result.TerminatedAt == nil {
		t.Fatalf("expected terminated_at to be recorded, got %+v", terminateResp.Result)
	}
	if len(terminateResp.Result.Transitions) != 7 {
		t.Fatalf("expected 7 transitions after full lifecycle, got %d", len(terminateResp.Result.Transitions))
	}
	last := terminateResp.Result.Transitions[len(terminateResp.Result.Transitions)-1]
	if last.Action != "secure_cell.terminated" {
		t.Fatalf("expected terminated transition, got %+v", last)
	}
}

func TestSecureCellsHandlers_BearerExpireQuarantineFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE"})

	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participantA, participantB}, nil)))
	createReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	createRec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createRec.Code, createRec.Body.String())
	}

	var createResp secureCellResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	cellID := createResp.Result.CellID
	expiredAt := time.Now().UTC().Add(-10 * time.Minute)
	quarantinePath := secureCellsItemPrefix + cellID + "/members/" + participantA.AgentID() + "/quarantine"
	quarantineReq := httptest.NewRequest(http.MethodPost, quarantinePath, bytes.NewReader(mustMarshalSecureCellMemberMutationRequestWithExpiry(t, nil, participantA.AgentID(), "timed hold", nil, &expiredAt)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	expireReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/quarantine/expire", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, nil, "expiry sweep", nil, &expiredAt)))
	expireReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	expireRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(expireRec, expireReq)
	if expireRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, expireRec.Code, expireRec.Body.String())
	}

	var expireResp secureCellResponse
	if err := json.Unmarshal(expireRec.Body.Bytes(), &expireResp); err != nil {
		t.Fatalf("unmarshal expire response: %v", err)
	}
	if expireResp.Result == nil || expireResp.Result.Status != securecellsintegration.SecureCellStatusActive {
		t.Fatalf("expected active cell after expiry release, got %+v", expireResp.Result)
	}
	last := expireResp.Result.Transitions[len(expireResp.Result.Transitions)-1]
	if last.Action != "secure_cell.quarantine_expired" {
		t.Fatalf("expected quarantine_expired transition, got %+v", last)
	}
}

func TestSecureCellsMutateHandler_AcceptsEnterprisePause(t *testing.T) {
	policySignerKey := mustSecureCellPolicySignerKey(t)
	policySignerDID := "did:aethelred:secure-cells-policy"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                                          "simulated",
		"aethelred.secure_cells.api.write_token":                      "secure-cells-secret",
		"aethelred.secure_cells.api.enterprise_policy_signers":        policySignerDID + "=" + mustSecureCellCompressedPublicKeyHex(t, &policySignerKey.PublicKey),
		"aethelred.secure_cells.api.enterprise_allowed_sponsors":      "did:aethelred:owner-sponsor",
		"aethelred.secure_cells.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	participant := mustSecureCellAppIdentity(t, "reviewer", []string{"UAE"})

	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participant}, nil)))
	createReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	createRec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createRec.Code, createRec.Body.String())
	}

	var createResp secureCellResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	cellID := createResp.Result.CellID
	pausePath := secureCellsItemPrefix + cellID + "/pause"
	receipt := mustSecureCellSignedPolicyReceiptForAction(t, policySignerKey, policySignerDID, owner, secureCellsAuthPauseAction, pausePath, "UAE")

	pauseReq := httptest.NewRequest(http.MethodPost, pausePath, bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "risk review", receipt, nil)))
	pauseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(pauseRec, pauseReq)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, pauseRec.Code, pauseRec.Body.String())
	}

	var pauseResp secureCellResponse
	if err := json.Unmarshal(pauseRec.Body.Bytes(), &pauseResp); err != nil {
		t.Fatalf("unmarshal pause response: %v", err)
	}
	if pauseResp.Result == nil || pauseResp.Result.Status != securecellsintegration.SecureCellStatusPaused {
		t.Fatalf("expected paused secure cell, got %+v", pauseResp.Result)
	}
	last := pauseResp.Result.Transitions[len(pauseResp.Result.Transitions)-1]
	if last.Action != "secure_cell.paused" {
		t.Fatalf("expected paused transition, got %+v", last)
	}
	if last.Metadata["auth.actor_did"] != owner.AgentID() || last.Metadata["auth.policy_receipt_id"] != receipt.ID {
		t.Fatalf("expected enterprise auth metadata to be preserved, got %+v", last.Metadata)
	}
}

func mustSecureCellAppIdentity(t *testing.T, label string, jurisdictions []string) *agent.AgentIdentity {
	t.Helper()

	sponsorDID := "did:aethelred:" + label + "-sponsor"
	identity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{{Name: secureCellsAuthRequiredTool, Version: "1.0"}},
		agent.EnterpriseIdentityOptions{
			Issuer: "did:aethelred:issuer-" + label,
			SponsorChain: []agent.SponsorRecord{{
				SponsorDID:        sponsorDID,
				SponsorName:       label + " sponsor",
				Jurisdiction:      jurisdictions[0],
				Role:              "sponsor_of_record",
				LiabilityAccepted: true,
				SignedAt:          time.Date(2026, 4, 15, 9, 0, 0, 0, time.UTC),
			}},
			Liability: &agent.LiabilityProfile{
				HumanOwner:      label + ".owner",
				BusinessUnit:    "secure-cells",
				SponsorOfRecord: sponsorDID,
				IncidentContact: "soc@example.com",
				LiabilityModel:  "enterprise-sponsored",
			},
			JurisdictionTags: jurisdictions,
			AllowedTools:     []string{secureCellsAuthRequiredTool},
			Metadata: map[string]string{
				"sector": "regulated-autonomy",
			},
		},
	)
	if err != nil {
		t.Fatalf("creating secure cell identity: %v", err)
	}
	return identity
}

func mustSecureCellPolicySignerKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate secure cell policy signer key: %v", err)
	}
	return key
}

func mustSecureCellCompressedPublicKeyHex(t *testing.T, publicKey *ecdsa.PublicKey) string {
	t.Helper()
	if publicKey == nil {
		t.Fatal("public key is required")
	}
	return hex.EncodeToString(elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y))
}

func mustSecureCellSignedPolicyReceipt(
	t *testing.T,
	signerKey *ecdsa.PrivateKey,
	signerDID string,
	identity *agent.AgentIdentity,
	resource string,
	jurisdiction string,
) *policy.SignedPolicyReceipt {
	t.Helper()

	return mustSecureCellSignedPolicyReceiptForAction(t, signerKey, signerDID, identity, secureCellsAuthRequestAction, resource, jurisdiction)
}

func mustSecureCellSignedPolicyReceiptForAction(
	t *testing.T,
	signerKey *ecdsa.PrivateKey,
	signerDID string,
	identity *agent.AgentIdentity,
	action string,
	resource string,
	jurisdiction string,
) *policy.SignedPolicyReceipt {
	t.Helper()

	if identity == nil {
		t.Fatal("identity is required")
	}
	evalReq := &policy.EvaluationRequest{
		Actor:    identity.AgentID(),
		Action:   action,
		Resource: resource,
		Context: map[string]string{
			"sector":       "regulated_autonomy",
			"jurisdiction": jurisdiction,
		},
		Metadata: map[string]string{
			"workflow": "secure_cell",
		},
	}
	evalResult := &policy.EvaluationResult{
		RequestID:    fmt.Sprintf("secure-cell-receipt-%d", time.Now().UnixNano()),
		Decision:     policy.Allow,
		MatchedRules: []string{"secure_cells.enterprise.allow"},
		AuditTrail:   "secure-cells-enterprise-audit-trail",
		EvaluatedAt:  time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC),
	}
	receipt, err := policy.CreateSignedPolicyReceipt(context.Background(), signerKey, signerDID, evalReq, evalResult, "")
	if err != nil {
		t.Fatalf("create signed secure cell policy receipt: %v", err)
	}
	return receipt
}

func mustMarshalSecureCellAdmitRequest(t *testing.T, actor *agent.AgentIdentity, participant *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellAdmitMemberRequest{
		ActorIdentity: mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt: receipt,
		Participant: securecellsintegration.SecureCellParticipant{
			Identity: participant,
			Role:     "participant_admitted",
			Metadata: map[string]string{"phase": "expansion"},
		},
		Reason:   "approved participant onboarded",
		Metadata: map[string]string{"ticket": "SC-ADMIT-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell admit request: %v", err)
	}
	return body
}

func mustMarshalSecureCellMemberMutationRequest(t *testing.T, actor *agent.AgentIdentity, participantDID string, reason string, receipt *policy.SignedPolicyReceipt) []byte {
	return mustMarshalSecureCellMemberMutationRequestWithExpiry(t, actor, participantDID, reason, receipt, nil)
}

func mustMarshalSecureCellMemberMutationRequestWithExpiry(t *testing.T, actor *agent.AgentIdentity, participantDID string, reason string, receipt *policy.SignedPolicyReceipt, expiresAt *time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellMemberMutationRequest{
		ActorIdentity:       mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:       receipt,
		ParticipantDID:      participantDID,
		Reason:              reason,
		QuarantineExpiresAt: expiresAt,
		Metadata:            map[string]string{"ticket": "SC-LIFE-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell member mutation request: %v", err)
	}
	return body
}

func mustMarshalSecureCellLifecycleRequest(t *testing.T, actor *agent.AgentIdentity, reason string, receipt *policy.SignedPolicyReceipt, effectiveAt *time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellLifecycleRequest{
		ActorIdentity: mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt: receipt,
		Reason:        reason,
		EffectiveAt:   effectiveAt,
		Metadata:      map[string]string{"ticket": "SC-GOV-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell lifecycle request: %v", err)
	}
	return body
}

func mustMarshalSecureCellCreateRequest(t *testing.T, owner *agent.AgentIdentity, participants []*agent.AgentIdentity, receipt *policy.SignedPolicyReceipt) []byte {
	t.Helper()

	secureCellParticipants := make([]securecellsintegration.SecureCellParticipant, 0, len(participants))
	for idx, participant := range participants {
		secureCellParticipants = append(secureCellParticipants, securecellsintegration.SecureCellParticipant{
			Identity: participant,
			Role:     fmt.Sprintf("participant_%d", idx+1),
		})
	}
	requireConfidentialCompute := true
	body, err := json.Marshal(secureCellCreateRequest{
		Identity:      mustJSONRawMessage(t, owner),
		PolicyReceipt: receipt,
		Name:          "Joint Review Cell",
		Purpose:       "regulated collaboration",
		Resource:      secureCellsAuthDefaultResource,
		Jurisdiction:  "UAE",
		Participants:  secureCellParticipants,
		Policy: securecellsintegration.SecureCellPolicy{
			DataClasses:                []string{"confidential"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: &requireConfidentialCompute,
		},
	})
	if err != nil {
		t.Fatalf("marshal secure cell create request: %v", err)
	}
	return body
}

func mustOptionalJSONRawMessage(t *testing.T, value any) json.RawMessage {
	t.Helper()
	if value == nil {
		return nil
	}
	return mustJSONRawMessage(t, value)
}
