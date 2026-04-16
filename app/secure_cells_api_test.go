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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
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

func TestSecureCellsHandlers_BearerSessionShareCloseFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE", "UK"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE", "UK"})

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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequest(t, nil, nil)))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal start response: %v", err)
	}
	if startResp.Result == nil || len(startResp.Result.Sessions) != 1 {
		t.Fatalf("expected started session, got %+v", startResp.Result)
	}
	sessionID := startResp.Result.Sessions[0].ID

	shareReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/share", bytes.NewReader(mustMarshalSecureCellSessionShareRequest(t, participantA, nil, []string{participantB.AgentID()})))
	shareReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	shareRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(shareRec, shareReq)
	if shareRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, shareRec.Code, shareRec.Body.String())
	}

	var shareResp secureCellResponse
	if err := json.Unmarshal(shareRec.Body.Bytes(), &shareResp); err != nil {
		t.Fatalf("unmarshal share response: %v", err)
	}
	if shareResp.Result == nil || len(shareResp.Result.SharedOutputs) != 1 {
		t.Fatalf("expected shared output, got %+v", shareResp.Result)
	}
	output := shareResp.Result.SharedOutputs[0]
	if output.SessionID != sessionID || output.IntegrityHash == "" || output.SealID == "" || output.TraceLinkID == "" {
		t.Fatalf("expected provenance-bearing shared output, got %+v", output)
	}

	closeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/close", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "session closed", nil, nil)))
	closeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	closeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(closeRec, closeReq)
	if closeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, closeRec.Code, closeRec.Body.String())
	}

	var closeResp secureCellResponse
	if err := json.Unmarshal(closeRec.Body.Bytes(), &closeResp); err != nil {
		t.Fatalf("unmarshal close response: %v", err)
	}
	if closeResp.Result == nil || len(closeResp.Result.Sessions) != 1 || closeResp.Result.Sessions[0].Status != securecellsintegration.SecureCellSessionStatusClosed {
		t.Fatalf("expected closed session, got %+v", closeResp.Result)
	}

	artifactsReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/artifacts", nil)
	artifactsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(artifactsRec, artifactsReq)
	if artifactsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, artifactsRec.Code, artifactsRec.Body.String())
	}
	var artifactsResp secureCellArtifactsResponse
	if err := json.Unmarshal(artifactsRec.Body.Bytes(), &artifactsResp); err != nil {
		t.Fatalf("unmarshal artifact response: %v", err)
	}
	if len(artifactsResp.Sessions) != 1 || len(artifactsResp.SharedOutputs) != 1 {
		t.Fatalf("expected session and shared output in artifacts projection, got %+v", artifactsResp)
	}
}

func TestSecureCellsHandlers_BearerSessionGovernanceFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE", "UK"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE", "UK"})

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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID
	if len(startResp.Result.Sessions[0].ParticipantDIDs) != 1 {
		t.Fatalf("expected one session participant, got %+v", startResp.Result.Sessions[0])
	}

	memberReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/members", bytes.NewReader(mustMarshalSecureCellSessionMemberMutationRequest(t, owner, participantB.AgentID(), "admit to room", nil)))
	memberReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	memberRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(memberRec, memberReq)
	if memberRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, memberRec.Code, memberRec.Body.String())
	}

	exchangeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/exchange", bytes.NewReader(mustMarshalSecureCellSessionExchangeRequest(t, participantA, nil, []string{participantB.AgentID()})))
	exchangeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	exchangeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(exchangeRec, exchangeReq)
	if exchangeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, exchangeRec.Code, exchangeRec.Body.String())
	}

	pauseReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/pause", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "pause room", nil, nil)))
	pauseReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	pauseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(pauseRec, pauseReq)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, pauseRec.Code, pauseRec.Body.String())
	}

	resumeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/resume", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "resume room", nil, nil)))
	resumeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	resumeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(resumeRec, resumeReq)
	if resumeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, resumeRec.Code, resumeRec.Body.String())
	}

	quarantineReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/quarantine", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "contain room", nil, nil)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	removeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/members/"+participantB.AgentID()+"/remove", bytes.NewReader(mustMarshalSecureCellSessionMemberMutationRequest(t, owner, participantB.AgentID(), "trim room", nil)))
	removeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	removeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(removeRec, removeReq)
	if removeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, removeRec.Code, removeRec.Body.String())
	}

	finalResumeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/resume", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "resume room again", nil, nil)))
	finalResumeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	finalResumeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(finalResumeRec, finalResumeReq)
	if finalResumeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, finalResumeRec.Code, finalResumeRec.Body.String())
	}

	artifactsReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/artifacts", nil)
	artifactsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(artifactsRec, artifactsReq)
	if artifactsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, artifactsRec.Code, artifactsRec.Body.String())
	}

	var artifactsResp secureCellArtifactsResponse
	if err := json.Unmarshal(artifactsRec.Body.Bytes(), &artifactsResp); err != nil {
		t.Fatalf("unmarshal artifact response: %v", err)
	}
	if len(artifactsResp.Sessions) != 1 || len(artifactsResp.SessionExchanges) != 1 {
		t.Fatalf("expected session and session exchange in artifact projection, got %+v", artifactsResp)
	}
	if artifactsResp.Sessions[0].Status != securecellsintegration.SecureCellSessionStatusActive {
		t.Fatalf("expected session to be active after final resume, got %+v", artifactsResp.Sessions[0])
	}
	if len(artifactsResp.Sessions[0].ParticipantDIDs) != 1 || artifactsResp.Sessions[0].ParticipantDIDs[0] != participantA.AgentID() {
		t.Fatalf("expected session membership trimmed to participant A, got %+v", artifactsResp.Sessions[0])
	}
	if artifactsResp.SessionExchanges[0].SealID == "" || artifactsResp.SessionExchanges[0].TraceLinkID == "" {
		t.Fatalf("expected evidence-bearing session exchange, got %+v", artifactsResp.SessionExchanges[0])
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

func TestSecureCellsCollectionHandler_FiltersLifecycleState(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE", "UK"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE", "UK"})

	createA := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participantA}, nil)))
	createA.Header.Set("Authorization", "Bearer secure-cells-secret")
	createARec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createARec, createA)
	if createARec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createARec.Code, createARec.Body.String())
	}

	createB := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participantB}, nil)))
	createB.Header.Set("Authorization", "Bearer secure-cells-secret")
	createBRec := httptest.NewRecorder()
	app.SecureCellsCreateHandler().ServeHTTP(createBRec, createB)
	if createBRec.Code != http.StatusCreated {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusCreated, createBRec.Code, createBRec.Body.String())
	}

	var createAResp secureCellResponse
	var createBResp secureCellResponse
	if err := json.Unmarshal(createARec.Body.Bytes(), &createAResp); err != nil {
		t.Fatalf("unmarshal create A response: %v", err)
	}
	if err := json.Unmarshal(createBRec.Body.Bytes(), &createBResp); err != nil {
		t.Fatalf("unmarshal create B response: %v", err)
	}

	pauseReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+createAResp.Result.CellID+"/pause", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, nil, "incident bridge", nil, nil)))
	pauseReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	pauseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(pauseRec, pauseReq)
	if pauseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, pauseRec.Code, pauseRec.Body.String())
	}

	quarantineReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+createBResp.Result.CellID+"/members/"+participantB.AgentID()+"/quarantine", bytes.NewReader(mustMarshalSecureCellMemberMutationRequest(t, nil, participantB.AgentID(), "containment", nil)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"?status=paused&participant_did="+participantA.AgentID(), nil)
	listRec := httptest.NewRecorder()
	app.SecureCellsCollectionHandler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, listRec.Code, listRec.Body.String())
	}

	var listResp secureCellListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(listResp.Items) != 1 || listResp.Items[0].CellID != createAResp.Result.CellID {
		t.Fatalf("expected paused cell listing, got %+v", listResp.Items)
	}
	if listResp.Items[0].PausedFromStatus != securecellsintegration.SecureCellStatusActive {
		t.Fatalf("expected paused_from_status active, got %+v", listResp.Items[0])
	}
}

func TestSecureCellsExpiringQuarantinesHandler_ListsExpiredMembers(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})

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

	expiredAt := time.Now().UTC().Add(-20 * time.Minute)
	futureAt := time.Now().UTC().Add(20 * time.Minute)
	quarantineAReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+createResp.Result.CellID+"/members/"+participantA.AgentID()+"/quarantine", bytes.NewReader(mustMarshalSecureCellMemberMutationRequestWithExpiry(t, nil, participantA.AgentID(), "expired hold", nil, &expiredAt)))
	quarantineAReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineARec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineARec, quarantineAReq)
	if quarantineARec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineARec.Code, quarantineARec.Body.String())
	}

	releaseReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+createResp.Result.CellID+"/members/"+participantA.AgentID()+"/release", bytes.NewReader(mustMarshalSecureCellMemberMutationRequest(t, nil, participantA.AgentID(), "manual release", nil)))
	releaseReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	releaseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(releaseRec, releaseReq)
	if releaseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, releaseRec.Code, releaseRec.Body.String())
	}

	quarantineExpiredReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+createResp.Result.CellID+"/members/"+participantA.AgentID()+"/quarantine", bytes.NewReader(mustMarshalSecureCellMemberMutationRequestWithExpiry(t, nil, participantA.AgentID(), "expired hold again", nil, &expiredAt)))
	quarantineExpiredReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineExpiredRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineExpiredRec, quarantineExpiredReq)
	if quarantineExpiredRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineExpiredRec.Code, quarantineExpiredRec.Body.String())
	}

	quarantineBReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+createResp.Result.CellID+"/members/"+participantB.AgentID()+"/quarantine", bytes.NewReader(mustMarshalSecureCellMemberMutationRequestWithExpiry(t, nil, participantB.AgentID(), "future hold", nil, &futureAt)))
	quarantineBReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineBRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineBRec, quarantineBReq)
	if quarantineBRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineBRec.Code, quarantineBRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/quarantine/expiring?before="+time.Now().UTC().Format(time.RFC3339Nano), nil)
	listRec := httptest.NewRecorder()
	app.SecureCellsExpiringQuarantinesHandler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, listRec.Code, listRec.Body.String())
	}

	var listResp secureCellQuarantineExpiryListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal expiry list response: %v", err)
	}
	if len(listResp.Items) != 1 || listResp.Items[0].ParticipantDID != participantA.AgentID() {
		t.Fatalf("expected one expired quarantine entry for participant A, got %+v", listResp.Items)
	}
}

func TestSecureCellsHandlers_BulkMutationEventsAndWebhookDeliveries(t *testing.T) {
	var (
		webhookMu      sync.Mutex
		webhookBodies  [][]byte
		webhookHeaders []http.Header
	)
	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		webhookMu.Lock()
		webhookBodies = append(webhookBodies, body)
		webhookHeaders = append(webhookHeaders, r.Header.Clone())
		webhookMu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhookServer.Close()

	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                           "simulated",
		"aethelred.secure_cells.api.write_token":       "secure-cells-secret",
		"aethelred.secure_cells.webhook_urls":          webhookServer.URL,
		"aethelred.secure_cells.webhook_hmac_secret":   "secure-cells-hmac",
		"aethelred.secure_cells.webhook_workers":       "1",
		"aethelred.secure_cells.webhook_retry_backoff": "10ms",
		"aethelred.secure_cells.expiry_sweep_interval": "off",
		flags.FlagHome: t.TempDir(),
	})

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

	bulkReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/members/bulk/quarantine", bytes.NewReader(mustMarshalSecureCellBulkMutationRequest(t, nil, []string{participantA.AgentID(), participantB.AgentID()}, "bulk containment", nil, nil)))
	bulkReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	bulkRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(bulkRec, bulkReq)
	if bulkRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, bulkRec.Code, bulkRec.Body.String())
	}

	var bulkResp secureCellBulkMutationResponse
	if err := json.Unmarshal(bulkRec.Body.Bytes(), &bulkResp); err != nil {
		t.Fatalf("unmarshal bulk response: %v", err)
	}
	if bulkResp.Result == nil || bulkResp.Result.SucceededCount != 2 || bulkResp.Result.FinalState == nil || bulkResp.Result.FinalState.Status != securecellsintegration.SecureCellStatusQuarantined {
		t.Fatalf("unexpected bulk mutation response: %+v", bulkResp.Result)
	}

	waitForSecureCellWebhookDeliveries(t, app, 3)

	eventsReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/events?cell_id="+cellID, nil)
	eventsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(eventsRec, eventsReq)
	if eventsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, eventsRec.Code, eventsRec.Body.String())
	}

	var eventsResp secureCellEventListResponse
	if err := json.Unmarshal(eventsRec.Body.Bytes(), &eventsResp); err != nil {
		t.Fatalf("unmarshal events response: %v", err)
	}
	if len(eventsResp.Items) < 3 {
		t.Fatalf("expected at least 3 secure-cell audit events, got %+v", eventsResp.Items)
	}

	deliveriesReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/webhook-deliveries?cell_id="+cellID+"&status=succeeded", nil)
	deliveriesRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(deliveriesRec, deliveriesReq)
	if deliveriesRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, deliveriesRec.Code, deliveriesRec.Body.String())
	}

	var deliveriesResp secureCellWebhookDeliveryListResponse
	if err := json.Unmarshal(deliveriesRec.Body.Bytes(), &deliveriesResp); err != nil {
		t.Fatalf("unmarshal deliveries response: %v", err)
	}
	if len(deliveriesResp.Items) < 3 {
		t.Fatalf("expected successful webhook deliveries, got %+v", deliveriesResp.Items)
	}

	webhookMu.Lock()
	defer webhookMu.Unlock()
	if len(webhookBodies) < 3 {
		t.Fatalf("expected webhook deliveries to reach test server, got %d", len(webhookBodies))
	}
	if got := webhookHeaders[len(webhookHeaders)-1].Get("X-Aethelred-Signature"); !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("expected signed webhook delivery, got headers %+v", webhookHeaders[len(webhookHeaders)-1])
	}
}

func TestSecureCellsAutomatedExpirySweeperReleasesExpiredMembers(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                           "simulated",
		"aethelred.secure_cells.api.write_token":       "secure-cells-secret",
		"aethelred.secure_cells.expiry_sweep_interval": "20ms",
		flags.FlagHome:                                 t.TempDir(),
	})

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
	expiredAt := time.Now().UTC().Add(-time.Minute)
	quarantineReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/members/"+participant.AgentID()+"/quarantine", bytes.NewReader(mustMarshalSecureCellMemberMutationRequestWithExpiry(t, nil, participant.AgentID(), "timed hold", nil, &expiredAt)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	waitForSecureCellCondition(t, 2*time.Second, func() bool {
		getReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID, nil)
		getRec := httptest.NewRecorder()
		app.SecureCellsGetHandler().ServeHTTP(getRec, getReq)
		if getRec.Code != http.StatusOK {
			return false
		}
		var getResp secureCellResponse
		if err := json.Unmarshal(getRec.Body.Bytes(), &getResp); err != nil || getResp.Result == nil {
			return false
		}
		return getResp.Result.Status == securecellsintegration.SecureCellStatusActive &&
			getResp.Result.Transitions[len(getResp.Result.Transitions)-1].Action == "secure_cell.quarantine_expired" &&
			getResp.Result.Transitions[len(getResp.Result.Transitions)-1].Actor == secureCellAutomatedSweepActor
	})
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

func mustMarshalSecureCellBulkMutationRequest(t *testing.T, actor *agent.AgentIdentity, participantDIDs []string, reason string, receipt *policy.SignedPolicyReceipt, expiresAt *time.Time) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellBulkMemberMutationRequest{
		ActorIdentity:       mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:       receipt,
		ParticipantDIDs:     participantDIDs,
		Reason:              reason,
		QuarantineExpiresAt: expiresAt,
		Metadata:            map[string]string{"ticket": "SC-BULK-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell bulk mutation request: %v", err)
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

func mustMarshalSecureCellSessionStartRequest(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt) []byte {
	return mustMarshalSecureCellSessionStartRequestWithParticipants(t, actor, receipt, nil)
}

func mustMarshalSecureCellSessionStartRequestWithParticipants(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, participantDIDs []string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellSessionStartRequest{
		ActorIdentity:   mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:   receipt,
		Name:            "Morning Review Session",
		Purpose:         "daily cross-bank review",
		ParticipantDIDs: participantDIDs,
		DataClasses:     []string{"confidential"},
		Reason:          "session opened",
		Metadata:        map[string]string{"ticket": "SC-SESSION-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell session start request: %v", err)
	}
	return body
}

func mustMarshalSecureCellSessionExchangeRequest(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, recipients []string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellSessionExchangeRequest{
		ActorIdentity:  mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:  receipt,
		Name:           "Live Risk Note",
		ExchangeType:   "message",
		Classification: "confidential",
		Resource:       "secure-cell:session:exchange:note",
		Summary:        "live room note",
		Recipients:     recipients,
		Reason:         "exchange sent",
		Metadata:       map[string]string{"ticket": "SC-XCHG-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell session exchange request: %v", err)
	}
	return body
}

func mustMarshalSecureCellSessionMemberMutationRequest(t *testing.T, actor *agent.AgentIdentity, participantDID string, reason string, receipt *policy.SignedPolicyReceipt) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellSessionMemberMutationRequest{
		ActorIdentity:  mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:  receipt,
		ParticipantDID: participantDID,
		Reason:         reason,
		Metadata:       map[string]string{"ticket": "SC-SESS-MEMBER-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell session member mutation request: %v", err)
	}
	return body
}

func mustMarshalSecureCellSessionShareRequest(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, sharedWith []string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellSessionShareRequest{
		ActorIdentity:  mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:  receipt,
		Name:           "Escalation Memo",
		ArtifactType:   "memo",
		Classification: "confidential",
		Resource:       "secure-cell:shared-output:memo",
		Summary:        "counterparty escalation memo",
		SharedWith:     sharedWith,
		Reason:         "memo shared",
		Metadata:       map[string]string{"ticket": "SC-SHARE-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell session share request: %v", err)
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

func waitForSecureCellWebhookDeliveries(t *testing.T, app *AethelredApp, minSucceeded int) {
	t.Helper()
	waitForSecureCellCondition(t, 2*time.Second, func() bool {
		if app == nil || app.secureCellRuntime == nil {
			return false
		}
		items := app.secureCellRuntime.ListDeliveries(secureCellWebhookDeliveryFilter{Status: secureCellWebhookDeliverySucceeded})
		return len(items) >= minSucceeded
	})
}

func waitForSecureCellCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied before timeout")
}
