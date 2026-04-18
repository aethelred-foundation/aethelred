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
	"net/url"
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

	wantWorkflowDir := filepath.Join(homeDir, "data", "secure-cells", "workflows")
	if app.secureCellWorkflowStoreDir != wantWorkflowDir {
		t.Fatalf("expected secure cell workflow store dir %q, got %q", wantWorkflowDir, app.secureCellWorkflowStoreDir)
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

func TestSecureCellsHandlers_BearerFederationLifecycleFlow(t *testing.T) {
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
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UK"})
	participantC := mustSecureCellAppIdentity(t, "reviewer-c", []string{"UK"})

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

	inviteReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/federation/invitations", bytes.NewReader(mustMarshalSecureCellFederationInviteRequest(t, nil, participantB, nil)))
	inviteReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	inviteRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(inviteRec, inviteReq)
	if inviteRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, inviteRec.Code, inviteRec.Body.String())
	}

	var inviteResp secureCellResponse
	if err := json.Unmarshal(inviteRec.Body.Bytes(), &inviteResp); err != nil {
		t.Fatalf("unmarshal invite response: %v", err)
	}
	if len(inviteResp.Result.FederationInvitations) != 1 {
		t.Fatalf("expected one pending invitation, got %+v", inviteResp.Result.FederationInvitations)
	}
	invitationID := inviteResp.Result.FederationInvitations[0].ID

	acceptReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/federation/invitations/"+invitationID+"/accept", bytes.NewReader(mustMarshalSecureCellFederationAcceptRequest(t, nil, invitationID, participantB, nil)))
	acceptReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	acceptRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(acceptRec, acceptReq)
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, acceptRec.Code, acceptRec.Body.String())
	}

	var acceptResp secureCellResponse
	if err := json.Unmarshal(acceptRec.Body.Bytes(), &acceptResp); err != nil {
		t.Fatalf("unmarshal accept response: %v", err)
	}
	if len(acceptResp.Result.Participants) != 2 {
		t.Fatalf("expected second live participant after federation accept, got %+v", acceptResp.Result.Participants)
	}

	secondInviteReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/federation/invitations", bytes.NewReader(mustMarshalSecureCellFederationInviteRequest(t, nil, participantC, nil)))
	secondInviteReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	secondInviteRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(secondInviteRec, secondInviteReq)
	if secondInviteRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, secondInviteRec.Code, secondInviteRec.Body.String())
	}

	var secondInviteResp secureCellResponse
	if err := json.Unmarshal(secondInviteRec.Body.Bytes(), &secondInviteResp); err != nil {
		t.Fatalf("unmarshal second invite response: %v", err)
	}
	if len(secondInviteResp.Result.FederationInvitations) != 2 {
		t.Fatalf("expected two invitations after second invite, got %+v", secondInviteResp.Result.FederationInvitations)
	}
	secondInvitationID := secondInviteResp.Result.FederationInvitations[1].ID

	revokeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/federation/invitations/"+secondInvitationID+"/revoke", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, nil, "counterparty withdrawn", nil, nil)))
	revokeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	revokeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, revokeRec.Code, revokeRec.Body.String())
	}

	federationReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/federation", nil)
	federationRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(federationRec, federationReq)
	if federationRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, federationRec.Code, federationRec.Body.String())
	}

	var federationResp secureCellFederationResponse
	if err := json.Unmarshal(federationRec.Body.Bytes(), &federationResp); err != nil {
		t.Fatalf("unmarshal federation response: %v", err)
	}
	if len(federationResp.Invitations) != 2 {
		t.Fatalf("expected two federation invitations, got %+v", federationResp.Invitations)
	}
	if len(federationResp.Organizations) != 4 {
		t.Fatalf("expected owner + local participant + accepted org + revoked org, got %+v", federationResp.Organizations)
	}
	if federationResp.PortablePackageHash == "" || !federationResp.PortablePackageSigned || !federationResp.PortablePackageAnchored {
		t.Fatalf("expected signed and anchored portable package projection, got %+v", federationResp)
	}

	var acceptedFound bool
	var revokedFound bool
	for _, invitation := range federationResp.Invitations {
		switch invitation.ID {
		case invitationID:
			acceptedFound = invitation.Status == securecellsintegration.SecureCellFederationInvitationStatusAccepted && invitation.ExpectedDID == participantB.AgentID()
		case secondInvitationID:
			revokedFound = invitation.Status == securecellsintegration.SecureCellFederationInvitationStatusRevoked && invitation.ExpectedDID == participantC.AgentID()
		}
	}
	if !acceptedFound || !revokedFound {
		t.Fatalf("expected accepted and revoked federation invitations, got %+v", federationResp.Invitations)
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

func TestSecureCellsMutateHandler_AcceptsEnterpriseFederationInviteAndAccept(t *testing.T) {
	policySignerKey := mustSecureCellPolicySignerKey(t)
	policySignerDID := "did:aethelred:secure-cells-policy"
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode": "simulated",
		"aethelred.secure_cells.api.enterprise_policy_signers":        policySignerDID + "=" + mustSecureCellCompressedPublicKeyHex(t, &policySignerKey.PublicKey),
		"aethelred.secure_cells.api.enterprise_allowed_sponsors":      "did:aethelred:owner-sponsor,did:aethelred:reviewer-b-sponsor",
		"aethelred.secure_cells.api.enterprise_required_jurisdiction": "UAE",
		flags.FlagHome: t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	participantA := mustSecureCellAppIdentity(t, "reviewer-a", []string{"UAE"})
	participantB := mustSecureCellAppIdentity(t, "reviewer-b", []string{"UAE"})

	createReceipt := mustSecureCellSignedPolicyReceipt(t, policySignerKey, policySignerDID, owner, secureCellsAuthDefaultResource, "UAE")
	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequest(t, owner, []*agent.AgentIdentity{participantA}, createReceipt)))
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

	invitePath := secureCellsItemPrefix + cellID + "/federation/invitations"
	inviteReceipt := mustSecureCellSignedPolicyReceiptForAction(t, policySignerKey, policySignerDID, owner, secureCellsAuthFederationInviteAction, invitePath, "UAE")
	inviteReq := httptest.NewRequest(http.MethodPost, invitePath, bytes.NewReader(mustMarshalSecureCellFederationInviteRequest(t, owner, participantB, inviteReceipt)))
	inviteRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(inviteRec, inviteReq)
	if inviteRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, inviteRec.Code, inviteRec.Body.String())
	}

	var inviteResp secureCellResponse
	if err := json.Unmarshal(inviteRec.Body.Bytes(), &inviteResp); err != nil {
		t.Fatalf("unmarshal invite response: %v", err)
	}
	if len(inviteResp.Result.FederationInvitations) != 1 {
		t.Fatalf("expected one federation invitation, got %+v", inviteResp.Result.FederationInvitations)
	}
	invitationID := inviteResp.Result.FederationInvitations[0].ID

	acceptPath := secureCellsItemPrefix + cellID + "/federation/invitations/" + invitationID + "/accept"
	acceptReceipt := mustSecureCellSignedPolicyReceiptForAction(t, policySignerKey, policySignerDID, participantB, secureCellsAuthFederationAcceptAction, acceptPath, "UAE")
	acceptReq := httptest.NewRequest(http.MethodPost, acceptPath, bytes.NewReader(mustMarshalSecureCellFederationAcceptRequest(t, participantB, invitationID, participantB, acceptReceipt)))
	acceptRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(acceptRec, acceptReq)
	if acceptRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, acceptRec.Code, acceptRec.Body.String())
	}

	var acceptResp secureCellResponse
	if err := json.Unmarshal(acceptRec.Body.Bytes(), &acceptResp); err != nil {
		t.Fatalf("unmarshal accept response: %v", err)
	}
	if len(acceptResp.Result.Participants) != 2 {
		t.Fatalf("expected accepted enterprise federation participant, got %+v", acceptResp.Result.Participants)
	}
	if acceptResp.Result.FederationInvitations[0].Status != securecellsintegration.SecureCellFederationInvitationStatusAccepted {
		t.Fatalf("expected accepted federation invitation, got %+v", acceptResp.Result.FederationInvitations)
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

func TestSecureCellsHandlers_BearerSessionThreadGovernanceFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))); err != nil {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID(), participantB.AgentID()})))
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

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	if threadStartResp.Result == nil || len(threadStartResp.Result.Threads) != 1 {
		t.Fatalf("expected started thread, got %+v", threadStartResp.Result)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	messageReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/messages", bytes.NewReader(mustMarshalSecureCellThreadMessageRequest(t, participantA, nil, []string{participantA.AgentID()})))
	messageReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	messageRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(messageRec, messageReq)
	if messageRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, messageRec.Code, messageRec.Body.String())
	}

	var messageResp secureCellResponse
	if err := json.Unmarshal(messageRec.Body.Bytes(), &messageResp); err != nil {
		t.Fatalf("unmarshal thread message response: %v", err)
	}
	if messageResp.Result == nil || len(messageResp.Result.SessionExchanges) != 1 {
		t.Fatalf("expected thread message exchange, got %+v", messageResp.Result)
	}
	if messageResp.Result.SessionExchanges[0].ThreadID != threadID {
		t.Fatalf("expected thread-scoped exchange, got %+v", messageResp.Result.SessionExchanges[0])
	}

	quarantineReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/quarantine", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "contain substream", nil, nil)))
	quarantineReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	quarantineRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(quarantineRec, quarantineReq)
	if quarantineRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, quarantineRec.Code, quarantineRec.Body.String())
	}

	blockedMessageReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/messages", bytes.NewReader(mustMarshalSecureCellThreadMessageRequest(t, participantA, nil, []string{participantA.AgentID()})))
	blockedMessageReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	blockedMessageRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(blockedMessageRec, blockedMessageReq)
	if blockedMessageRec.Code != http.StatusConflict {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusConflict, blockedMessageRec.Code, blockedMessageRec.Body.String())
	}

	eventsReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/events?thread_id="+threadID+"&action=secure_cell.session_thread_quarantined", nil)
	eventsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(eventsRec, eventsReq)
	if eventsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, eventsRec.Code, eventsRec.Body.String())
	}
	var eventsResp secureCellEventListResponse
	if err := json.Unmarshal(eventsRec.Body.Bytes(), &eventsResp); err != nil {
		t.Fatalf("unmarshal events response: %v", err)
	}
	if len(eventsResp.Items) == 0 || eventsResp.Items[0].ThreadID != threadID {
		t.Fatalf("expected thread-scoped quarantine event, got %+v", eventsResp.Items)
	}

	resumeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/resume", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "resume substream", nil, nil)))
	resumeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	resumeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(resumeRec, resumeReq)
	if resumeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, resumeRec.Code, resumeRec.Body.String())
	}

	closeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/close", bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "close substream", nil, nil)))
	closeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	closeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(closeRec, closeReq)
	if closeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, closeRec.Code, closeRec.Body.String())
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
	if len(artifactsResp.Threads) != 1 || len(artifactsResp.SessionExchanges) != 1 {
		t.Fatalf("expected thread and thread exchange in artifact projection, got %+v", artifactsResp)
	}
	if artifactsResp.Threads[0].Status != securecellsintegration.SecureCellThreadStatusClosed {
		t.Fatalf("expected closed thread in artifacts, got %+v", artifactsResp.Threads[0])
	}
	if artifactsResp.SessionExchanges[0].ThreadID != threadID || artifactsResp.SessionExchanges[0].SealID == "" {
		t.Fatalf("expected evidence-bearing thread exchange in artifacts, got %+v", artifactsResp.SessionExchanges[0])
	}
}

func TestSecureCellsHandlers_BearerThreadDecisionLifecycleFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize))); err != nil {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID(), participantB.AgentID()})))
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

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	messageReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/messages", bytes.NewReader(mustMarshalSecureCellThreadMessageRequest(t, participantA, nil, []string{participantA.AgentID()})))
	messageReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	messageRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(messageRec, messageReq)
	if messageRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, messageRec.Code, messageRec.Body.String())
	}

	var messageResp secureCellResponse
	if err := json.Unmarshal(messageRec.Body.Bytes(), &messageResp); err != nil {
		t.Fatalf("unmarshal thread message response: %v", err)
	}
	exchangeID := messageResp.Result.SessionExchanges[0].ID

	decisionCreateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequest(t, participantA, nil, []string{exchangeID})))
	decisionCreateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionCreateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionCreateRec, decisionCreateReq)
	if decisionCreateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionCreateRec.Code, decisionCreateRec.Body.String())
	}

	var decisionCreateResp secureCellResponse
	if err := json.Unmarshal(decisionCreateRec.Body.Bytes(), &decisionCreateResp); err != nil {
		t.Fatalf("unmarshal decision create response: %v", err)
	}
	if decisionCreateResp.Result == nil || len(decisionCreateResp.Result.Decisions) != 1 {
		t.Fatalf("expected one created decision, got %+v", decisionCreateResp.Result)
	}
	decisionID := decisionCreateResp.Result.Decisions[0].ID

	for _, action := range []string{"approve", "quarantine", "resume", "close"} {
		req := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/"+action, bytes.NewReader(mustMarshalSecureCellLifecycleRequest(t, owner, "decision "+action, nil, nil)))
		req.Header.Set("Authorization", "Bearer secure-cells-secret")
		rec := httptest.NewRecorder()
		app.SecureCellsMutateHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d for %s, got %d body=%s", http.StatusOK, action, rec.Code, rec.Body.String())
		}
	}

	eventsReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/events?thread_id="+threadID+"&decision_id="+decisionID+"&action=secure_cell.session_thread_decision_closed", nil)
	eventsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(eventsRec, eventsReq)
	if eventsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, eventsRec.Code, eventsRec.Body.String())
	}
	var eventsResp secureCellEventListResponse
	if err := json.Unmarshal(eventsRec.Body.Bytes(), &eventsResp); err != nil {
		t.Fatalf("unmarshal events response: %v", err)
	}
	if len(eventsResp.Items) == 0 || eventsResp.Items[0].ThreadID != threadID || eventsResp.Items[0].DecisionID != decisionID {
		t.Fatalf("expected thread-scoped decision event, got %+v", eventsResp.Items)
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
	if len(artifactsResp.Decisions) != 1 || artifactsResp.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusClosed {
		t.Fatalf("expected closed decision in artifacts, got %+v", artifactsResp.Decisions)
	}
	if len(artifactsResp.Threads) != 1 || len(artifactsResp.Threads[0].DecisionIDs) != 1 || artifactsResp.Threads[0].DecisionIDs[0] != decisionID {
		t.Fatalf("expected thread decision linkage in artifacts, got %+v", artifactsResp.Threads)
	}
	if artifactsResp.Transitions[len(artifactsResp.Transitions)-1].DecisionID != decisionID {
		t.Fatalf("expected final transition to reference decision %q, got %+v", decisionID, artifactsResp.Transitions[len(artifactsResp.Transitions)-1])
	}
}

func TestSecureCellsHandlers_BearerThreadDecisionCommentContainmentAndThresholdFlow(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, ed25519.SeedSize))); err != nil {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID(), participantB.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
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
		t.Fatalf("expected one shared output, got %+v", shareResp.Result)
	}
	sharedOutputID := shareResp.Result.SharedOutputs[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	threshold := 2
	decisionCreateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithOptions(t, participantA, nil, nil, []string{sharedOutputID}, &threshold, []string{owner.AgentID(), participantA.AgentID()})))
	decisionCreateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionCreateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionCreateRec, decisionCreateReq)
	if decisionCreateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionCreateRec.Code, decisionCreateRec.Body.String())
	}

	var decisionCreateResp secureCellResponse
	if err := json.Unmarshal(decisionCreateRec.Body.Bytes(), &decisionCreateResp); err != nil {
		t.Fatalf("unmarshal decision create response: %v", err)
	}
	if decisionCreateResp.Result == nil || len(decisionCreateResp.Result.Decisions) != 1 {
		t.Fatalf("expected one created decision, got %+v", decisionCreateResp.Result)
	}
	decisionID := decisionCreateResp.Result.Decisions[0].ID

	approveReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/approve", bytes.NewReader(mustMarshalSecureCellDecisionLifecycleRequest(t, owner, "threshold approval", nil, []string{sharedOutputID}, &threshold, "approve", "first approver vote", map[string]string{"ticket": "SC-THREAD-APPROVAL-THRESHOLD"})))
	approveReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	approveRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, approveRec.Code, approveRec.Body.String())
	}

	var approveResp secureCellResponse
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approveResp); err != nil {
		t.Fatalf("unmarshal approval response: %v", err)
	}
	if approveResp.Result == nil || approveResp.Result.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusOpen {
		t.Fatalf("expected open decision after first thresholded vote, got %+v", approveResp.Result)
	}
	lastApprovalTransition := approveResp.Result.Transitions[len(approveResp.Result.Transitions)-1]
	if lastApprovalTransition.Action != "secure_cell.session_thread_decision_voted" {
		t.Fatalf("expected vote transition, got %+v", lastApprovalTransition)
	}
	if lastApprovalTransition.Metadata["approval_threshold"] != "2" || lastApprovalTransition.Metadata["approval_vote"] != "approve" || lastApprovalTransition.Metadata["approval_comment"] != "first approver vote" {
		t.Fatalf("expected approval metadata to be preserved, got %+v", lastApprovalTransition.Metadata)
	}

	commentReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/comments", bytes.NewReader(mustMarshalSecureCellDecisionLifecycleRequest(t, participantA, "commented rationale", nil, []string{sharedOutputID}, nil, "", "documented rationale", map[string]string{"ticket": "SC-THREAD-DECISION-COMMENT"})))
	commentReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	commentRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(commentRec, commentReq)
	if commentRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, commentRec.Code, commentRec.Body.String())
	}

	var commentResp secureCellResponse
	if err := json.Unmarshal(commentRec.Body.Bytes(), &commentResp); err != nil {
		t.Fatalf("unmarshal comment response: %v", err)
	}
	if commentResp.Result == nil || len(commentResp.Result.Decisions) == 0 || len(commentResp.Result.Decisions[0].Comments) != 1 {
		t.Fatalf("expected comment to be attached to the decision, got %+v", commentResp.Result)
	}
	commentItem := commentResp.Result.Decisions[0].Comments[0]
	if commentItem.Comment != "documented rationale" || commentItem.ActorDID != participantA.AgentID() {
		t.Fatalf("expected decision comment evidence, got %+v", commentItem)
	}

	containReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/contain-outputs", bytes.NewReader(mustMarshalSecureCellDecisionLifecycleRequest(t, owner, "contain decision outputs", nil, []string{sharedOutputID}, nil, "", "contain outputs", map[string]string{"ticket": "SC-THREAD-DECISION-CONTAIN"})))
	containReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	containRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(containRec, containReq)
	if containRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, containRec.Code, containRec.Body.String())
	}

	var containResp secureCellResponse
	if err := json.Unmarshal(containRec.Body.Bytes(), &containResp); err != nil {
		t.Fatalf("unmarshal containment response: %v", err)
	}
	if containResp.Result == nil || containResp.Result.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusOpen {
		t.Fatalf("expected decision status to remain open after output containment, got %+v", containResp.Result)
	}
	if containResp.Result.SharedOutputs[0].ContainmentStatus != securecellsintegration.SecureCellArtifactContainmentStatusContained {
		t.Fatalf("expected shared output to be contained, got %+v", containResp.Result.SharedOutputs[0])
	}
	lastContainTransition := containResp.Result.Transitions[len(containResp.Result.Transitions)-1]
	if got := lastContainTransition.Metadata["related_output_ids"]; got != sharedOutputID {
		t.Fatalf("expected containment metadata to include related output id %q, got %q", sharedOutputID, got)
	}

	releaseReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/release-outputs", bytes.NewReader(mustMarshalSecureCellDecisionLifecycleRequest(t, owner, "release decision outputs", nil, []string{sharedOutputID}, nil, "", "release outputs", map[string]string{"ticket": "SC-THREAD-DECISION-RELEASE"})))
	releaseReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	releaseRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(releaseRec, releaseReq)
	if releaseRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, releaseRec.Code, releaseRec.Body.String())
	}

	var releaseResp secureCellResponse
	if err := json.Unmarshal(releaseRec.Body.Bytes(), &releaseResp); err != nil {
		t.Fatalf("unmarshal release response: %v", err)
	}
	if releaseResp.Result == nil || releaseResp.Result.SharedOutputs[0].ContainmentStatus != securecellsintegration.SecureCellArtifactContainmentStatusReleased {
		t.Fatalf("expected released shared output after release, got %+v", releaseResp.Result)
	}
	lastReleaseTransition := releaseResp.Result.Transitions[len(releaseResp.Result.Transitions)-1]
	if got := lastReleaseTransition.Metadata["release_mode"]; got != "decision_outputs" {
		t.Fatalf("expected release metadata to include decision_outputs mode, got %+v", lastReleaseTransition.Metadata)
	}

	secondApproveReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/approve", bytes.NewReader(mustMarshalSecureCellDecisionLifecycleRequest(t, participantA, "second threshold approval", nil, []string{sharedOutputID}, &threshold, "approve", "second approver vote", map[string]string{"ticket": "SC-THREAD-APPROVAL-THRESHOLD-02"})))
	secondApproveReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	secondApproveRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(secondApproveRec, secondApproveReq)
	if secondApproveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, secondApproveRec.Code, secondApproveRec.Body.String())
	}

	var secondApproveResp secureCellResponse
	if err := json.Unmarshal(secondApproveRec.Body.Bytes(), &secondApproveResp); err != nil {
		t.Fatalf("unmarshal second approval response: %v", err)
	}
	if secondApproveResp.Result == nil || secondApproveResp.Result.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusApproved {
		t.Fatalf("expected approved decision after second thresholded vote, got %+v", secondApproveResp.Result)
	}
}

func TestSecureCellsHandlers_BearerThreadDecisionVoteDelegationAndOutcomeBundleRoutes(t *testing.T) {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	threshold := 2
	decisionCreateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithOptions(t, owner, nil, nil, nil, &threshold, []string{owner.AgentID(), participantA.AgentID(), participantB.AgentID()})))
	decisionCreateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionCreateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionCreateRec, decisionCreateReq)
	if decisionCreateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionCreateRec.Code, decisionCreateRec.Body.String())
	}

	var decisionCreateResp secureCellResponse
	if err := json.Unmarshal(decisionCreateRec.Body.Bytes(), &decisionCreateResp); err != nil {
		t.Fatalf("unmarshal decision create response: %v", err)
	}
	decisionID := decisionCreateResp.Result.Decisions[0].ID

	voteReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/vote", bytes.NewReader(mustMarshalSecureCellDecisionVoteRequest(t, owner, "first deliberation vote", nil, nil, &threshold, "approve", "primary_reviewer", "", map[string]string{"ticket": "SC-THREAD-VOTE-01"})))
	voteReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	voteRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(voteRec, voteReq)
	if voteRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, voteRec.Code, voteRec.Body.String())
	}

	var voteResp secureCellResponse
	if err := json.Unmarshal(voteRec.Body.Bytes(), &voteResp); err != nil {
		t.Fatalf("unmarshal vote response: %v", err)
	}
	if voteResp.Result == nil || voteResp.Result.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusOpen {
		t.Fatalf("expected open decision after vote route, got %+v", voteResp.Result)
	}
	if len(voteResp.Result.Decisions[0].ApprovalVotes) != 1 {
		t.Fatalf("expected one approval vote, got %+v", voteResp.Result.Decisions[0].ApprovalVotes)
	}
	voteItem := voteResp.Result.Decisions[0].ApprovalVotes[0]
	if voteItem.ActorDID != owner.AgentID() {
		t.Fatalf("expected vote actor DID %q, got %+v", owner.AgentID(), voteItem)
	}
	if voteItem.Metadata["decision_vote_choice"] != "approve" || voteItem.Metadata["decision_vote_role"] != "primary_reviewer" {
		t.Fatalf("expected vote metadata to preserve choice and role, got %+v", voteItem.Metadata)
	}

	delegateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/delegate", bytes.NewReader(mustMarshalSecureCellDecisionDelegationRequest(t, owner, "delegate decision ownership", nil, participantA.AgentID(), map[string]string{"ticket": "SC-THREAD-DELEGATE-01"})))
	delegateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	delegateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(delegateRec, delegateReq)
	if delegateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, delegateRec.Code, delegateRec.Body.String())
	}

	escalateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/escalate", bytes.NewReader(mustMarshalSecureCellDecisionEscalationRequest(t, participantA, "escalate decision review", nil, participantB.AgentID(), "board escalation needed", map[string]string{"ticket": "SC-THREAD-ESCALATE-01"})))
	escalateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	escalateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(escalateRec, escalateReq)
	if escalateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, escalateRec.Code, escalateRec.Body.String())
	}

	finalApproveReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/approve", bytes.NewReader(mustMarshalSecureCellDecisionVoteRequest(t, participantA, "second deliberation vote", nil, nil, &threshold, "approve", "secondary_reviewer", "", map[string]string{"ticket": "SC-THREAD-VOTE-02"})))
	finalApproveReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	finalApproveRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(finalApproveRec, finalApproveReq)
	if finalApproveRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, finalApproveRec.Code, finalApproveRec.Body.String())
	}

	var finalApproveResp secureCellResponse
	if err := json.Unmarshal(finalApproveRec.Body.Bytes(), &finalApproveResp); err != nil {
		t.Fatalf("unmarshal final approve response: %v", err)
	}
	if finalApproveResp.Result == nil || finalApproveResp.Result.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusApproved {
		t.Fatalf("expected approved decision after second vote, got %+v", finalApproveResp.Result)
	}

	outcomeBundleReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/outcome-bundles", bytes.NewReader(mustMarshalSecureCellDecisionOutcomeBundleRequest(t, owner, "create outcome bundle", nil, decisionID, "deliberation-summary", "portable", map[string]string{"ticket": "SC-THREAD-BUNDLE-01"})))
	outcomeBundleReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	outcomeBundleRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(outcomeBundleRec, outcomeBundleReq)
	if outcomeBundleRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, outcomeBundleRec.Code, outcomeBundleRec.Body.String())
	}

	var outcomeBundleResp secureCellResponse
	if err := json.Unmarshal(outcomeBundleRec.Body.Bytes(), &outcomeBundleResp); err != nil {
		t.Fatalf("unmarshal outcome bundle response: %v", err)
	}
	if outcomeBundleResp.Result == nil || len(outcomeBundleResp.Result.DecisionOutcomes) == 0 {
		t.Fatalf("expected decision outcome bundle in result, got %+v", outcomeBundleResp.Result)
	}

	outcomeBundleFetchReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/outcome-bundles/fetch", bytes.NewReader(mustMarshalSecureCellDecisionOutcomeBundleRequest(t, owner, "fetch outcome bundle", nil, decisionID, "deliberation-summary", "portable", map[string]string{"ticket": "SC-THREAD-BUNDLE-02"})))
	outcomeBundleFetchReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	outcomeBundleFetchRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(outcomeBundleFetchRec, outcomeBundleFetchReq)
	if outcomeBundleFetchRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, outcomeBundleFetchRec.Code, outcomeBundleFetchRec.Body.String())
	}

	var outcomeBundleFetchResp secureCellResponse
	if err := json.Unmarshal(outcomeBundleFetchRec.Body.Bytes(), &outcomeBundleFetchResp); err != nil {
		t.Fatalf("unmarshal outcome bundle fetch response: %v", err)
	}
	if outcomeBundleFetchResp.Result == nil || len(outcomeBundleFetchResp.Result.DecisionOutcomes) == 0 {
		t.Fatalf("expected fetched decision outcome bundle in result, got %+v", outcomeBundleFetchResp.Result)
	}
}

func TestSecureCellsHandlers_BearerThreadDecisionRejectAbstainAndQueryRoutes(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, ed25519.SeedSize))); err != nil {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID(), participantB.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID(), participantB.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	threshold := 2
	decisionCreateReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithOptions(t, owner, nil, nil, nil, &threshold, []string{owner.AgentID(), participantA.AgentID(), participantB.AgentID()})))
	decisionCreateReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionCreateRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionCreateRec, decisionCreateReq)
	if decisionCreateRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionCreateRec.Code, decisionCreateRec.Body.String())
	}

	var decisionCreateResp secureCellResponse
	if err := json.Unmarshal(decisionCreateRec.Body.Bytes(), &decisionCreateResp); err != nil {
		t.Fatalf("unmarshal decision create response: %v", err)
	}
	if decisionCreateResp.Result == nil || len(decisionCreateResp.Result.Decisions) != 1 {
		t.Fatalf("expected one created decision, got %+v", decisionCreateResp.Result)
	}
	decisionID := decisionCreateResp.Result.Decisions[0].ID

	abstainReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/vote", bytes.NewReader(mustMarshalSecureCellDecisionVoteRequest(t, participantA, "abstain deliberation", nil, nil, &threshold, "abstain", "secondary_reviewer", "abstain pending escalation", map[string]string{"ticket": "SC-THREAD-VOTE-ABSTAIN"})))
	abstainReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	abstainRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(abstainRec, abstainReq)
	if abstainRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, abstainRec.Code, abstainRec.Body.String())
	}

	var abstainResp secureCellResponse
	if err := json.Unmarshal(abstainRec.Body.Bytes(), &abstainResp); err != nil {
		t.Fatalf("unmarshal abstain response: %v", err)
	}
	if abstainResp.Result == nil || abstainResp.Result.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusOpen || len(abstainResp.Result.Decisions[0].ApprovalVotes) != 1 {
		t.Fatalf("expected open decision with one abstain vote, got %+v", abstainResp.Result)
	}
	if abstainResp.Result.Decisions[0].ApprovalVotes[0].Choice != securecellsintegration.SecureCellThreadDecisionVoteChoiceAbstain {
		t.Fatalf("expected persisted abstain vote, got %+v", abstainResp.Result.Decisions[0].ApprovalVotes)
	}

	rejectReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/vote", bytes.NewReader(mustMarshalSecureCellDecisionVoteRequest(t, owner, "reject deliberation", nil, nil, &threshold, "reject", "primary_reviewer", "reject the proposal", map[string]string{"ticket": "SC-THREAD-VOTE-REJECT"})))
	rejectReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	rejectRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(rejectRec, rejectReq)
	if rejectRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, rejectRec.Code, rejectRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", nil)
	listRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, listRec.Code, listRec.Body.String())
	}

	var listResp secureCellDecisionListResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal decision list response: %v", err)
	}
	if len(listResp.Items) != 1 || listResp.Items[0].ID != decisionID {
		t.Fatalf("expected one decision in list response, got %+v", listResp.Items)
	}

	statusReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/status", nil)
	statusRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(statusRec, statusReq)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, statusRec.Code, statusRec.Body.String())
	}

	var statusResp secureCellDecisionQueryResponse
	if err := json.Unmarshal(statusRec.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("unmarshal decision status response: %v", err)
	}
	if statusResp.Result == nil || statusResp.Result.Status != securecellsintegration.SecureCellThreadDecisionStatusQuorumFailed || len(statusResp.Result.ApprovalVotes) != 2 {
		t.Fatalf("expected quorum-failed decision status with two persisted explicit votes, got %+v", statusResp.Result)
	}
	if statusResp.Result.QuorumFailedAt == nil || statusResp.Result.QuorumFailedBy != owner.AgentID() {
		t.Fatalf("expected quorum failure metadata to be persisted, got %+v", statusResp.Result)
	}

	deliberationReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/deliberation", nil)
	deliberationRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(deliberationRec, deliberationReq)
	if deliberationRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, deliberationRec.Code, deliberationRec.Body.String())
	}

	var deliberationResp secureCellDecisionDeliberationResponse
	if err := json.Unmarshal(deliberationRec.Body.Bytes(), &deliberationResp); err != nil {
		t.Fatalf("unmarshal deliberation response: %v", err)
	}
	if deliberationResp.Result == nil || deliberationResp.Result.Status != securecellsintegration.SecureCellThreadDecisionStatusQuorumFailed || len(deliberationResp.Result.ApprovalVotes) != 2 || len(deliberationResp.DecisionOutcomes) != 0 {
		t.Fatalf("expected deliberation projection with persisted dissent and no outcomes, got %+v", deliberationResp)
	}
	if deliberationResp.Result.ApprovalVotes[0].Choice != securecellsintegration.SecureCellThreadDecisionVoteChoiceAbstain || deliberationResp.Result.ApprovalVotes[1].Choice != securecellsintegration.SecureCellThreadDecisionVoteChoiceReject {
		t.Fatalf("expected abstain then reject votes in deliberation projection, got %+v", deliberationResp.Result.ApprovalVotes)
	}

	outcomesReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions/"+decisionID+"/outcomes", nil)
	outcomesRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(outcomesRec, outcomesReq)
	if outcomesRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, outcomesRec.Code, outcomesRec.Body.String())
	}

	var outcomesResp secureCellDecisionOutcomeListResponse
	if err := json.Unmarshal(outcomesRec.Body.Bytes(), &outcomesResp); err != nil {
		t.Fatalf("unmarshal outcomes response: %v", err)
	}
	if len(outcomesResp.Items) != 0 {
		t.Fatalf("expected no decision outcomes yet, got %+v", outcomesResp.Items)
	}

	artifactsReq := httptest.NewRequest(http.MethodGet, secureCellsItemPrefix+cellID+"/artifacts", nil)
	artifactsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(artifactsRec, artifactsReq)
	if artifactsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, artifactsRec.Code, artifactsRec.Body.String())
	}

	var artifactsResp secureCellArtifactsResponse
	if err := json.Unmarshal(artifactsRec.Body.Bytes(), &artifactsResp); err != nil {
		t.Fatalf("unmarshal artifacts response: %v", err)
	}
	if len(artifactsResp.Decisions) != 1 || artifactsResp.Decisions[0].Status != securecellsintegration.SecureCellThreadDecisionStatusQuorumFailed || len(artifactsResp.Decisions[0].ApprovalVotes) != 2 {
		t.Fatalf("expected decision dissent to remain queryable via artifacts projection, got %+v", artifactsResp.Decisions)
	}
}

func TestSecureCellsHandlers_BearerThreadDecisionGovernanceFieldsPassthrough(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{47}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE", "UK"})
	participant := mustSecureCellAppIdentity(t, "reviewer", []string{"UAE", "UK"})

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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participant.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participant.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	deadlineAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	autoEscalation := true
	decisionReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithGovernance(t, owner, &deadlineAt, "board-reviewed-template", &autoEscalation, []string{owner.AgentID(), participant.AgentID()}, map[string]string{"ticket": "SC-DEC-GOV-01"})))
	decisionReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionRec.Code, decisionRec.Body.String())
	}

	var decisionResp secureCellResponse
	if err := json.Unmarshal(decisionRec.Body.Bytes(), &decisionResp); err != nil {
		t.Fatalf("unmarshal decision response: %v", err)
	}
	if decisionResp.Result == nil || len(decisionResp.Result.Decisions) != 1 {
		t.Fatalf("expected one decision result, got %+v", decisionResp.Result)
	}
	decision := decisionResp.Result.Decisions[0]
	if decision.Metadata["decision_deadline_at"] != deadlineAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("expected deadline passthrough in metadata, got %+v", decision.Metadata)
	}
	if decision.Metadata["decision_policy_template"] != "board-reviewed-template" {
		t.Fatalf("expected policy template passthrough in metadata, got %+v", decision.Metadata)
	}
	if decision.Metadata["decision_auto_escalation_enabled"] != "true" {
		t.Fatalf("expected auto escalation passthrough in metadata, got %+v", decision.Metadata)
	}
}

func TestSecureCellsHandlers_BearerThreadDecisionExplicitGovernanceConfiguration(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))); err != nil {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID(), participantB.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	escalationDueAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)
	resolutionDueAt := escalationDueAt.Add(3 * time.Hour)
	decisionReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithExplicitGovernance(t, owner, "dual_control", participantB.AgentID(), &escalationDueAt, &resolutionDueAt, []string{owner.AgentID(), participantA.AgentID()}, map[string]string{"ticket": "SC-DEC-GOV-API-01"})))
	decisionReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionRec.Code, decisionRec.Body.String())
	}

	var decisionResp secureCellResponse
	if err := json.Unmarshal(decisionRec.Body.Bytes(), &decisionResp); err != nil {
		t.Fatalf("unmarshal decision response: %v", err)
	}
	if decisionResp.Result == nil || len(decisionResp.Result.Decisions) != 1 {
		t.Fatalf("expected one decision result, got %+v", decisionResp.Result)
	}
	decision := decisionResp.Result.Decisions[0]
	if decision.GovernanceTemplate != "dual_control" {
		t.Fatalf("expected explicit governance template to reach service, got %+v", decision)
	}
	if len(decision.AllowedVoteChoices) != 2 || decision.AllowedVoteChoices[0] != securecellsintegration.SecureCellThreadDecisionVoteChoiceApprove || decision.AllowedVoteChoices[1] != securecellsintegration.SecureCellThreadDecisionVoteChoiceReject {
		t.Fatalf("expected explicit vote-choice policy, got %+v", decision.AllowedVoteChoices)
	}
	if len(decision.RejectorRoles) != 1 || decision.RejectorRoles[0] != "owner" {
		t.Fatalf("expected explicit rejector roles, got %+v", decision.RejectorRoles)
	}
	if decision.AutoEscalateToDID != participantB.AgentID() || decision.EscalationDueAt == nil || decision.ResolutionDueAt == nil {
		t.Fatalf("expected explicit automation fields on decision, got %+v", decision)
	}
	if !decision.EscalationDueAt.Equal(escalationDueAt) || !decision.ResolutionDueAt.Equal(resolutionDueAt) {
		t.Fatalf("expected explicit due times to survive API mapping, got %+v", decision)
	}
}

func TestSecureCellsHandlers_BearerDecisionAutomationOperatorViews(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, ed25519.SeedSize))); err != nil {
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

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{participantA.AgentID(), participantB.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{participantA.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	now := time.Now().UTC().Truncate(time.Second)
	firstTierDueAt := now.Add(-15 * time.Minute)
	secondTierDueAt := now.Add(45 * time.Minute)
	resolutionDueAt := now.Add(90 * time.Minute)
	ladderReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithEscalationLadder(t, owner, []securecellsintegration.SecureCellDecisionEscalationTier{
		{
			TierID:    "tier_1",
			TargetDID: participantA.AgentID(),
			DueAt:     &firstTierDueAt,
			Reason:    "reviewer-a due",
		},
		{
			TierID:    "tier_2",
			TargetDID: participantB.AgentID(),
			DueAt:     &secondTierDueAt,
			Reason:    "reviewer-b due",
		},
	}, &resolutionDueAt, []string{owner.AgentID(), participantA.AgentID(), participantB.AgentID()}, map[string]string{"ticket": "SC-API-SLA-01"})))
	ladderReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	ladderRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(ladderRec, ladderReq)
	if ladderRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, ladderRec.Code, ladderRec.Body.String())
	}

	var ladderResp secureCellResponse
	if err := json.Unmarshal(ladderRec.Body.Bytes(), &ladderResp); err != nil {
		t.Fatalf("unmarshal ladder decision response: %v", err)
	}
	ladderDecisionID := ladderResp.Result.Decisions[len(ladderResp.Result.Decisions)-1].ID

	closeDueAt := now.Add(-5 * time.Minute)
	closeReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithExplicitGovernance(t, owner, "standard_review", "", nil, &closeDueAt, []string{owner.AgentID(), participantA.AgentID()}, map[string]string{"ticket": "SC-API-SLA-02"})))
	closeReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	closeRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(closeRec, closeReq)
	if closeRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, closeRec.Code, closeRec.Body.String())
	}

	overdueReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/decisions/overdue?cell_id="+cellID+"&before="+url.QueryEscape(now.Format(time.RFC3339Nano)), nil)
	overdueRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(overdueRec, overdueReq)
	if overdueRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, overdueRec.Code, overdueRec.Body.String())
	}
	var overdueResp secureCellOverdueDecisionListResponse
	if err := json.Unmarshal(overdueRec.Body.Bytes(), &overdueResp); err != nil {
		t.Fatalf("unmarshal overdue response: %v", err)
	}
	if len(overdueResp.Items) != 2 {
		t.Fatalf("expected two overdue decisions, got %+v", overdueResp.Items)
	}
	if overdueResp.Items[0].DecisionID != ladderDecisionID || overdueResp.Items[0].TierID != "tier_1" {
		t.Fatalf("expected ladder decision to surface as first overdue item, got %+v", overdueResp.Items)
	}

	overdueExportReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/decisions/overdue/export?cell_id="+cellID+"&before="+url.QueryEscape(now.Format(time.RFC3339Nano))+"&format=csv", nil)
	overdueExportRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(overdueExportRec, overdueExportReq)
	if overdueExportRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, overdueExportRec.Code, overdueExportRec.Body.String())
	}
	if body := overdueExportRec.Body.String(); !strings.Contains(body, "decision_id") || !strings.Contains(body, ladderDecisionID) {
		t.Fatalf("expected overdue csv export to include decision rows, got %s", body)
	}

	if _, err := app.secureCellService.SweepDecisionGovernance(context.Background(), now, securecellsintegration.SecureCellLifecycleRequest{
		ActorDID: "did:aethelred:automation-sweeper",
		Reason:   "automated decision governance sweep",
		Metadata: map[string]string{"ticket": "SC-API-SLA-SWEEP"},
	}); err != nil {
		t.Fatalf("SweepDecisionGovernance failed: %v", err)
	}

	actionsReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/decisions/automation-actions?cell_id="+cellID, nil)
	actionsRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(actionsRec, actionsReq)
	if actionsRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, actionsRec.Code, actionsRec.Body.String())
	}
	var actionsResp secureCellDecisionAutomationActionListResponse
	if err := json.Unmarshal(actionsRec.Body.Bytes(), &actionsResp); err != nil {
		t.Fatalf("unmarshal automation actions response: %v", err)
	}
	if len(actionsResp.Items) != 2 {
		t.Fatalf("expected two automation actions, got %+v", actionsResp.Items)
	}
	if actionsResp.Items[0].TierID == "" && actionsResp.Items[1].TierID == "" {
		t.Fatalf("expected at least one tiered automation action, got %+v", actionsResp.Items)
	}

	actionsExportReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/decisions/automation-actions/export?cell_id="+cellID+"&format=csv", nil)
	actionsExportRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(actionsExportRec, actionsExportReq)
	if actionsExportRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, actionsExportRec.Code, actionsExportRec.Body.String())
	}
	if body := actionsExportRec.Body.String(); !strings.Contains(body, "transition_id") || !strings.Contains(body, "secure_cell.session_thread_decision_") {
		t.Fatalf("expected automation csv export to include action rows, got %s", body)
	}
}

func TestSecureCellsHandlers_BearerDecisionSLATemplateCatalogAndFinancePack(t *testing.T) {
	app := newAuditEnabledTestApp(t, sims.AppOptionsMap{
		"aethelred.pqc.mode":                     "simulated",
		"aethelred.secure_cells.api.write_token": "secure-cells-secret",
		flags.FlagHome:                           t.TempDir(),
	})
	if err := app.SetValidatorPrivateKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, ed25519.SeedSize))); err != nil {
		t.Fatalf("SetValidatorPrivateKey failed: %v", err)
	}

	owner := mustSecureCellAppIdentity(t, "owner", []string{"UAE"})
	reviewer := mustSecureCellAppIdentity(t, "treasury-reviewer", []string{"UAE"})
	manager := mustSecureCellAppIdentity(t, "treasury-manager", []string{"UAE"})
	compliance := mustSecureCellAppIdentity(t, "compliance-officer", []string{"UAE"})

	createReq := httptest.NewRequest(http.MethodPost, secureCellsCollectionRoute, bytes.NewReader(mustMarshalSecureCellCreateRequestWithParticipantRoles(t, owner, []securecellsintegration.SecureCellParticipant{
		{Identity: reviewer, Role: "treasury_reviewer"},
		{Identity: manager, Role: "treasury_manager"},
		{Identity: compliance, Role: "compliance_officer"},
	}, nil)))
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

	catalogReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/decision-sla-templates?sector_policy_pack=finance", nil)
	catalogRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(catalogRec, catalogReq)
	if catalogRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, catalogRec.Code, catalogRec.Body.String())
	}
	var catalogResp secureCellDecisionSLATemplateListResponse
	if err := json.Unmarshal(catalogRec.Body.Bytes(), &catalogResp); err != nil {
		t.Fatalf("unmarshal SLA template catalog response: %v", err)
	}
	if len(catalogResp.Items) < 2 || catalogResp.Items[0].SectorPolicyPack != "finance" {
		t.Fatalf("expected finance SLA catalog entries, got %+v", catalogResp.Items)
	}
	if catalogResp.Items[0].ID != "finance_payment_release" {
		t.Fatalf("expected finance payment release template first, got %+v", catalogResp.Items[0])
	}

	catalogExportReq := httptest.NewRequest(http.MethodGet, secureCellsCollectionRoute+"/decision-sla-templates/export?sector_policy_pack=finance&format=csv", nil)
	catalogExportRec := httptest.NewRecorder()
	app.SecureCellsGetHandler().ServeHTTP(catalogExportRec, catalogExportReq)
	if catalogExportRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, catalogExportRec.Code, catalogExportRec.Body.String())
	}
	if body := catalogExportRec.Body.String(); !strings.Contains(body, "finance_payment_release") || !strings.Contains(body, "sector_policy_pack") {
		t.Fatalf("expected SLA template csv export to include finance template rows, got %s", body)
	}

	startReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions", bytes.NewReader(mustMarshalSecureCellSessionStartRequestWithParticipants(t, nil, nil, []string{reviewer.AgentID()})))
	startReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	startRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, startRec.Code, startRec.Body.String())
	}

	var startResp secureCellResponse
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("unmarshal session start response: %v", err)
	}
	sessionID := startResp.Result.Sessions[0].ID

	threadStartReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads", bytes.NewReader(mustMarshalSecureCellSessionThreadStartRequest(t, owner, nil, []string{reviewer.AgentID()})))
	threadStartReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	threadStartRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(threadStartRec, threadStartReq)
	if threadStartRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, threadStartRec.Code, threadStartRec.Body.String())
	}

	var threadStartResp secureCellResponse
	if err := json.Unmarshal(threadStartRec.Body.Bytes(), &threadStartResp); err != nil {
		t.Fatalf("unmarshal thread start response: %v", err)
	}
	threadID := threadStartResp.Result.Threads[0].ID

	decisionReq := httptest.NewRequest(http.MethodPost, secureCellsItemPrefix+cellID+"/sessions/"+sessionID+"/threads/"+threadID+"/decisions", bytes.NewReader(mustMarshalSecureCellThreadDecisionRequestWithSLATemplate(t, owner, "", "finance", []string{owner.AgentID(), reviewer.AgentID()}, map[string]string{"ticket": "SC-API-SLA-PACK-01"})))
	decisionReq.Header.Set("Authorization", "Bearer secure-cells-secret")
	decisionRec := httptest.NewRecorder()
	app.SecureCellsMutateHandler().ServeHTTP(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d body=%s", http.StatusOK, decisionRec.Code, decisionRec.Body.String())
	}

	var decisionResp secureCellResponse
	if err := json.Unmarshal(decisionRec.Body.Bytes(), &decisionResp); err != nil {
		t.Fatalf("unmarshal SLA-pack decision response: %v", err)
	}
	if decisionResp.Result == nil || len(decisionResp.Result.Decisions) != 1 {
		t.Fatalf("expected one decision result, got %+v", decisionResp.Result)
	}
	decision := decisionResp.Result.Decisions[0]
	if decision.GovernanceTemplate != "dual_control" || decision.SLATemplate != "finance_payment_release" || decision.SectorPolicyPack != "finance" {
		t.Fatalf("expected finance SLA pack defaults to reach the decision, got %+v", decision)
	}
	if len(decision.EscalationLadder) != 2 || decision.EscalationLadder[0].TargetDID != manager.AgentID() || decision.EscalationLadder[1].TargetDID != compliance.AgentID() {
		t.Fatalf("expected finance SLA escalation targets to resolve, got %+v", decision.EscalationLadder)
	}
	if decision.ResolutionDueAt == nil || !decision.ResolutionDueAt.After(decision.ProposedAt) {
		t.Fatalf("expected SLA-derived resolution deadline, got %+v", decision)
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

type secureCellDecisionGovernanceSweepStub struct {
	called    bool
	at        time.Time
	lifecycle securecellsintegration.SecureCellLifecycleRequest
}

func (s *secureCellDecisionGovernanceSweepStub) SweepDecisionGovernance(_ context.Context, at time.Time, lifecycle securecellsintegration.SecureCellLifecycleRequest) (string, error) {
	s.called = true
	s.at = at.UTC()
	s.lifecycle = lifecycle
	return "decision-governance-sweep-complete", nil
}

func TestInvokeSecureCellDecisionGovernanceSweep_UsesOptionalServiceMethod(t *testing.T) {
	stub := &secureCellDecisionGovernanceSweepStub{}
	at := time.Date(2026, 4, 16, 8, 0, 0, 0, time.UTC)
	lifecycle := securecellsintegration.SecureCellLifecycleRequest{
		ActorDID: secureCellAutomatedSweepActor,
		Reason:   "automated decision governance sweep",
		Metadata: map[string]string{
			"sweep_mode":      "automated",
			"workflow":        "secure_cell",
			"automation_mode": "decision_governance",
		},
	}

	result, ok, err := invokeSecureCellDecisionGovernanceSweep(stub, at, lifecycle)
	if err != nil {
		t.Fatalf("invokeSecureCellDecisionGovernanceSweep returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected sweep hook to report a callable method")
	}
	if !stub.called {
		t.Fatal("expected sweep stub to be invoked")
	}
	if stub.at != at {
		t.Fatalf("expected sweep at %s, got %s", at, stub.at)
	}
	if stub.lifecycle.ActorDID != secureCellAutomatedSweepActor || stub.lifecycle.Reason != lifecycle.Reason {
		t.Fatalf("unexpected lifecycle passed to sweep hook: %+v", stub.lifecycle)
	}
	if result != "decision-governance-sweep-complete" {
		t.Fatalf("unexpected sweep result: %#v", result)
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

func mustMarshalSecureCellFederationInviteRequest(t *testing.T, actor *agent.AgentIdentity, participant *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt) []byte {
	t.Helper()
	jurisdiction := ""
	if len(participant.JurisdictionTags) > 0 {
		jurisdiction = participant.JurisdictionTags[0]
	}
	body, err := json.Marshal(secureCellFederationInviteRequest{
		ActorIdentity:    mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:    receipt,
		SponsorOfRecord:  participant.Liability.SponsorOfRecord,
		OrganizationName: participant.Liability.BusinessUnit,
		Jurisdiction:     jurisdiction,
		ExpectedDID:      participant.AgentID(),
		Role:             "federated_participant",
		Reason:           "cross-org collaboration invite",
		Metadata:         map[string]string{"ticket": "SC-FED-API-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell federation invite request: %v", err)
	}
	return body
}

func mustMarshalSecureCellFederationAcceptRequest(t *testing.T, actor *agent.AgentIdentity, invitationID string, participant *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellFederationAcceptRequest{
		ActorIdentity: mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt: receipt,
		InvitationID:  invitationID,
		Participant: securecellsintegration.SecureCellParticipant{
			Identity: participant,
			Role:     "federated_participant",
			Metadata: map[string]string{"bank": "federated"},
		},
		Reason:   "join approved secure cell",
		Metadata: map[string]string{"ticket": "SC-FED-API-02"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell federation accept request: %v", err)
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

func mustMarshalSecureCellDecisionLifecycleRequest(t *testing.T, actor *agent.AgentIdentity, reason string, receipt *policy.SignedPolicyReceipt, relatedOutputIDs []string, approvalThreshold *int, approvalVote string, comment string, metadata map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellLifecycleRequest{
		ActorIdentity:     mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:     receipt,
		Reason:            reason,
		Comment:           comment,
		RelatedOutputIDs:  relatedOutputIDs,
		ApprovalThreshold: approvalThreshold,
		ApprovalVote:      approvalVote,
		Metadata:          metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell decision lifecycle request: %v", err)
	}
	return body
}

func mustMarshalSecureCellDecisionVoteRequest(t *testing.T, actor *agent.AgentIdentity, reason string, receipt *policy.SignedPolicyReceipt, relatedOutputIDs []string, approvalThreshold *int, voteChoice string, voteRole string, comment string, metadata map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellLifecycleRequest{
		ActorIdentity:     mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:     receipt,
		Reason:            reason,
		Comment:           comment,
		RelatedOutputIDs:  relatedOutputIDs,
		ApprovalThreshold: approvalThreshold,
		ApprovalVote:      voteChoice,
		VoteChoice:        voteChoice,
		VoteRole:          voteRole,
		Metadata:          metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell decision vote request: %v", err)
	}
	return body
}

func mustMarshalSecureCellDecisionDelegationRequest(t *testing.T, actor *agent.AgentIdentity, reason string, receipt *policy.SignedPolicyReceipt, delegatedToDID string, metadata map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellLifecycleRequest{
		ActorIdentity:  mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:  receipt,
		Reason:         reason,
		DelegatedToDID: delegatedToDID,
		Metadata:       metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell decision delegation request: %v", err)
	}
	return body
}

func mustMarshalSecureCellDecisionEscalationRequest(t *testing.T, actor *agent.AgentIdentity, reason string, receipt *policy.SignedPolicyReceipt, delegatedToDID string, escalationReason string, metadata map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellLifecycleRequest{
		ActorIdentity:    mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:    receipt,
		Reason:           reason,
		DelegatedToDID:   delegatedToDID,
		EscalationReason: escalationReason,
		Metadata:         metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell decision escalation request: %v", err)
	}
	return body
}

func mustMarshalSecureCellDecisionOutcomeBundleRequest(t *testing.T, actor *agent.AgentIdentity, reason string, receipt *policy.SignedPolicyReceipt, decisionID string, bundleName string, bundleType string, metadata map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellLifecycleRequest{
		ActorIdentity:     mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:     receipt,
		Reason:            reason,
		OutcomeBundleID:   decisionID,
		OutcomeBundleName: bundleName,
		OutcomeBundleType: bundleType,
		Metadata:          metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell decision outcome bundle request: %v", err)
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

func mustMarshalSecureCellSessionThreadStartRequest(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, participantDIDs []string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellSessionThreadStartRequest{
		ActorIdentity:   mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:   receipt,
		Name:            "Escalation Thread",
		Purpose:         "targeted substream",
		ParticipantDIDs: participantDIDs,
		DataClasses:     []string{"confidential"},
		Reason:          "thread opened",
		Metadata:        map[string]string{"ticket": "SC-THREAD-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell session thread start request: %v", err)
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

func mustMarshalSecureCellThreadMessageRequest(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, recipients []string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellThreadMessageRequest{
		ActorIdentity:  mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:  receipt,
		Name:           "Escalation Update",
		ExchangeType:   "message",
		Classification: "confidential",
		Resource:       "secure-cell:thread:message:update",
		Summary:        "thread-scoped update",
		Recipients:     recipients,
		Reason:         "thread exchange sent",
		Metadata:       map[string]string{"ticket": "SC-THREAD-MSG-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell thread message request: %v", err)
	}
	return body
}

func mustMarshalSecureCellThreadDecisionRequest(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, relatedExchangeIDs []string) []byte {
	return mustMarshalSecureCellThreadDecisionRequestWithOptions(t, actor, receipt, relatedExchangeIDs, nil, nil, nil)
}

func mustMarshalSecureCellThreadDecisionRequestWithOptions(t *testing.T, actor *agent.AgentIdentity, receipt *policy.SignedPolicyReceipt, relatedExchangeIDs []string, relatedOutputIDs []string, approvalThreshold *int, eligibleApproverDIDs []string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellThreadDecisionRequest{
		ActorIdentity:        mustOptionalJSONRawMessage(t, actor),
		PolicyReceipt:        receipt,
		Title:                "Freeze Counterparty Exposure",
		Summary:              "temporary trading freeze required",
		Classification:       "confidential",
		ApprovalThreshold:    approvalThreshold,
		EligibleApproverDIDs: eligibleApproverDIDs,
		RelatedExchangeIDs:   relatedExchangeIDs,
		RelatedOutputIDs:     relatedOutputIDs,
		Reason:               "decision proposed",
		Metadata:             map[string]string{"ticket": "SC-THREAD-DECIDE-01"},
	})
	if err != nil {
		t.Fatalf("marshal secure cell thread decision request: %v", err)
	}
	return body
}

func mustMarshalSecureCellThreadDecisionRequestWithGovernance(t *testing.T, actor *agent.AgentIdentity, deadlineAt *time.Time, policyTemplate string, autoEscalation *bool, eligibleApproverDIDs []string, metadata map[string]string) []byte {
	t.Helper()
	approvalThreshold := 2
	body, err := json.Marshal(secureCellThreadDecisionRequest{
		ActorIdentity:        mustOptionalJSONRawMessage(t, actor),
		Title:                "Decision Governance",
		Summary:              "governance-aware decision request",
		Classification:       "confidential",
		ApprovalThreshold:    &approvalThreshold,
		EligibleApproverDIDs: eligibleApproverDIDs,
		DeadlineAt:           deadlineAt,
		PolicyTemplate:       policyTemplate,
		AutoEscalation:       autoEscalation,
		Reason:               "decision proposed",
		Metadata:             metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell thread decision governance request: %v", err)
	}
	return body
}

func mustMarshalSecureCellThreadDecisionRequestWithExplicitGovernance(t *testing.T, actor *agent.AgentIdentity, governanceTemplate string, autoEscalateToDID string, escalationDueAt *time.Time, resolutionDueAt *time.Time, eligibleApproverDIDs []string, metadata map[string]string) []byte {
	t.Helper()
	approvalThreshold := 2
	body, err := json.Marshal(secureCellThreadDecisionRequest{
		ActorIdentity:        mustOptionalJSONRawMessage(t, actor),
		Title:                "Decision Governance",
		Summary:              "explicit governance-aware decision request",
		Classification:       "confidential",
		GovernanceTemplate:   governanceTemplate,
		ApprovalThreshold:    &approvalThreshold,
		EligibleApproverDIDs: eligibleApproverDIDs,
		AllowedVoteChoices: []securecellsintegration.SecureCellThreadDecisionVoteChoice{
			securecellsintegration.SecureCellThreadDecisionVoteChoiceApprove,
			securecellsintegration.SecureCellThreadDecisionVoteChoiceReject,
		},
		RejectorRoles:     []string{"owner"},
		ReopenRoles:       []string{"owner"},
		AutoEscalateToDID: autoEscalateToDID,
		EscalationDueAt:   escalationDueAt,
		ResolutionDueAt:   resolutionDueAt,
		Reason:            "decision proposed",
		Metadata:          metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell thread decision explicit governance request: %v", err)
	}
	return body
}

func mustMarshalSecureCellThreadDecisionRequestWithEscalationLadder(t *testing.T, actor *agent.AgentIdentity, ladder []securecellsintegration.SecureCellDecisionEscalationTier, resolutionDueAt *time.Time, eligibleApproverDIDs []string, metadata map[string]string) []byte {
	t.Helper()
	approvalThreshold := 2
	body, err := json.Marshal(secureCellThreadDecisionRequest{
		ActorIdentity:        mustOptionalJSONRawMessage(t, actor),
		Title:                "Tiered Decision Governance",
		Summary:              "tiered sla and escalation ladder",
		Classification:       "confidential",
		GovernanceTemplate:   "standard_review",
		ApprovalThreshold:    &approvalThreshold,
		EligibleApproverDIDs: eligibleApproverDIDs,
		EscalationLadder:     ladder,
		ResolutionDueAt:      resolutionDueAt,
		Reason:               "decision proposed",
		Metadata:             metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell thread decision escalation ladder request: %v", err)
	}
	return body
}

func mustMarshalSecureCellThreadDecisionRequestWithSLATemplate(t *testing.T, actor *agent.AgentIdentity, slaTemplate string, sectorPolicyPack string, eligibleApproverDIDs []string, metadata map[string]string) []byte {
	t.Helper()
	body, err := json.Marshal(secureCellThreadDecisionRequest{
		ActorIdentity:        mustOptionalJSONRawMessage(t, actor),
		Title:                "Treasury Release Decision",
		Summary:              "use sector SLA defaults",
		Classification:       "confidential",
		SLATemplate:          slaTemplate,
		SectorPolicyPack:     sectorPolicyPack,
		EligibleApproverDIDs: eligibleApproverDIDs,
		Reason:               "decision proposed",
		Metadata:             metadata,
	})
	if err != nil {
		t.Fatalf("marshal secure cell thread decision SLA-template request: %v", err)
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

func mustMarshalSecureCellCreateRequestWithParticipantRoles(t *testing.T, owner *agent.AgentIdentity, participants []securecellsintegration.SecureCellParticipant, receipt *policy.SignedPolicyReceipt) []byte {
	t.Helper()

	requireConfidentialCompute := true
	body, err := json.Marshal(secureCellCreateRequest{
		Identity:      mustJSONRawMessage(t, owner),
		PolicyReceipt: receipt,
		Name:          "Joint Review Cell",
		Purpose:       "regulated collaboration",
		Resource:      secureCellsAuthDefaultResource,
		Jurisdiction:  "UAE",
		Participants:  append([]securecellsintegration.SecureCellParticipant(nil), participants...),
		Policy: securecellsintegration.SecureCellPolicy{
			DataClasses:                []string{"confidential"},
			ComputeZones:               []string{"uae-enclave"},
			RequireConfidentialCompute: &requireConfidentialCompute,
		},
	})
	if err != nil {
		t.Fatalf("marshal secure cell create request with participant roles: %v", err)
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
