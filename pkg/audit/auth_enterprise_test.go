package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/evidence"
	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
)

func TestEnterpriseControlLedgerWriteAuthorizer_AuthorizeAndEnrich(t *testing.T) {
	req, trustedSigners := newEnterpriseWriteRequest(t, "enterprise-ledger-001")
	authorizer, err := NewEnterpriseControlLedgerWriteAuthorizer(EnterpriseControlLedgerWriteConfig{
		TrustedPolicySigners: trustedSigners,
		RequiredJurisdiction: "UAE",
		AllowedSponsors:      []string{"did:aethelred:sponsor-bank"},
	})
	if err != nil {
		t.Fatalf("new enterprise authorizer: %v", err)
	}

	if err := authorizer.Authorize(nil, req); err != nil {
		t.Fatalf("authorize enterprise write: %v", err)
	}

	if len(req.Ledger.Bundle.AgentPassports) != 1 {
		t.Fatalf("expected 1 passport injected into ledger, got %d", len(req.Ledger.Bundle.AgentPassports))
	}
	if len(req.Ledger.Bundle.PolicyReceipts) != 1 {
		t.Fatalf("expected 1 policy receipt injected into ledger, got %d", len(req.Ledger.Bundle.PolicyReceipts))
	}
	if req.Ledger.Metadata["auth.mode"] != "enterprise_policy_receipt" {
		t.Fatalf("expected auth.mode metadata to be set, got %q", req.Ledger.Metadata["auth.mode"])
	}
	if req.Ledger.Metadata["auth.sponsor_of_record"] != "did:aethelred:sponsor-bank" {
		t.Fatalf("expected sponsor metadata to be set, got %q", req.Ledger.Metadata["auth.sponsor_of_record"])
	}
	if req.Ledger.Metadata["auth.trust_source"] != "startup_config" {
		t.Fatalf("expected trust source metadata to be set, got %q", req.Ledger.Metadata["auth.trust_source"])
	}
	if req.Ledger.Metadata["auth.trust_registry_version"] != "bootstrap-static-config" {
		t.Fatalf("expected trust registry version metadata to be set, got %q", req.Ledger.Metadata["auth.trust_registry_version"])
	}
	if req.Ledger.Metadata["auth.policy_signer_status"] != string(TrustRegistryEntryStatusActive) {
		t.Fatalf("expected policy signer status metadata to be set, got %q", req.Ledger.Metadata["auth.policy_signer_status"])
	}
	if req.Ledger.Metadata["auth.sponsor_status"] != string(TrustRegistryEntryStatusActive) {
		t.Fatalf("expected sponsor status metadata to be set, got %q", req.Ledger.Metadata["auth.sponsor_status"])
	}

	store := evidence.NewInMemoryControlLedgerStore()
	if err := store.Save(context.Background(), req.Ledger); err != nil {
		t.Fatalf("save authorized ledger: %v", err)
	}
}

func TestEnterpriseControlLedgerWriteAuthorizer_RejectsRevokedSignerFromTrustSource(t *testing.T) {
	req, trustedSigners := newEnterpriseWriteRequest(t, "enterprise-ledger-revoked-signer")
	trustSource, err := newStaticTrustSourceForTest(trustedSigners, []string{"did:aethelred:sponsor-bank"}, func(snapshot *EnterpriseControlLedgerTrustSnapshot) {
		entry := snapshot.PolicySigners["did:aethelred:policy-gateway-1"]
		entry.Status = TrustRegistryEntryStatusRevoked
		snapshot.PolicySigners["did:aethelred:policy-gateway-1"] = entry
		snapshot.Source = "test_registry"
		snapshot.Version = "2026.04.14"
	})
	if err != nil {
		t.Fatalf("new trust source: %v", err)
	}

	authorizer, err := NewEnterpriseControlLedgerWriteAuthorizer(EnterpriseControlLedgerWriteConfig{
		TrustSource: trustSource,
	})
	if err != nil {
		t.Fatalf("new enterprise authorizer: %v", err)
	}

	err = authorizer.Authorize(nil, req)
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected revoked signer authorization failure, got %v", err)
	}
}

func TestEnterpriseControlLedgerWriteAuthorizer_RejectsDisallowedSponsor(t *testing.T) {
	req, trustedSigners := newEnterpriseWriteRequest(t, "enterprise-ledger-002")
	authorizer, err := NewEnterpriseControlLedgerWriteAuthorizer(EnterpriseControlLedgerWriteConfig{
		TrustedPolicySigners: trustedSigners,
		RequiredJurisdiction: "UAE",
		AllowedSponsors:      []string{"did:aethelred:other-sponsor"},
	})
	if err != nil {
		t.Fatalf("new enterprise authorizer: %v", err)
	}

	err = authorizer.Authorize(nil, req)
	if err == nil || !strings.Contains(err.Error(), "sponsor_of_record") {
		t.Fatalf("expected sponsor authorization failure, got %v", err)
	}
}

func TestAuditServer_PostControlLedgerAcceptsEnterpriseAuthorization(t *testing.T) {
	server := NewAuditServer(nil, nil)
	req, trustedSigners := newEnterpriseWriteRequest(t, "enterprise-ledger-003")
	authorizer, err := NewEnterpriseControlLedgerWriteAuthorizer(EnterpriseControlLedgerWriteConfig{
		TrustedPolicySigners: trustedSigners,
		RequiredJurisdiction: "UAE",
		AllowedSponsors:      []string{"did:aethelred:sponsor-bank"},
	})
	if err != nil {
		t.Fatalf("new enterprise authorizer: %v", err)
	}
	server.SetControlLedgerWriteAuthorizer(authorizer)

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/audit/control-ledgers", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httpReq)

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
	if resp.Ledger.Metadata["auth.actor_did"] == "" || resp.Ledger.Metadata["auth.policy_receipt_id"] == "" {
		t.Fatal("expected enterprise authorization metadata in persisted ledger")
	}
}

func newEnterpriseWriteRequest(t *testing.T, ledgerID string) (*PutControlLedgerRequest, map[string]string) {
	t.Helper()

	actorIdentity, _, err := agent.NewEnterpriseAgentIdentity(
		[]agent.Capability{{Name: defaultEnterpriseControlLedgerWriteAction, Version: "1.0"}},
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
			AllowedTools:     []string{defaultEnterpriseControlLedgerWriteAction},
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
			Action:   defaultEnterpriseControlLedgerWriteAction,
			Resource: "control-ledger:" + ledgerID,
			Context: map[string]string{
				"jurisdiction": "UAE",
			},
			Metadata: map[string]string{
				"sponsor_of_record": "did:aethelred:sponsor-bank",
			},
		},
		&policy.EvaluationResult{
			Decision:    policy.Allow,
			AuditTrail:  "policy-write-trace",
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
		ControlName: "Enterprise Ledger Ingestion",
		Status:      evidence.ControlSatisfied,
		Description: "Authorizes a control-ledger write with enterprise passport and policy receipt.",
		EvidenceRefs: evidence.ControlEvidenceRefs{
			RecordIDs: []string{"record-" + ledgerID},
		},
	}); err != nil {
		t.Fatalf("add control: %v", err)
	}

	signerPublicKeyHex := hex.EncodeToString(elliptic.MarshalCompressed(signerKey.PublicKey.Curve, signerKey.PublicKey.X, signerKey.PublicKey.Y))

	return &PutControlLedgerRequest{
			Ledger: ledger,
			EnterpriseAuth: &EnterpriseControlLedgerWriteAuthz{
				ActorIdentity: actorIdentity,
				PolicyReceipt: receipt,
			},
		}, map[string]string{
			"did:aethelred:policy-gateway-1": signerPublicKeyHex,
		}
}

func newStaticTrustSourceForTest(trustedSigners map[string]string, allowedSponsors []string, mutate func(snapshot *EnterpriseControlLedgerTrustSnapshot)) (*StaticEnterpriseControlLedgerTrustSource, error) {
	cfg := EnterpriseControlLedgerWriteConfig{
		TrustedPolicySigners: trustedSigners,
		RequiredJurisdiction: "UAE",
		AllowedSponsors:      allowedSponsors,
	}
	source, err := newEnterpriseControlLedgerTrustSourceFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	staticSource, ok := source.(*StaticEnterpriseControlLedgerTrustSource)
	if !ok {
		return nil, ErrInvalidInput
	}
	snapshot, err := staticSource.Snapshot(context.Background())
	if err != nil {
		return nil, err
	}
	if mutate != nil {
		mutate(snapshot)
	}
	return NewStaticEnterpriseControlLedgerTrustSource(snapshot)
}
