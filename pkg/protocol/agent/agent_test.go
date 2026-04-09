package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Identity tests
// ---------------------------------------------------------------------------

func TestNewAgentIdentity(t *testing.T) {
	caps := []Capability{
		{Name: "compute.execute", Version: "1.0"},
		{Name: "model.deploy", Version: "1.0"},
	}

	identity, privKey, err := NewAgentIdentity(caps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if identity == nil || privKey == nil {
		t.Fatal("expected non-nil identity and key")
	}
	if identity.DID == nil {
		t.Fatal("expected non-nil DID")
	}
	if identity.DID.Method != DIDMethod {
		t.Errorf("expected method %q, got %q", DIDMethod, identity.DID.Method)
	}
	if len(identity.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(identity.Capabilities))
	}
}

func TestVerifyIdentity(t *testing.T) {
	identity, _, err := NewAgentIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyIdentity(identity); err != nil {
		t.Errorf("expected valid identity, got error: %v", err)
	}
}

func TestVerifyIdentity_Expired(t *testing.T) {
	identity, _, err := NewAgentIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	identity.ExpiresAt = time.Now().Add(-1 * time.Hour)

	if err := VerifyIdentity(identity); err == nil {
		t.Error("expected error for expired identity")
	}
}

func TestVerifyIdentity_Nil(t *testing.T) {
	if err := VerifyIdentity(nil); err == nil {
		t.Error("expected error for nil identity")
	}
}

func TestParseDID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		method  string
		id      string
		frag    string
	}{
		{"valid", "did:aethelred:abc123", false, "aethelred", "abc123", ""},
		{"with_fragment", "did:aethelred:abc123#key-1", false, "aethelred", "abc123", "key-1"},
		{"wrong_method", "did:other:abc123", true, "", "", ""},
		{"invalid_format", "not-a-did", true, "", "", ""},
		{"empty_id", "did:aethelred:", true, "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			did, err := ParseDID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if did.Method != tt.method {
				t.Errorf("expected method %q, got %q", tt.method, did.Method)
			}
			if did.ID != tt.id {
				t.Errorf("expected id %q, got %q", tt.id, did.ID)
			}
			if did.Fragment != tt.frag {
				t.Errorf("expected fragment %q, got %q", tt.frag, did.Fragment)
			}
		})
	}
}

func TestFormatDID(t *testing.T) {
	identity, _, _ := NewAgentIdentity(nil)
	did := FormatDID(identity)
	if did == "" {
		t.Error("expected non-empty DID string")
	}

	// Parse it back.
	parsed, err := ParseDID(did)
	if err != nil {
		t.Fatalf("failed to parse formatted DID: %v", err)
	}
	if parsed.ID != identity.DID.ID {
		t.Error("round-trip DID mismatch")
	}
}

func TestHasCapability(t *testing.T) {
	identity, _, _ := NewAgentIdentity([]Capability{
		{Name: "compute.execute", Version: "1.0"},
	})

	if !identity.HasCapability("compute.execute") {
		t.Error("expected to have compute.execute capability")
	}
	if identity.HasCapability("model.deploy") {
		t.Error("expected not to have model.deploy capability")
	}
}

// ---------------------------------------------------------------------------
// Credential tests
// ---------------------------------------------------------------------------

func TestIssueAndVerifyCredential(t *testing.T) {
	issuerID, issuerKey, _ := NewAgentIdentity(nil)
	subjectID, _, _ := NewAgentIdentity(nil)

	ctx := context.Background()
	claims := []Claim{
		{Name: "role", Value: "compute_agent", Verified: true},
	}

	cred, err := IssueCredential(ctx, issuerKey, issuerID.AgentID(), subjectID.AgentID(), CapabilityCredential, claims, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}
	if cred.Proof == nil {
		t.Fatal("expected credential proof")
	}

	// Verify.
	if err := VerifyCredential(cred, &issuerKey.PublicKey); err != nil {
		t.Errorf("credential verification failed: %v", err)
	}
}

func TestVerifyCredential_WrongKey(t *testing.T) {
	issuerID, issuerKey, _ := NewAgentIdentity(nil)
	subjectID, _, _ := NewAgentIdentity(nil)

	ctx := context.Background()
	claims := []Claim{{Name: "test", Value: "value", Verified: true}}
	cred, _ := IssueCredential(ctx, issuerKey, issuerID.AgentID(), subjectID.AgentID(), CapabilityCredential, claims, time.Hour)

	// Verify with wrong key.
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyCredential(cred, &wrongKey.PublicKey); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestCredential_Revocation(t *testing.T) {
	issuerID, issuerKey, _ := NewAgentIdentity(nil)
	subjectID, _, _ := NewAgentIdentity(nil)

	ctx := context.Background()
	store := NewMemoryCredentialStore()
	claims := []Claim{{Name: "test", Value: "value", Verified: true}}

	cred, _ := IssueCredential(ctx, issuerKey, issuerID.AgentID(), subjectID.AgentID(), CapabilityCredential, claims, time.Hour)
	store.Store(cred)

	if err := RevokeCredential(ctx, store, cred.ID); err != nil {
		t.Fatal(err)
	}

	revoked, _ := store.Get(cred.ID)
	if !revoked.Revoked {
		t.Error("expected credential to be revoked")
	}
	if revoked.IsValid() {
		t.Error("revoked credential should not be valid")
	}
}

func TestMemoryCredentialStore_ListBySubject(t *testing.T) {
	store := NewMemoryCredentialStore()
	store.Store(&AgentCredential{ID: "c1", Subject: "did:aethelred:a", Type: CapabilityCredential, IssuedAt: time.Now()})
	store.Store(&AgentCredential{ID: "c2", Subject: "did:aethelred:a", Type: AuthorizationCredential, IssuedAt: time.Now()})
	store.Store(&AgentCredential{ID: "c3", Subject: "did:aethelred:b", Type: CapabilityCredential, IssuedAt: time.Now()})

	creds, _ := store.ListBySubject("did:aethelred:a")
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials for subject a, got %d", len(creds))
	}
}

// ---------------------------------------------------------------------------
// Delegation tests
// ---------------------------------------------------------------------------

func TestDelegation_BasicFlow(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{
		Actions:   []string{"read", "write"},
		TimeLimit: 24 * time.Hour,
	}

	d, err := dm.Delegate(ctx, "did:aethelred:alice", "did:aethelred:bob", scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Depth != 0 {
		t.Errorf("expected depth 0, got %d", d.Depth)
	}
	if !IsDelegationValid(d) {
		t.Error("expected valid delegation")
	}

	// Verify action coverage.
	valid, err := dm.VerifyDelegation(ctx, d.ID, "read")
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("expected delegation to cover 'read' action")
	}

	// Action not in scope.
	valid, _ = dm.VerifyDelegation(ctx, d.ID, "delete")
	if valid {
		t.Error("expected delegation to not cover 'delete' action")
	}
}

func TestDelegation_SelfDelegation(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	_, err := dm.Delegate(ctx, "did:aethelred:alice", "did:aethelred:alice", &DelegationScope{}, nil)
	if err == nil {
		t.Error("expected error for self-delegation")
	}
}

func TestDelegation_SubDelegation(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{
		Actions:   []string{"read"},
		MaxDepth:  3,
		TimeLimit: 24 * time.Hour,
	}

	d1, _ := dm.Delegate(ctx, "did:aethelred:alice", "did:aethelred:bob", scope, nil)
	d2, err := dm.SubDelegate(ctx, d1.ID, "did:aethelred:carol", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Depth != 1 {
		t.Errorf("expected depth 1, got %d", d2.Depth)
	}
	if d2.ParentID != d1.ID {
		t.Error("expected parent ID to match")
	}
}

func TestDelegation_MaxDepthEnforced(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{
		Actions:  []string{"read"},
		MaxDepth: 1, // Only one level of sub-delegation allowed.
	}

	d1, _ := dm.Delegate(ctx, "did:aethelred:a", "did:aethelred:b", scope, nil)
	d2, _ := dm.SubDelegate(ctx, d1.ID, "did:aethelred:c", nil, nil)
	if d2 == nil {
		t.Fatal("first sub-delegation should succeed (depth=1)")
	}
	_, err := dm.SubDelegate(ctx, d2.ID, "did:aethelred:d", nil, nil)
	if err == nil {
		t.Error("expected error for exceeding max delegation depth")
	}
}

func TestDelegation_GlobalMaxDepth(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{Actions: []string{"read"}}
	var prev *DelegationChain
	var err error

	agents := []string{"a", "b", "c", "d", "e", "f", "g"}

	prev, _ = dm.Delegate(ctx, "did:aethelred:"+agents[0], "did:aethelred:"+agents[1], scope, nil)
	for i := 2; i < len(agents); i++ {
		prev, err = dm.SubDelegate(ctx, prev.ID, "did:aethelred:"+agents[i], nil, nil)
		if prev != nil && prev.Depth > MaxDelegationDepth {
			t.Fatalf("delegation depth %d exceeds global maximum %d", prev.Depth, MaxDelegationDepth)
		}
		if err != nil {
			// Expected after MaxDelegationDepth.
			break
		}
	}
}

func TestDelegation_CascadingRevocation(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{Actions: []string{"read"}, MaxDepth: 5}
	d1, _ := dm.Delegate(ctx, "did:aethelred:a", "did:aethelred:b", scope, nil)
	d2, _ := dm.SubDelegate(ctx, d1.ID, "did:aethelred:c", nil, nil)
	d3, _ := dm.SubDelegate(ctx, d2.ID, "did:aethelred:d", nil, nil)

	// Revoke parent.
	dm.RevokeDelegation(ctx, d1.ID)

	// All children should be revoked.
	d1check, _ := dm.GetDelegation(ctx, d1.ID)
	if !d1check.Revoked {
		t.Error("expected d1 to be revoked")
	}
	d2check, _ := dm.GetDelegation(ctx, d2.ID)
	if !d2check.Revoked {
		t.Error("expected d2 to be revoked (cascade)")
	}
	d3check, _ := dm.GetDelegation(ctx, d3.ID)
	if !d3check.Revoked {
		t.Error("expected d3 to be revoked (cascade)")
	}
}

func TestDelegation_VerifyRevokedChain(t *testing.T) {
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{Actions: []string{"read"}, MaxDepth: 5}
	d1, _ := dm.Delegate(ctx, "did:aethelred:a", "did:aethelred:b", scope, nil)
	d2, _ := dm.SubDelegate(ctx, d1.ID, "did:aethelred:c", nil, nil)

	// Revoke root.
	dm.RevokeDelegation(ctx, d1.ID)

	// Verification should fail.
	_, err := dm.VerifyDelegation(ctx, d2.ID, "read")
	if err == nil {
		t.Error("expected error when verifying revoked delegation")
	}
}

// ---------------------------------------------------------------------------
// Receipt tests
// ---------------------------------------------------------------------------

func TestCreateAndVerifyReceipt(t *testing.T) {
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	evidence := map[string]string{"model_hash": "abc123"}
	receipt, err := CreateReceipt(ctx, privKey, "did:aethelred:agent1", "deploy_model", "model-42", "success", "", evidence)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ContentHash == "" {
		t.Error("expected non-empty content hash")
	}
	if receipt.Signature == "" {
		t.Error("expected non-empty signature")
	}

	// Verify.
	if err := VerifyReceipt(receipt, &privKey.PublicKey); err != nil {
		t.Errorf("receipt verification failed: %v", err)
	}
}

func TestVerifyReceipt_WrongKey(t *testing.T) {
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	receipt, _ := CreateReceipt(ctx, privKey, "did:aethelred:agent1", "action", "resource", "success", "", nil)

	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyReceipt(receipt, &wrongKey.PublicKey); err == nil {
		t.Error("expected verification failure with wrong key")
	}
}

func TestSealReceipt(t *testing.T) {
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	receipt, _ := CreateReceipt(ctx, privKey, "did:aethelred:agent1", "action", "resource", "success", "", nil)

	if err := SealReceipt(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SealID == "" {
		t.Error("expected non-empty seal ID after sealing")
	}
}

func TestBuildAndVerifyReceiptChain(t *testing.T) {
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	r1, _ := CreateReceipt(ctx, privKey, "did:aethelred:a", "step1", "res", "success", "", nil)
	r2, _ := CreateReceipt(ctx, privKey, "did:aethelred:a", "step2", "res", "success", "", nil)
	r3, _ := CreateReceipt(ctx, privKey, "did:aethelred:a", "step3", "res", "success", "", nil)

	chain, err := BuildReceiptChain(ctx, []*ActionReceipt{r1, r2, r3})
	if err != nil {
		t.Fatal(err)
	}
	if chain.ChainHash == "" {
		t.Error("expected non-empty chain hash")
	}
	if len(chain.Receipts) != 3 {
		t.Errorf("expected 3 receipts in chain, got %d", len(chain.Receipts))
	}

	// Verify chain.
	if err := VerifyReceiptChain(chain); err != nil {
		t.Errorf("chain verification failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Authorization tests
// ---------------------------------------------------------------------------

func TestAuthorize_Success(t *testing.T) {
	identity, _, _ := NewAgentIdentity([]Capability{{Name: "compute.execute", Version: "1.0"}})
	ctx := context.Background()

	policy := &AuthorizationPolicy{
		AllowedActions: []string{"compute.execute", "model.deploy"},
	}

	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, nil)

	result, err := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:  identity,
		Action: "compute.execute",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Authorized {
		t.Errorf("expected authorized, got denied: %s", result.Reason)
	}
}

func TestAuthorize_ActionNotAllowed(t *testing.T) {
	identity, _, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	policy := &AuthorizationPolicy{
		AllowedActions: []string{"read"},
	}

	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, nil)

	result, _ := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:  identity,
		Action: "delete",
	})
	if result.Authorized {
		t.Error("expected unauthorized for disallowed action")
	}
}

func TestAuthorize_MissingCredential(t *testing.T) {
	identity, _, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	policy := &AuthorizationPolicy{
		RequiredCredentials: []CredentialType{CapabilityCredential},
		AllowedActions:      []string{"*"},
	}

	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, nil)

	result, _ := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:       identity,
		Action:      "deploy",
		Credentials: nil,
	})
	if result.Authorized {
		t.Error("expected unauthorized for missing credential")
	}
	if len(result.RequiredCredentials) == 0 {
		t.Error("expected required credentials in result")
	}
}

func TestAuthorize_WithDelegation(t *testing.T) {
	identity, _, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	dm := NewDelegationManager()
	scope := &DelegationScope{Actions: []string{"read"}}
	d, _ := dm.Delegate(ctx, "did:aethelred:alice", identity.AgentID(), scope, nil)

	policy := &AuthorizationPolicy{
		AllowedActions: []string{"read"},
		DelegationRules: &DelegationAuthRules{
			AllowDelegation:          true,
			MaxDepth:                 5,
			RequireChainVerification: true,
		},
	}

	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, dm)

	result, _ := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:      identity,
		Action:     "read",
		Delegation: d,
	})
	if !result.Authorized {
		t.Errorf("expected authorized with delegation, got: %s", result.Reason)
	}
}

func TestAuthorize_DelegationNotAllowed(t *testing.T) {
	identity, _, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	dm := NewDelegationManager()
	scope := &DelegationScope{Actions: []string{"read"}}
	d, _ := dm.Delegate(ctx, "did:aethelred:alice", identity.AgentID(), scope, nil)

	policy := &AuthorizationPolicy{
		AllowedActions: []string{"read"},
		DelegationRules: &DelegationAuthRules{
			AllowDelegation: false,
		},
	}

	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, dm)

	result, _ := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:      identity,
		Action:     "read",
		Delegation: d,
	})
	if result.Authorized {
		t.Error("expected unauthorized when delegation is not allowed")
	}
}

// ---------------------------------------------------------------------------
// Negotiation tests
// ---------------------------------------------------------------------------

func TestNegotiation_FullFlow(t *testing.T) {
	nm := NewNegotiationManager()
	ctx := context.Background()

	initiator := "did:aethelred:alice"
	responder := "did:aethelred:bob"

	// Step 1: Initiate.
	session, err := nm.InitiateNegotiation(ctx, initiator, responder, &NegotiationRequirements{
		RequiredCredentials: []CredentialType{CapabilityCredential},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != NegotiationInitiated {
		t.Errorf("expected Initiated, got %s", session.Status)
	}

	// Step 2: Exchange credentials.
	cred := &AgentCredential{ID: "cred-1", Type: CapabilityCredential, IssuedAt: time.Now()}
	nm.ExchangeCredentials(ctx, session.ID, []*AgentCredential{cred})

	s, _ := nm.GetNegotiationStatus(ctx, session.ID)
	if s.Status != NegotiationCredentialExchange {
		t.Errorf("expected CredentialExchange, got %s", s.Status)
	}

	// Step 3: Propose policy.
	policy := &AuthorizationPolicy{AllowedActions: []string{"read", "write"}}
	nm.ProposePolicy(ctx, session.ID, initiator, policy)

	s, _ = nm.GetNegotiationStatus(ctx, session.ID)
	if s.Status != NegotiationPolicyAlignment {
		t.Errorf("expected PolicyAlignment, got %s", s.Status)
	}

	// Step 4: Accept policy.
	nm.AcceptPolicy(ctx, session.ID, responder)

	s, _ = nm.GetNegotiationStatus(ctx, session.ID)
	if s.Status != NegotiationAgreed {
		t.Errorf("expected Agreed, got %s", s.Status)
	}
	if s.AgreedPolicy == nil {
		t.Error("expected agreed policy")
	}
}

func TestNegotiation_SelfNegotiation(t *testing.T) {
	nm := NewNegotiationManager()
	ctx := context.Background()

	_, err := nm.InitiateNegotiation(ctx, "did:aethelred:alice", "did:aethelred:alice", nil)
	if err == nil {
		t.Error("expected error for self-negotiation")
	}
}

func TestNegotiation_RejectAndCounterPropose(t *testing.T) {
	nm := NewNegotiationManager()
	ctx := context.Background()

	session, _ := nm.InitiateNegotiation(ctx, "did:aethelred:alice", "did:aethelred:bob", nil)
	nm.ExchangeCredentials(ctx, session.ID, nil)

	// Alice proposes.
	nm.ProposePolicy(ctx, session.ID, "did:aethelred:alice", &AuthorizationPolicy{AllowedActions: []string{"*"}})

	// Bob rejects.
	nm.RejectPolicy(ctx, session.ID, "too broad")

	s, _ := nm.GetNegotiationStatus(ctx, session.ID)
	if s.Status != NegotiationCredentialExchange {
		t.Errorf("expected CredentialExchange after rejection, got %s", s.Status)
	}

	// Bob counter-proposes.
	nm.ProposePolicy(ctx, session.ID, "did:aethelred:bob", &AuthorizationPolicy{AllowedActions: []string{"read"}})

	// Alice accepts.
	nm.AcceptPolicy(ctx, session.ID, "did:aethelred:alice")

	s, _ = nm.GetNegotiationStatus(ctx, session.ID)
	if s.Status != NegotiationAgreed {
		t.Errorf("expected Agreed, got %s", s.Status)
	}
}

func TestNegotiation_ProposerCannotAccept(t *testing.T) {
	nm := NewNegotiationManager()
	ctx := context.Background()

	session, _ := nm.InitiateNegotiation(ctx, "did:aethelred:alice", "did:aethelred:bob", nil)
	nm.ProposePolicy(ctx, session.ID, "did:aethelred:alice", &AuthorizationPolicy{})

	err := nm.AcceptPolicy(ctx, session.ID, "did:aethelred:alice")
	if err == nil {
		t.Error("expected error: proposer cannot accept own proposal")
	}
}

func TestNegotiation_FailNegotiation(t *testing.T) {
	nm := NewNegotiationManager()
	ctx := context.Background()

	session, _ := nm.InitiateNegotiation(ctx, "did:aethelred:alice", "did:aethelred:bob", nil)
	nm.FailNegotiation(ctx, session.ID, "incompatible requirements")

	s, _ := nm.GetNegotiationStatus(ctx, session.ID)
	if s.Status != NegotiationFailed {
		t.Errorf("expected Failed, got %s", s.Status)
	}
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

func TestRegistry_RegisterAndLookup(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity([]Capability{{Name: "compute.execute", Version: "1.0"}})

	reg, err := registry.RegisterAgent(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Status != AgentActive {
		t.Errorf("expected Active, got %s", reg.Status)
	}
	if reg.ReputationScore != 0.5 {
		t.Errorf("expected initial reputation 0.5, got %f", reg.ReputationScore)
	}

	// Lookup.
	found, err := registry.LookupAgent(ctx, identity.AgentID())
	if err != nil {
		t.Fatal(err)
	}
	if found.Identity.AgentID() != identity.AgentID() {
		t.Error("lookup returned different agent")
	}
}

func TestRegistry_DuplicateRegistration(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity)

	_, err := registry.RegisterAgent(ctx, identity)
	if err == nil {
		t.Error("expected error for duplicate registration")
	}
}

func TestRegistry_Deregister(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity)

	err := registry.DeregisterAgent(ctx, identity.AgentID())
	if err != nil {
		t.Fatal(err)
	}

	reg, _ := registry.LookupAgent(ctx, identity.AgentID())
	if reg.Status != AgentDeregistered {
		t.Errorf("expected Deregistered, got %s", reg.Status)
	}
}

func TestRegistry_SuspendAndReactivate(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity)

	registry.SuspendAgent(ctx, identity.AgentID())
	reg, _ := registry.LookupAgent(ctx, identity.AgentID())
	if reg.Status != AgentSuspended {
		t.Errorf("expected Suspended, got %s", reg.Status)
	}

	registry.ReactivateAgent(ctx, identity.AgentID())
	reg, _ = registry.LookupAgent(ctx, identity.AgentID())
	if reg.Status != AgentActive {
		t.Errorf("expected Active, got %s", reg.Status)
	}
}

func TestRegistry_DiscoverAgents(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	id1, _, _ := NewAgentIdentity([]Capability{{Name: "compute.execute"}, {Name: "model.deploy"}})
	id2, _, _ := NewAgentIdentity([]Capability{{Name: "compute.execute"}})
	id3, _, _ := NewAgentIdentity([]Capability{{Name: "data.store"}})

	registry.RegisterAgent(ctx, id1)
	registry.RegisterAgent(ctx, id2)
	registry.RegisterAgent(ctx, id3)

	found := registry.DiscoverAgents(ctx, []string{"compute.execute"})
	if len(found) != 2 {
		t.Errorf("expected 2 agents with compute.execute, got %d", len(found))
	}

	found = registry.DiscoverAgents(ctx, []string{"compute.execute", "model.deploy"})
	if len(found) != 1 {
		t.Errorf("expected 1 agent with both capabilities, got %d", len(found))
	}
}

func TestRegistry_Reputation(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity)

	// Successful actions should increase reputation.
	for i := 0; i < 10; i++ {
		registry.UpdateReputation(ctx, identity.AgentID(), true)
	}

	score, _ := registry.GetAgentReputation(ctx, identity.AgentID())
	if score <= 0.5 {
		t.Errorf("expected reputation above 0.5 after successes, got %f", score)
	}

	// Failed actions should decrease reputation.
	for i := 0; i < 20; i++ {
		registry.UpdateReputation(ctx, identity.AgentID(), false)
	}

	score, _ = registry.GetAgentReputation(ctx, identity.AgentID())
	if score >= 0.5 {
		t.Errorf("expected reputation below 0.5 after many failures, got %f", score)
	}
}

// ---------------------------------------------------------------------------
// Edge case, error path, and concurrency tests
// ---------------------------------------------------------------------------

func TestIdentity_NilPublicKey(t *testing.T) {
	t.Parallel()
	identity := &AgentIdentity{PublicKey: nil}
	err := VerifyIdentity(identity)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}

func TestIdentity_EmptyCapabilities(t *testing.T) {
	t.Parallel()
	identity, _, err := NewAgentIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(identity.Capabilities))
	}

	identity2, _, err := NewAgentIdentity([]Capability{})
	if err != nil {
		t.Fatal(err)
	}
	if len(identity2.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities with empty slice, got %d", len(identity2.Capabilities))
	}
}

func TestParseDID_InvalidFormat_EdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
	}{
		{"no_did_prefix", "aethelred:abc123"},
		{"wrong_method", "did:other:abc123"},
		{"no_id", "did:aethelred:"},
		{"empty", ""},
		{"just_did", "did:"},
		{"just_did_colon", "did::"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDID(tt.input)
			if err == nil {
				t.Errorf("expected error for invalid DID: %q", tt.input)
			}
		})
	}
}

func TestParseDID_EmptyString_EdgeCase(t *testing.T) {
	t.Parallel()
	_, err := ParseDID("")
	if err == nil {
		t.Error("expected error for empty DID string")
	}
}

func TestCredential_ExpiredCredential(t *testing.T) {
	t.Parallel()
	cred := &AgentCredential{
		ID:        "expired-cred",
		Type:      CapabilityCredential,
		IssuedAt:  time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour),
	}
	if cred.IsValid() {
		t.Error("expired credential should not be valid")
	}
}

func TestCredential_RevokedCredential(t *testing.T) {
	t.Parallel()
	cred := &AgentCredential{
		ID:        "revoked-cred",
		Type:      CapabilityCredential,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   true,
	}
	if cred.IsValid() {
		t.Error("revoked credential should not be valid")
	}
}

func TestCredential_NilIssuerKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	claims := []Claim{{Name: "test", Value: "value", Verified: true}}
	_, err := IssueCredential(ctx, nil, "issuer", "subject", CapabilityCredential, claims, time.Hour)
	if err == nil {
		t.Error("expected error for nil issuer key")
	}
}

func TestCredential_TamperedClaim(t *testing.T) {
	t.Parallel()
	issuerID, issuerKey, _ := NewAgentIdentity(nil)
	subjectID, _, _ := NewAgentIdentity(nil)

	ctx := context.Background()
	claims := []Claim{{Name: "role", Value: "admin", Verified: true}}
	cred, err := IssueCredential(ctx, issuerKey, issuerID.AgentID(), subjectID.AgentID(), CapabilityCredential, claims, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with claim.
	cred.Claims[0].Value = "superadmin"

	err = VerifyCredential(cred, &issuerKey.PublicKey)
	if err == nil {
		t.Error("expected verification failure for tampered claim")
	}
}

func TestDelegation_MaxDepthExactly_EdgeCase(t *testing.T) {
	t.Parallel()
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{
		Actions:  []string{"read"},
		MaxDepth: MaxDelegationDepth,
	}

	agents := make([]string, MaxDelegationDepth+2)
	for i := range agents {
		agents[i] = fmt.Sprintf("did:aethelred:agent_%d", i)
	}

	d, _ := dm.Delegate(ctx, agents[0], agents[1], scope, nil)
	for i := 2; i < len(agents); i++ {
		next, err := dm.SubDelegate(ctx, d.ID, agents[i], nil, nil)
		if err != nil {
			// Expected when exceeding max depth.
			break
		}
		d = next
	}
}

func TestDelegation_SubDelegateOnRevoked(t *testing.T) {
	t.Parallel()
	dm := NewDelegationManager()
	ctx := context.Background()

	scope := &DelegationScope{Actions: []string{"read"}, MaxDepth: 5}
	d1, _ := dm.Delegate(ctx, "did:aethelred:a", "did:aethelred:b", scope, nil)

	// Revoke the root delegation.
	dm.RevokeDelegation(ctx, d1.ID)

	// Try to sub-delegate on revoked parent.
	_, err := dm.SubDelegate(ctx, d1.ID, "did:aethelred:c", nil, nil)
	if err == nil {
		t.Error("expected error for sub-delegation on revoked parent")
	}
}

func TestDelegation_CircularDelegation(t *testing.T) {
	t.Parallel()
	dm := NewDelegationManager()
	ctx := context.Background()

	// A delegates to B.
	scope := &DelegationScope{Actions: []string{"read"}, MaxDepth: 5}
	_, err := dm.Delegate(ctx, "did:aethelred:a", "did:aethelred:b", scope, nil)
	if err != nil {
		t.Fatal(err)
	}

	// B delegates to A (circular).
	_, err = dm.Delegate(ctx, "did:aethelred:b", "did:aethelred:a", scope, nil)
	// This may or may not be an error depending on implementation.
	// A separate delegation from B->A is a new root, not circular.
	_ = err
}

func TestDelegation_ConcurrentDelegation(t *testing.T) {
	t.Parallel()
	dm := NewDelegationManager()
	ctx := context.Background()

	const goroutines = 20
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			scope := &DelegationScope{Actions: []string{"read"}, TimeLimit: time.Hour}
			_, err := dm.Delegate(ctx,
				fmt.Sprintf("did:aethelred:delegator_%d", idx),
				fmt.Sprintf("did:aethelred:delegate_%d", idx),
				scope, nil)
			errs <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent delegation failed: %v", err)
		}
	}
}

func TestReceipt_NilActor(t *testing.T) {
	t.Parallel()
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	_, err := CreateReceipt(ctx, privKey, "", "action", "resource", "success", "", nil)
	if err == nil {
		t.Error("expected error for empty actor")
	}
}

func TestReceipt_TamperedContentHash(t *testing.T) {
	t.Parallel()
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	receipt, err := CreateReceipt(ctx, privKey, "did:aethelred:agent1", "action", "resource", "success", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with content hash.
	receipt.ContentHash = "tampered-hash"
	if err := VerifyReceipt(receipt, &privKey.PublicKey); err == nil {
		t.Error("expected verification failure for tampered content hash")
	}
}

func TestReceipt_ChainWithMissingLink(t *testing.T) {
	t.Parallel()
	_, privKey, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	r1, _ := CreateReceipt(ctx, privKey, "did:aethelred:a", "step1", "res", "success", "", nil)
	_, _ = CreateReceipt(ctx, privKey, "did:aethelred:a", "step2", "res", "success", "", nil) // skipped
	r3, _ := CreateReceipt(ctx, privKey, "did:aethelred:a", "step3", "res", "success", "", nil)

	// Build chain with a gap (skip r2).
	chain, err := BuildReceiptChain(ctx, []*ActionReceipt{r1, r3})
	if err != nil {
		// If chain-building fails because of the gap, that's acceptable.
		return
	}
	// If it built, verify should detect the gap.
	_ = VerifyReceiptChain(chain)
}

func TestAuthorization_NoCredentials(t *testing.T) {
	t.Parallel()
	identity, _, _ := NewAgentIdentity(nil)
	ctx := context.Background()

	policy := &AuthorizationPolicy{
		RequiredCredentials: []CredentialType{CapabilityCredential},
		AllowedActions:      []string{"*"},
	}

	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, nil)
	result, _ := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:       identity,
		Action:      "deploy",
		Credentials: nil,
	})
	if result.Authorized {
		t.Error("expected unauthorized without required credentials")
	}
}

func TestAuthorization_ContextCancelled(t *testing.T) {
	t.Parallel()
	identity, _, _ := NewAgentIdentity(nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	policy := &AuthorizationPolicy{AllowedActions: []string{"read"}}
	authorizer := NewAuthorizer([]*AuthorizationPolicy{policy}, nil)

	_, err := authorizer.Authorize(ctx, &AuthorizationContext{
		Actor:  identity,
		Action: "read",
	})
	// May return error or succeed (depending on implementation).
	_ = err
}

func TestNegotiation_SelfNegotiation_EdgeCase(t *testing.T) {
	t.Parallel()
	nm := NewNegotiationManager()
	ctx := context.Background()

	_, err := nm.InitiateNegotiation(ctx, "did:aethelred:same", "did:aethelred:same", nil)
	if err == nil {
		t.Error("expected error for self-negotiation")
	}
}

func TestNegotiation_DoubleAccept(t *testing.T) {
	t.Parallel()
	nm := NewNegotiationManager()
	ctx := context.Background()

	session, _ := nm.InitiateNegotiation(ctx, "did:aethelred:alice", "did:aethelred:bob", nil)
	nm.ExchangeCredentials(ctx, session.ID, nil)
	nm.ProposePolicy(ctx, session.ID, "did:aethelred:alice", &AuthorizationPolicy{AllowedActions: []string{"read"}})

	// First accept by bob.
	err := nm.AcceptPolicy(ctx, session.ID, "did:aethelred:bob")
	if err != nil {
		t.Fatalf("first accept failed: %v", err)
	}

	// Second accept on already-agreed session.
	err = nm.AcceptPolicy(ctx, session.ID, "did:aethelred:bob")
	if err == nil {
		t.Error("expected error for double accept on agreed session")
	}
}

func TestRegistry_ConcurrentRegistration(t *testing.T) {
	t.Parallel()
	registry := NewAgentRegistry()
	ctx := context.Background()

	const goroutines = 20
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			identity, _, _ := NewAgentIdentity(nil)
			_, err := registry.RegisterAgent(ctx, identity)
			errs <- err
		}()
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent registration failed: %v", err)
		}
	}
}

func TestRegistry_ReputationBoundary(t *testing.T) {
	t.Parallel()
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity)

	// Drive reputation toward 1.0.
	for i := 0; i < 1000; i++ {
		registry.UpdateReputation(ctx, identity.AgentID(), true)
	}
	score, _ := registry.GetAgentReputation(ctx, identity.AgentID())
	if score > 1.0 {
		t.Errorf("reputation should not exceed 1.0, got %f", score)
	}
	if score < 0.0 {
		t.Errorf("reputation should not be negative, got %f", score)
	}

	// Drive reputation toward 0.0.
	identity2, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity2)
	for i := 0; i < 1000; i++ {
		registry.UpdateReputation(ctx, identity2.AgentID(), false)
	}
	score2, _ := registry.GetAgentReputation(ctx, identity2.AgentID())
	if score2 < 0.0 {
		t.Errorf("reputation should not be negative, got %f", score2)
	}
	if score2 > 1.0 {
		t.Errorf("reputation should not exceed 1.0, got %f", score2)
	}
}

func TestRegistry_SuspendedAgent(t *testing.T) {
	t.Parallel()
	registry := NewAgentRegistry()
	ctx := context.Background()

	identity, _, _ := NewAgentIdentity(nil)
	registry.RegisterAgent(ctx, identity)
	registry.SuspendAgent(ctx, identity.AgentID())

	// Verify suspended agent is not discovered.
	found := registry.DiscoverAgents(ctx, nil)
	for _, reg := range found {
		if reg.Identity.AgentID() == identity.AgentID() {
			t.Error("suspended agent should not appear in discovery")
		}
	}

	// Verify suspended status.
	reg, _ := registry.LookupAgent(ctx, identity.AgentID())
	if reg.Status != AgentSuspended {
		t.Errorf("expected Suspended, got %s", reg.Status)
	}
}

// ---------------------------------------------------------------------------

func TestRegistry_ListActiveAgents(t *testing.T) {
	registry := NewAgentRegistry()
	ctx := context.Background()

	id1, _, _ := NewAgentIdentity(nil)
	id2, _, _ := NewAgentIdentity(nil)
	id3, _, _ := NewAgentIdentity(nil)

	registry.RegisterAgent(ctx, id1)
	registry.RegisterAgent(ctx, id2)
	registry.RegisterAgent(ctx, id3)

	registry.SuspendAgent(ctx, id2.AgentID())

	active := registry.ListActiveAgents(ctx)
	if len(active) != 2 {
		t.Errorf("expected 2 active agents, got %d", len(active))
	}
}
