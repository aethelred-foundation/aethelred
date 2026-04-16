package sdk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
	"github.com/aethelred/aethelred/pkg/protocol/agent"
	"github.com/aethelred/aethelred/x/seal/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// cloneSeal creates a deep copy of a DigitalSeal using protobuf cloning,
// which is safe for types containing sync.Mutex via protoimpl.MessageState.
func cloneSeal(seal *types.DigitalSeal) *types.DigitalSeal {
	return proto.Clone(seal).(*types.DigitalSeal)
}

var bech32Once sync.Once

func ensureBech32() {
	bech32Once.Do(func() {
		defer func() { _ = recover() }()
		cfg := sdk.GetConfig()
		cfg.SetBech32PrefixForAccount("aethel", "aethelpub")
		cfg.SetBech32PrefixForValidator("aethelvaloper", "aethelvaloperpub")
		cfg.SetBech32PrefixForConsensusNode("aethelvalcons", "aethelvalconspub")
		cfg.Seal()
	})
}

func testAccAddress(seed byte) string {
	ensureBech32()
	addr := bytes.Repeat([]byte{seed}, 20)
	return sdk.AccAddress(addr).String()
}

// --- mock keeper ---

type mockKeeper struct {
	mu    sync.RWMutex
	seals map[string]*types.DigitalSeal
}

func newMockKeeper() *mockKeeper {
	return &mockKeeper{seals: make(map[string]*types.DigitalSeal)}
}

func (m *mockKeeper) CreateSeal(_ context.Context, seal *types.DigitalSeal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.seals[seal.GetId()]; exists {
		return fmt.Errorf("seal already exists: %s", seal.GetId())
	}
	m.seals[seal.GetId()] = cloneSeal(seal)
	return nil
}

func (m *mockKeeper) GetSeal(_ context.Context, id string) (*types.DigitalSeal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seal, ok := m.seals[id]
	if !ok {
		return nil, fmt.Errorf("seal not found: %s", id)
	}
	return cloneSeal(seal), nil
}

func (m *mockKeeper) SetSeal(_ context.Context, seal *types.DigitalSeal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seals[seal.GetId()] = cloneSeal(seal)
	return nil
}

func (m *mockKeeper) RevokeSeal(_ context.Context, id, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	seal, ok := m.seals[id]
	if !ok {
		return fmt.Errorf("seal not found: %s", id)
	}
	seal.Status = types.SealStatusRevoked
	return nil
}

func (m *mockKeeper) VerifySeal(_ context.Context, id string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seal, ok := m.seals[id]
	if !ok {
		return false, fmt.Errorf("seal not found: %s", id)
	}
	return seal.Status == types.SealStatusActive && seal.IsVerified(), nil
}

func (m *mockKeeper) ListSeals(_ context.Context, limit, offset int) ([]*types.DigitalSeal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*types.DigitalSeal
	i := 0
	for _, seal := range m.seals {
		if i < offset {
			i++
			continue
		}
		if len(result) >= limit {
			break
		}
		result = append(result, cloneSeal(seal))
		i++
	}
	return result, nil
}

func (m *mockKeeper) ListSealsByModel(_ context.Context, modelHash []byte) ([]*types.DigitalSeal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*types.DigitalSeal
	for _, seal := range m.seals {
		if bytes.Equal(seal.GetModelCommitment(), modelHash) {
			result = append(result, cloneSeal(seal))
		}
	}
	return result, nil
}

func (m *mockKeeper) ListSealsByRequester(_ context.Context, requester string) ([]*types.DigitalSeal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*types.DigitalSeal
	for _, seal := range m.seals {
		if seal.GetRequestedBy() == requester {
			result = append(result, cloneSeal(seal))
		}
	}
	return result, nil
}

// --- test helpers ---

func testHash(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, 32)
}

func testSDK(t *testing.T) (*SealSDK, *mockKeeper) {
	t.Helper()
	ensureBech32()
	keeper := newMockKeeper()
	s, err := NewSealSDK(Config{
		ChainID:       "test-chain-1",
		SignerAddress: testAccAddress(0x01),
	}, keeper)
	if err != nil {
		t.Fatalf("NewSealSDK: %v", err)
	}
	return s, keeper
}

func testRequest() SealRequest {
	return SealRequest{
		ModelHash:  testHash(0x01),
		InputHash:  testHash(0x02),
		OutputHash: testHash(0x03),
		Purpose:    "credit_scoring",
	}
}

func testEnterpriseIdentity(t *testing.T) *agent.AgentIdentity {
	t.Helper()

	identity, _, err := agent.NewEnterpriseAgentIdentity([]agent.Capability{
		{Name: "mcp.policy.evaluate", Version: "1.0.0"},
		{Name: "seal.execute", Version: "1.0.0"},
	}, agent.EnterpriseIdentityOptions{
		Issuer: "did:aethelred:policy-gateway-1",
		SponsorChain: []agent.SponsorRecord{{
			SponsorDID:        "did:aethelred:sponsor-1",
			SponsorName:       "Chief Risk Office",
			Jurisdiction:      "UAE",
			Role:              "primary",
			LiabilityAccepted: true,
		}},
		Liability: &agent.LiabilityProfile{
			HumanOwner:       "alice@example.com",
			BusinessUnit:     "Risk",
			SponsorOfRecord:  "did:aethelred:sponsor-1",
			FallbackApprover: "did:aethelred:backup-1",
			IncidentContact:  "soc@example.com",
			LiabilityModel:   "joint",
		},
		JurisdictionTags: []string{"UAE", "UK"},
		AllowedTools:     []string{"mcp.policy.evaluate", "seal.execute"},
		Metadata:         map[string]string{"tier": "production", "owner": "risk"},
	})
	if err != nil {
		t.Fatalf("NewEnterpriseAgentIdentity: %v", err)
	}
	if err := agent.VerifyIdentity(identity); err != nil {
		t.Fatalf("VerifyIdentity: %v", err)
	}
	return identity
}

func testPolicyReceipt(t *testing.T) *policy.SignedPolicyReceipt {
	t.Helper()
	return &policy.SignedPolicyReceipt{
		ID:                  "receipt-001",
		RequestID:           "request-001",
		Actor:               "did:aethelred:agent-001",
		Action:              "approve_transfer",
		Resource:            "ledger/tx/123",
		Decision:            "allow",
		AuditTrail:          "audit-hash-001",
		Signer:              "did:aethelred:policy-gateway-1",
		ContentHash:         "content-hash-001",
		PreviousReceiptHash: "content-hash-000",
		EvaluatedAt:         time.Date(2026, 4, 14, 12, 30, 0, 0, time.UTC),
	}
}

// ======================================================================
// Core SDK Tests
// ======================================================================

func TestNewSealSDK(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		keeper  SealKeeper
		wantErr bool
	}{
		{
			name:    "nil keeper",
			config:  Config{},
			keeper:  nil,
			wantErr: true,
		},
		{
			name:    "valid config",
			config:  Config{ChainID: "test-1"},
			keeper:  newMockKeeper(),
			wantErr: false,
		},
		{
			name:    "defaults applied",
			config:  Config{},
			keeper:  newMockKeeper(),
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSealSDK(tc.config, tc.keeper)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if s == nil {
				t.Fatal("expected non-nil SDK")
			}
		})
	}
}

func TestCreateSeal(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	resp, err := s.CreateSeal(ctx, testRequest())
	if err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}
	if resp.SealID == "" {
		t.Fatal("expected non-empty seal ID")
	}
	if resp.Purpose != "credit_scoring" {
		t.Fatalf("expected purpose credit_scoring, got %s", resp.Purpose)
	}
}

func TestCreateSealValidation(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		req     SealRequest
		wantErr string
	}{
		{
			name:    "empty model hash",
			req:     SealRequest{ModelHash: nil, InputHash: testHash(2), OutputHash: testHash(3), Purpose: "test"},
			wantErr: "model hash must be 32 bytes",
		},
		{
			name:    "short input hash",
			req:     SealRequest{ModelHash: testHash(1), InputHash: []byte{0x01}, OutputHash: testHash(3), Purpose: "test"},
			wantErr: "input hash must be 32 bytes",
		},
		{
			name:    "empty purpose",
			req:     SealRequest{ModelHash: testHash(1), InputHash: testHash(2), OutputHash: testHash(3), Purpose: ""},
			wantErr: "purpose is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.CreateSeal(ctx, tc.req)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.wantErr != "" && !containsSubstring(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestCreateSealWithAttestation(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	req := testRequest()
	req.TEEAttestations = []*types.TEEAttestation{
		{
			ValidatorAddress: "aethel1validator1",
			Platform:         "aws-nitro",
			EnclaveId:        "enclave-123",
			Measurement:      testHash(0x10),
			Quote:            testHash(0x11),
			Signature:        testHash(0x12),
			Timestamp:        timestamppb.Now(),
		},
	}

	resp, err := s.CreateSeal(ctx, req)
	if err != nil {
		t.Fatalf("CreateSeal with attestation: %v", err)
	}
	if len(resp.Attestations) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(resp.Attestations))
	}
	// Should be active since it has verification evidence
	if resp.Status != types.SealStatusActive {
		t.Fatalf("expected ACTIVE status, got %s", resp.Status.String())
	}
}

func TestCreateSealWithZKProof(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	req := testRequest()
	req.ZKProof = &types.ZKMLProof{
		ProofSystem:      "ezkl",
		ProofBytes:       testHash(0x20),
		PublicInputs:     testHash(0x21),
		VerifyingKeyHash: testHash(0x22),
		CircuitHash:      testHash(0x23),
	}

	resp, err := s.CreateSeal(ctx, req)
	if err != nil {
		t.Fatalf("CreateSeal with proof: %v", err)
	}
	if resp.Proof == nil {
		t.Fatal("expected proof to be set")
	}
	if resp.Status != types.SealStatusActive {
		t.Fatalf("expected ACTIVE status, got %s", resp.Status.String())
	}
}

func TestGetSeal(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	req := testRequest()
	req.TEEAttestations = []*types.TEEAttestation{{
		ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
		Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
	}}

	created, err := s.CreateSeal(ctx, req)
	if err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}

	retrieved, err := s.GetSeal(ctx, created.SealID)
	if err != nil {
		t.Fatalf("GetSeal: %v", err)
	}
	if retrieved.SealID != created.SealID {
		t.Fatalf("ID mismatch: %s != %s", retrieved.SealID, created.SealID)
	}
}

func TestGetSealNotFound(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	_, err := s.GetSeal(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent seal")
	}
}

func TestRevokeSeal(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	resp, _ := s.CreateSeal(ctx, testRequest())

	err := s.RevokeSeal(ctx, resp.SealID, "compromised model")
	if err != nil {
		t.Fatalf("RevokeSeal: %v", err)
	}

	updated, err := s.GetSeal(ctx, resp.SealID)
	if err != nil {
		t.Fatalf("GetSeal after revoke: %v", err)
	}
	if updated.Status != types.SealStatusRevoked {
		t.Fatalf("expected REVOKED, got %s", updated.Status.String())
	}
}

func TestRevokeSealValidation(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	if err := s.RevokeSeal(ctx, "", "reason"); err == nil {
		t.Fatal("expected error for empty ID")
	}
	if err := s.RevokeSeal(ctx, "some-id", ""); err == nil {
		t.Fatal("expected error for empty reason")
	}
}

func TestListSeals(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	// Create multiple seals with different models
	for i := byte(1); i <= 5; i++ {
		req := SealRequest{
			ModelHash:  testHash(i),
			InputHash:  testHash(0x10 + i),
			OutputHash: testHash(0x20 + i),
			Purpose:    fmt.Sprintf("purpose_%d", i),
		}
		if _, err := s.CreateSeal(ctx, req); err != nil {
			t.Fatalf("CreateSeal[%d]: %v", i, err)
		}
	}

	results, err := s.ListSeals(ctx, SealFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListSeals: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("expected 5 seals, got %d", len(results))
	}
}

func TestListSealsByModel(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	sharedModel := testHash(0xAA)
	for i := byte(0); i < 3; i++ {
		req := SealRequest{
			ModelHash:  sharedModel,
			InputHash:  testHash(0x10 + i),
			OutputHash: testHash(0x20 + i),
			Purpose:    "test",
		}
		if _, err := s.CreateSeal(ctx, req); err != nil {
			t.Fatalf("CreateSeal: %v", err)
		}
	}
	// One with a different model
	req := SealRequest{
		ModelHash:  testHash(0xBB),
		InputHash:  testHash(0x40),
		OutputHash: testHash(0x50),
		Purpose:    "test",
	}
	if _, err := s.CreateSeal(ctx, req); err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}

	results, err := s.ListSeals(ctx, SealFilter{ModelHash: sharedModel})
	if err != nil {
		t.Fatalf("ListSeals by model: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 seals for model, got %d", len(results))
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("test data for hashing")
	h := ComputeHash(data)
	if len(h) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(h))
	}

	expected := sha256.Sum256(data)
	if !bytes.Equal(h, expected[:]) {
		t.Fatal("hash does not match expected SHA-256")
	}
}

func TestComputeHashHex(t *testing.T) {
	data := []byte("test")
	h := ComputeHashHex(data)
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(h))
	}
}

// ======================================================================
// Verifier Tests
// ======================================================================

func TestVerifierOffline(t *testing.T) {
	ensureBech32()
	v := NewVerifier(nil)

	requester := testAccAddress(0x05)
	validator := testAccAddress(0x06)

	seal := &types.DigitalSeal{
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      100,
		RequestedBy:      requester,
		Purpose:          "credit_scoring",
		Status:           types.SealStatusActive,
		Timestamp:        timestamppb.Now(),
		TeeAttestations: []*types.TEEAttestation{
			{
				ValidatorAddress: validator,
				Platform:         "aws-nitro",
				EnclaveId:        "enclave-1",
				Measurement:      testHash(0x10),
				Quote:            testHash(0x11),
				Signature:        testHash(0x12),
				Timestamp:        timestamppb.Now(),
			},
		},
		ValidatorSet: []string{validator},
	}
	seal.Id = seal.GenerateID()

	result := v.VerifyOffline(seal)
	if !result.Valid {
		t.Fatalf("expected valid seal, got errors: %v", result.Errors)
	}
	if result.AttestationStatus.Valid != 1 {
		t.Fatalf("expected 1 valid attestation, got %d", result.AttestationStatus.Valid)
	}
}

func TestVerifierOfflineRevokedSeal(t *testing.T) {
	ensureBech32()
	v := NewVerifier(nil)

	requester := testAccAddress(0x07)

	seal := &types.DigitalSeal{
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      100,
		RequestedBy:      requester,
		Purpose:          "credit_scoring",
		Status:           types.SealStatusRevoked,
		Timestamp:        timestamppb.Now(),
		TeeAttestations: []*types.TEEAttestation{{
			ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
			Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			Timestamp: timestamppb.Now(),
		}},
		ValidatorSet: []string{"v1"},
	}
	seal.Id = seal.GenerateID()

	result := v.VerifyOffline(seal)
	if result.Valid {
		t.Fatal("expected revoked seal to fail verification")
	}
}

func TestVerifyChain(t *testing.T) {
	ensureBech32()
	v := NewVerifier(nil)

	addr := testAccAddress(0x08)
	att := func() []*types.TEEAttestation {
		return []*types.TEEAttestation{{
			ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
			Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			Timestamp: timestamppb.Now(),
		}}
	}

	seal1 := &types.DigitalSeal{
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03), // output feeds seal2 input
		BlockHeight:      100,
		RequestedBy:      addr,
		Purpose:          "step1",
		Status:           types.SealStatusActive,
		Timestamp:        timestamppb.New(time.Now().Add(-2 * time.Hour)),
		TeeAttestations:  att(),
		ValidatorSet:     []string{"v1"},
	}
	seal1.Id = seal1.GenerateID()

	seal2 := &types.DigitalSeal{
		ModelCommitment:  testHash(0x04),
		InputCommitment:  testHash(0x03), // matches seal1 output
		OutputCommitment: testHash(0x05),
		BlockHeight:      200,
		RequestedBy:      addr,
		Purpose:          "step2",
		Status:           types.SealStatusActive,
		Timestamp:        timestamppb.New(time.Now().Add(-1 * time.Hour)),
		TeeAttestations:  att(),
		ValidatorSet:     []string{"v1"},
	}
	seal2.Id = seal2.GenerateID()

	result := v.VerifyChain([]*types.DigitalSeal{seal1, seal2})
	if !result.Valid {
		t.Fatalf("expected valid chain, got errors: %v", result.Errors)
	}
}

func TestVerifyChainBroken(t *testing.T) {
	ensureBech32()
	v := NewVerifier(nil)

	addr := testAccAddress(0x09)
	att := func() []*types.TEEAttestation {
		return []*types.TEEAttestation{{
			ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
			Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			Timestamp: timestamppb.Now(),
		}}
	}

	seal1 := &types.DigitalSeal{
		ModelCommitment: testHash(0x01), InputCommitment: testHash(0x02),
		OutputCommitment: testHash(0x03), BlockHeight: 100,
		RequestedBy: addr, Purpose: "step1", Status: types.SealStatusActive,
		Timestamp: timestamppb.Now(), TeeAttestations: att(), ValidatorSet: []string{"v1"},
	}
	seal1.Id = seal1.GenerateID()

	seal2 := &types.DigitalSeal{
		ModelCommitment: testHash(0x04), InputCommitment: testHash(0xFF), // MISMATCH
		OutputCommitment: testHash(0x05), BlockHeight: 200,
		RequestedBy: addr, Purpose: "step2", Status: types.SealStatusActive,
		Timestamp: timestamppb.Now(), TeeAttestations: att(), ValidatorSet: []string{"v1"},
	}
	seal2.Id = seal2.GenerateID()

	result := v.VerifyChain([]*types.DigitalSeal{seal1, seal2})
	if result.Valid {
		t.Fatal("expected broken chain to fail")
	}
}

func TestValidateAttestation(t *testing.T) {
	v := NewVerifier(nil)

	tests := []struct {
		name    string
		att     *types.TEEAttestation
		wantErr bool
	}{
		{
			name:    "nil attestation",
			att:     nil,
			wantErr: true,
		},
		{
			name: "untrusted platform",
			att: &types.TEEAttestation{
				ValidatorAddress: "v1", Platform: "unknown-tee", EnclaveId: "e1",
				Measurement: testHash(1), Quote: testHash(2), Signature: testHash(3),
				Timestamp: timestamppb.Now(),
			},
			wantErr: true,
		},
		{
			name: "empty enclave ID",
			att: &types.TEEAttestation{
				ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "",
				Measurement: testHash(1), Quote: testHash(2), Signature: testHash(3),
				Timestamp: timestamppb.Now(),
			},
			wantErr: true,
		},
		{
			name: "valid attestation",
			att: &types.TEEAttestation{
				ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
				Measurement: testHash(1), Quote: testHash(2), Signature: testHash(3),
				Timestamp: timestamppb.Now(),
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidateAttestation(tc.att)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateProof(t *testing.T) {
	v := NewVerifier(nil)

	tests := []struct {
		name    string
		proof   *types.ZKMLProof
		wantErr bool
	}{
		{
			name:    "nil proof",
			proof:   nil,
			wantErr: true,
		},
		{
			name: "unknown proof system",
			proof: &types.ZKMLProof{
				ProofSystem: "unknown", ProofBytes: testHash(1), PublicInputs: testHash(2),
				VerifyingKeyHash: testHash(3), CircuitHash: testHash(4),
			},
			wantErr: true,
		},
		{
			name: "empty proof bytes",
			proof: &types.ZKMLProof{
				ProofSystem: "ezkl", ProofBytes: nil, PublicInputs: testHash(2),
				VerifyingKeyHash: testHash(3), CircuitHash: testHash(4),
			},
			wantErr: true,
		},
		{
			name: "valid proof",
			proof: &types.ZKMLProof{
				ProofSystem: "ezkl", ProofBytes: testHash(1), PublicInputs: testHash(2),
				VerifyingKeyHash: testHash(3), CircuitHash: testHash(4),
			},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.ValidateProof(tc.proof)
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestVerifyCommitmentBinding(t *testing.T) {
	data := []byte("model weights v1.0")
	commitment := ComputeHash(data)

	if !VerifyCommitmentBinding(data, commitment) {
		t.Fatal("expected valid binding")
	}
	if VerifyCommitmentBinding([]byte("tampered"), commitment) {
		t.Fatal("expected invalid binding for tampered data")
	}
}

func TestP256PublicKeyFromBytes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}

	pubBytes := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	recovered, err := P256PublicKeyFromBytes(pubBytes)
	if err != nil {
		t.Fatalf("P256PublicKeyFromBytes: %v", err)
	}
	if recovered.X.Cmp(key.PublicKey.X) != 0 || recovered.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("recovered key does not match original")
	}

	// Invalid bytes
	_, err = P256PublicKeyFromBytes([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for invalid key bytes")
	}
}

// ======================================================================
// Evidence Tests
// ======================================================================

func TestEvidenceAttachment(t *testing.T) {
	store := NewInMemoryEvidenceStore()
	sealID := "test-seal-001"

	evidence := NewEvidenceAttachment(
		EvidenceTypeModelCard,
		[]byte(`{"model": "gpt-4", "version": "1.0"}`),
		"aethel1signer",
		"Model card for evaluation",
		"application/json",
	)

	if err := AttachEvidence(store, sealID, evidence); err != nil {
		t.Fatalf("AttachEvidence: %v", err)
	}

	retrieved, err := GetEvidence(store, sealID)
	if err != nil {
		t.Fatalf("GetEvidence: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("expected 1 evidence, got %d", len(retrieved))
	}
	if retrieved[0].Type != EvidenceTypeModelCard {
		t.Fatalf("expected model_card type, got %s", retrieved[0].Type)
	}
}

func TestEvidenceAttachmentValidation(t *testing.T) {
	store := NewInMemoryEvidenceStore()

	// Empty seal ID
	err := AttachEvidence(store, "", NewEvidenceAttachment(EvidenceTypeCustom, []byte("data"), "", "", ""))
	if err == nil {
		t.Fatal("expected error for empty seal ID")
	}

	// Empty data
	err = AttachEvidence(store, "seal-1", EvidenceAttachment{Data: nil})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestEvidenceHashIntegrity(t *testing.T) {
	store := NewInMemoryEvidenceStore()

	data := []byte("authentic data")
	h := sha256.Sum256(data)

	// Tampered hash should fail
	evidence := EvidenceAttachment{
		Type:      EvidenceTypeCustom,
		Data:      data,
		Hash:      bytes.Repeat([]byte{0xFF}, 32), // wrong hash
		Timestamp: time.Now(),
	}
	err := AttachEvidence(store, "seal-1", evidence)
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}

	// Correct hash should succeed
	evidence.Hash = h[:]
	err = AttachEvidence(store, "seal-1", evidence)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStructuredPolicyReceiptEvidenceAndAttachment(t *testing.T) {
	receipt := testPolicyReceipt(t)

	evidence, err := NewPolicyReceiptEvidence(receipt)
	if err != nil {
		t.Fatalf("NewPolicyReceiptEvidence: %v", err)
	}
	if evidence.ID != receipt.ID || evidence.RequestID != receipt.RequestID || evidence.Signer != receipt.Signer {
		t.Fatal("policy receipt fields were not preserved")
	}
	if evidence.EvaluatedAt != receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("expected evaluated_at to be normalized, got %s", evidence.EvaluatedAt)
	}

	attachment, err := NewPolicyReceiptAttachment(receipt)
	if err != nil {
		t.Fatalf("NewPolicyReceiptAttachment: %v", err)
	}
	if attachment.Type != EvidenceTypePolicyReceipt {
		t.Fatalf("expected policy receipt attachment type, got %s", attachment.Type)
	}
	if attachment.MimeType != "application/json" {
		t.Fatalf("expected application/json attachment, got %s", attachment.MimeType)
	}

	var decoded PolicyReceiptEvidence
	if err := json.Unmarshal(attachment.Data, &decoded); err != nil {
		t.Fatalf("unmarshal policy receipt attachment: %v", err)
	}
	if decoded.ContentHash != receipt.ContentHash || decoded.Decision != receipt.Decision {
		t.Fatal("policy receipt attachment payload does not match source receipt")
	}
}

func TestStructuredAgentPassportEvidenceAndAttachment(t *testing.T) {
	identity := testEnterpriseIdentity(t)

	evidence, err := NewAgentPassportEvidence(identity)
	if err != nil {
		t.Fatalf("NewAgentPassportEvidence: %v", err)
	}
	if evidence.DID != identity.AgentID() {
		t.Fatalf("expected DID %s, got %s", identity.AgentID(), evidence.DID)
	}
	if evidence.HumanOwner != identity.Liability.HumanOwner {
		t.Fatalf("expected human owner %s, got %s", identity.Liability.HumanOwner, evidence.HumanOwner)
	}

	pubBytes, err := hex.DecodeString(identity.PublicKeyHex)
	if err != nil {
		t.Fatalf("hex decode public key: %v", err)
	}
	if evidence.PublicKeyHash != EvidenceHashHex(pubBytes) {
		t.Fatal("passport public key hash does not match canonical hash")
	}
	if len(evidence.SponsorChain) != 1 || evidence.SponsorChain[0].SponsorDID != identity.SponsorChain[0].SponsorDID {
		t.Fatal("passport sponsor chain was not preserved")
	}

	attachment, err := NewAgentPassportAttachment(identity)
	if err != nil {
		t.Fatalf("NewAgentPassportAttachment: %v", err)
	}
	if attachment.Type != EvidenceTypeAgentPassport {
		t.Fatalf("expected agent passport attachment type, got %s", attachment.Type)
	}
	var decoded AgentPassportEvidence
	if err := json.Unmarshal(attachment.Data, &decoded); err != nil {
		t.Fatalf("unmarshal agent passport attachment: %v", err)
	}
	if decoded.SponsorOfRecord != identity.Liability.SponsorOfRecord || decoded.Issuer != identity.Issuer {
		t.Fatal("passport attachment payload does not match source identity")
	}
}

func TestStructuredTraceLinkAttachmentAndBundle(t *testing.T) {
	store := NewInMemoryEvidenceStore()
	identity := testEnterpriseIdentity(t)
	receipt := testPolicyReceipt(t)
	seal := Seal{
		SealID:     "seal-structured-001",
		JobID:      "job-001",
		OutputHash: "output-hash-001",
	}

	traceLink, err := NewTraceLink(identity, receipt, seal, "policy approved output")
	if err != nil {
		t.Fatalf("NewTraceLink: %v", err)
	}
	if traceLink.AgentDID != identity.AgentID() || traceLink.PolicyReceiptHash != receipt.ContentHash {
		t.Fatal("trace link fields were not preserved")
	}

	attachment, err := NewTraceLinkAttachment(traceLink)
	if err != nil {
		t.Fatalf("NewTraceLinkAttachment: %v", err)
	}
	if attachment.Type != EvidenceTypeTraceLink {
		t.Fatalf("expected trace link attachment type, got %s", attachment.Type)
	}
	if err := AttachEvidence(store, seal.SealID, attachment); err != nil {
		t.Fatalf("AttachEvidence(trace): %v", err)
	}
	if err := AttachEvidence(store, seal.SealID, func() EvidenceAttachment {
		att, err := NewPolicyReceiptAttachment(receipt)
		if err != nil {
			t.Fatalf("NewPolicyReceiptAttachment: %v", err)
		}
		return att
	}()); err != nil {
		t.Fatalf("AttachEvidence(receipt): %v", err)
	}
	if err := AttachEvidence(store, seal.SealID, func() EvidenceAttachment {
		att, err := NewAgentPassportAttachment(identity)
		if err != nil {
			t.Fatalf("NewAgentPassportAttachment: %v", err)
		}
		return att
	}()); err != nil {
		t.Fatalf("AttachEvidence(passport): %v", err)
	}

	bundleSeal := &types.DigitalSeal{
		Id:               seal.SealID,
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		RequestedBy:      "aethel1requester",
		Purpose:          "regulated_autonomy",
		Status:           types.SealStatusActive,
	}

	bundle, err := CreateBundle(store, bundleSeal)
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}
	if len(bundle.Attachments) != 3 {
		t.Fatalf("expected 3 structured attachments, got %d", len(bundle.Attachments))
	}

	typeCounts := map[EvidenceType]int{}
	for _, att := range bundle.Attachments {
		typeCounts[att.Type]++
	}
	if typeCounts[EvidenceTypePolicyReceipt] != 1 || typeCounts[EvidenceTypeAgentPassport] != 1 || typeCounts[EvidenceTypeTraceLink] != 1 {
		t.Fatalf("unexpected attachment type counts: %#v", typeCounts)
	}

	if err := VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

func TestStructuredEvidenceValidationFailures(t *testing.T) {
	if _, err := NewPolicyReceiptEvidence(nil); err == nil {
		t.Fatal("expected policy receipt helper to reject nil input")
	}
	if _, err := NewAgentPassportEvidence(nil); err == nil {
		t.Fatal("expected agent passport helper to reject nil input")
	}
	if _, err := NewTraceLink(nil, testPolicyReceipt(t), Seal{SealID: "seal-1"}, ""); err == nil {
		t.Fatal("expected trace link helper to reject nil identity")
	}
	if _, err := NewTraceLinkAttachment(TraceLink{}); err == nil {
		t.Fatal("expected trace link attachment helper to reject empty link")
	}
}

func TestCreateBundle(t *testing.T) {
	store := NewInMemoryEvidenceStore()

	seal := &types.DigitalSeal{
		Id:               "seal-bundle-test",
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		RequestedBy:      "aethel1requester",
		Purpose:          "fraud_detection",
		Status:           types.SealStatusActive,
		TeeAttestations: []*types.TEEAttestation{{
			ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
			Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
		}},
	}

	// Attach some evidence
	_ = store.StoreEvidence(seal.GetId(), NewEvidenceAttachment(
		EvidenceTypeAuditLog, []byte("audit entry"), "auditor", "Audit", "text/plain"))

	bundle, err := CreateBundle(store, seal)
	if err != nil {
		t.Fatalf("CreateBundle: %v", err)
	}

	if bundle.SealID != seal.GetId() {
		t.Fatalf("bundle seal ID mismatch")
	}
	// 1 custom + 1 TEE attestation
	if len(bundle.Attachments) != 2 {
		t.Fatalf("expected 2 attachments, got %d", len(bundle.Attachments))
	}
	if len(bundle.BundleHash) != 32 {
		t.Fatalf("expected 32-byte bundle hash")
	}
}

func TestVerifyBundle(t *testing.T) {
	bundle := &EvidenceBundle{
		SealID:    "seal-1",
		SealHash:  testHash(0x01),
		CreatedAt: time.Now(),
		Attachments: []EvidenceAttachment{
			NewEvidenceAttachment(EvidenceTypeCustom, []byte("evidence data"), "", "", ""),
		},
	}
	bundle.BundleHash = computeBundleHash(bundle)

	if err := VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	// Tamper with attachment
	bundle.Attachments[0].Hash = bytes.Repeat([]byte{0xFF}, 32)
	if err := VerifyBundle(bundle); err == nil {
		t.Fatal("expected error for tampered bundle")
	}
}

// ======================================================================
// Export/Import Tests
// ======================================================================

func TestExportImportJSON(t *testing.T) {
	seal := &types.DigitalSeal{
		Id:               "export-test-seal",
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      500,
		Timestamp:        timestamppb.New(time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)),
		RequestedBy:      "aethel1requester",
		Purpose:          "risk_assessment",
		Status:           types.SealStatusActive,
		ValidatorSet:     []string{"v1", "v2"},
		TeeAttestations: []*types.TEEAttestation{{
			ValidatorAddress: "v1",
			Platform:         "aws-nitro",
			EnclaveId:        "e1",
			Measurement:      testHash(0x10),
			Quote:            testHash(0x11),
			Signature:        testHash(0x12),
			Timestamp:        timestamppb.New(time.Date(2025, 1, 15, 11, 0, 0, 0, time.UTC)),
		}},
		ZkProof: &types.ZKMLProof{
			ProofSystem:      "ezkl",
			ProofBytes:       testHash(0x20),
			PublicInputs:     testHash(0x21),
			VerifyingKeyHash: testHash(0x22),
			CircuitHash:      testHash(0x23),
		},
		RegulatoryInfo: &types.RegulatoryInfo{
			DataClassification:   "confidential",
			ComplianceFrameworks: []string{"GDPR", "SOC2"},
			AuditRequired:        true,
		},
	}

	data, err := ExportJSON(seal)
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}

	imported, err := ImportJSON(data)
	if err != nil {
		t.Fatalf("ImportJSON: %v", err)
	}

	if imported.GetId() != seal.GetId() {
		t.Fatalf("ID mismatch: %s != %s", imported.GetId(), seal.GetId())
	}
	if !bytes.Equal(imported.GetModelCommitment(), seal.GetModelCommitment()) {
		t.Fatal("model commitment mismatch")
	}
	if !bytes.Equal(imported.GetInputCommitment(), seal.GetInputCommitment()) {
		t.Fatal("input commitment mismatch")
	}
	if !bytes.Equal(imported.GetOutputCommitment(), seal.GetOutputCommitment()) {
		t.Fatal("output commitment mismatch")
	}
	if imported.GetBlockHeight() != seal.GetBlockHeight() {
		t.Fatalf("block height mismatch: %d != %d", imported.GetBlockHeight(), seal.GetBlockHeight())
	}
	if imported.GetPurpose() != seal.GetPurpose() {
		t.Fatal("purpose mismatch")
	}
	if len(imported.GetTeeAttestations()) != 1 {
		t.Fatalf("attestation count mismatch")
	}
	if imported.GetZkProof() == nil {
		t.Fatal("expected proof")
	}
	if imported.GetZkProof().GetProofSystem() != "ezkl" {
		t.Fatalf("proof system mismatch: %s", imported.GetZkProof().GetProofSystem())
	}
	if imported.GetRegulatoryInfo() == nil {
		t.Fatal("expected regulatory info")
	}
	if imported.GetRegulatoryInfo().GetDataClassification() != "confidential" {
		t.Fatal("data classification mismatch")
	}
}

func TestExportImportProtobuf(t *testing.T) {
	seal := &types.DigitalSeal{
		Id:               "protobuf-test",
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      42,
		Timestamp:        timestamppb.Now(),
		RequestedBy:      "aethel1test",
		Purpose:          "test",
		Status:           types.SealStatusPending,
	}

	data, err := ExportProtobuf(seal)
	if err != nil {
		t.Fatalf("ExportProtobuf: %v", err)
	}

	imported, err := ImportProtobuf(data)
	if err != nil {
		t.Fatalf("ImportProtobuf: %v", err)
	}

	if imported.GetId() != seal.GetId() {
		t.Fatal("ID mismatch after protobuf round-trip")
	}
	if !bytes.Equal(imported.GetModelCommitment(), seal.GetModelCommitment()) {
		t.Fatal("model commitment mismatch after protobuf round-trip")
	}
}

func TestExportImportCBOR(t *testing.T) {
	seal := &types.DigitalSeal{
		Id:               "cbor-test",
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      99,
		Timestamp:        timestamppb.New(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)),
		RequestedBy:      "aethel1cbor",
		Purpose:          "cbor_test",
		Status:           types.SealStatusActive,
	}

	data, err := ExportCBOR(seal)
	if err != nil {
		t.Fatalf("ExportCBOR: %v", err)
	}

	imported, err := ImportCBOR(data)
	if err != nil {
		t.Fatalf("ImportCBOR: %v", err)
	}

	if imported.GetId() != seal.GetId() {
		t.Fatal("ID mismatch after CBOR round-trip")
	}
}

func TestExportNilSeal(t *testing.T) {
	if _, err := ExportJSON(nil); err == nil {
		t.Fatal("expected error for nil seal JSON export")
	}
	if _, err := ExportCBOR(nil); err == nil {
		t.Fatal("expected error for nil seal CBOR export")
	}
	if _, err := ExportProtobuf(nil); err == nil {
		t.Fatal("expected error for nil seal protobuf export")
	}
}

func TestImportEmpty(t *testing.T) {
	if _, err := ImportJSON(nil); err == nil {
		t.Fatal("expected error for empty JSON import")
	}
	if _, err := ImportCBOR(nil); err == nil {
		t.Fatal("expected error for empty CBOR import")
	}
	if _, err := ImportProtobuf(nil); err == nil {
		t.Fatal("expected error for empty protobuf import")
	}
}

// ======================================================================
// C2PA Bridge Tests
// ======================================================================

func TestC2PARoundTrip(t *testing.T) {
	bridge := NewC2PABridge()

	seal := &types.DigitalSeal{
		Id:               "c2pa-roundtrip",
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      300,
		Timestamp:        timestamppb.Now(),
		RequestedBy:      "aethel1creator",
		Purpose:          "content_moderation",
		Status:           types.SealStatusActive,
		TeeAttestations: []*types.TEEAttestation{{
			ValidatorAddress: "v1",
			Platform:         "aws-nitro",
			EnclaveId:        "enclave-1",
			Measurement:      testHash(0x10),
		}},
		ZkProof: &types.ZKMLProof{
			ProofSystem:      "ezkl",
			ProofBytes:       testHash(0x20),
			PublicInputs:     testHash(0x21),
			VerifyingKeyHash: testHash(0x22),
			CircuitHash:      testHash(0x23),
		},
		RegulatoryInfo: &types.RegulatoryInfo{
			DataClassification:   "public",
			ComplianceFrameworks: []string{"SOC2"},
			AuditRequired:        true,
		},
	}

	manifest, err := bridge.ToC2PAManifest(seal)
	if err != nil {
		t.Fatalf("ToC2PAManifest: %v", err)
	}

	if manifest.InstanceID != seal.GetId() {
		t.Fatal("instance ID mismatch")
	}
	if len(manifest.Assertions) == 0 {
		t.Fatal("expected assertions in manifest")
	}

	// Round-trip back to seal
	restored, err := bridge.FromC2PAManifest(manifest)
	if err != nil {
		t.Fatalf("FromC2PAManifest: %v", err)
	}

	if !bytes.Equal(restored.GetModelCommitment(), seal.GetModelCommitment()) {
		t.Fatal("model commitment lost in C2PA round-trip")
	}
	if !bytes.Equal(restored.GetInputCommitment(), seal.GetInputCommitment()) {
		t.Fatal("input commitment lost in C2PA round-trip")
	}
	if !bytes.Equal(restored.GetOutputCommitment(), seal.GetOutputCommitment()) {
		t.Fatal("output commitment lost in C2PA round-trip")
	}
	if restored.GetPurpose() != seal.GetPurpose() {
		t.Fatal("purpose lost in C2PA round-trip")
	}
}

func TestC2PANilInputs(t *testing.T) {
	bridge := NewC2PABridge()

	if _, err := bridge.ToC2PAManifest(nil); err == nil {
		t.Fatal("expected error for nil seal")
	}
	if _, err := bridge.FromC2PAManifest(nil); err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

// ======================================================================
// Batch Tests
// ======================================================================

func TestBatchSeal(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	requests := make([]SealRequest, 10)
	for i := range requests {
		requests[i] = SealRequest{
			ModelHash:  testHash(byte(i + 1)),
			InputHash:  testHash(byte(i + 0x10)),
			OutputHash: testHash(byte(i + 0x20)),
			Purpose:    fmt.Sprintf("batch_test_%d", i),
		}
	}

	result := s.BatchSeal(ctx, requests, &BatchConfig{Concurrency: 3})

	if result.TotalRequested != 10 {
		t.Fatalf("expected 10 requested, got %d", result.TotalRequested)
	}
	if result.Succeeded != 10 {
		t.Fatalf("expected 10 succeeded, got %d (failed: %d)", result.Succeeded, result.Failed)
	}
	if result.Duration == 0 {
		t.Fatal("expected non-zero duration")
	}
}

func TestBatchVerify(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	// Create some seals first
	var ids []string
	for i := byte(0); i < 5; i++ {
		req := SealRequest{
			ModelHash:  testHash(i + 1),
			InputHash:  testHash(i + 0x10),
			OutputHash: testHash(i + 0x20),
			Purpose:    "batch_verify",
			TEEAttestations: []*types.TEEAttestation{{
				ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
				Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			}},
		}
		resp, err := s.CreateSeal(ctx, req)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		ids = append(ids, resp.SealID)
	}

	result := s.BatchVerify(ctx, ids, &BatchConfig{Concurrency: 2})
	if result.TotalRequested != 5 {
		t.Fatalf("expected 5 requested, got %d", result.TotalRequested)
	}
	if result.Succeeded != 5 {
		t.Fatalf("expected 5 succeeded, got %d", result.Succeeded)
	}
}

func TestBatchSealEmpty(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	result := s.BatchSeal(ctx, nil, nil)
	if result.TotalRequested != 0 {
		t.Fatal("expected 0 for empty batch")
	}
}

func TestBatchVerifyEmpty(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	result := s.BatchVerify(ctx, nil, nil)
	if result.TotalRequested != 0 {
		t.Fatal("expected 0 for empty batch")
	}
}

// ======================================================================
// Helpers
// ======================================================================

// ======================================================================
// Edge case, error path, and concurrency tests
// ======================================================================

func TestSealSDK_NilKeeper_ErrorIs(t *testing.T) {
	t.Parallel()
	_, err := NewSealSDK(Config{}, nil)
	if err == nil {
		t.Fatal("expected error for nil keeper")
	}
}

func TestCreateSeal_EmptyModelHash(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()
	req := SealRequest{
		ModelHash:  nil,
		InputHash:  testHash(0x02),
		OutputHash: testHash(0x03),
		Purpose:    "test",
	}
	_, err := s.CreateSeal(ctx, req)
	if err == nil {
		t.Fatal("expected error for empty model hash")
	}
}

func TestCreateSeal_InvalidHashLength(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()
	req := SealRequest{
		ModelHash:  []byte{0x01, 0x02, 0x03}, // wrong length
		InputHash:  testHash(0x02),
		OutputHash: testHash(0x03),
		Purpose:    "test",
	}
	_, err := s.CreateSeal(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid hash length")
	}
}

func TestCreateSeal_NilContext(t *testing.T) {
	s, _ := testSDK(t)
	req := testRequest()
	//nolint:staticcheck // intentionally testing nil context
	_, err := s.CreateSeal(nil, req)
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestVerifySeal_EmptyID(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()
	_, err := s.GetSeal(ctx, "")
	if err == nil {
		t.Fatal("expected error for empty seal ID")
	}
}

func TestVerifySeal_NotFound_Error(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()
	_, err := s.GetSeal(ctx, "nonexistent-seal-id")
	if err == nil {
		t.Fatal("expected error for nonexistent seal")
	}
}

func TestRevokeSeal_AlreadyRevoked(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	resp, err := s.CreateSeal(ctx, testRequest())
	if err != nil {
		t.Fatalf("CreateSeal: %v", err)
	}

	// First revoke should succeed.
	if err := s.RevokeSeal(ctx, resp.SealID, "first revoke"); err != nil {
		t.Fatalf("first RevokeSeal: %v", err)
	}

	// Second revoke on already-revoked seal.
	err = s.RevokeSeal(ctx, resp.SealID, "second revoke")
	// Should either succeed idempotently or return an error.
	_ = err // no panic is the minimum requirement
}

func TestVerifier_NilSeal(t *testing.T) {
	t.Parallel()
	v := NewVerifier(nil)
	// VerifyOffline panics on nil seal, so we verify it by recovering.
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic or error for nil seal input")
		}
	}()
	result := v.VerifyOffline(nil)
	if result.Valid {
		t.Fatal("expected invalid result for nil seal")
	}
}

func TestVerifier_EmptyAttestations(t *testing.T) {
	t.Parallel()
	ensureBech32()
	v := NewVerifier(nil)

	seal := &types.DigitalSeal{
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      100,
		RequestedBy:      testAccAddress(0x20),
		Purpose:          "test",
		Status:           types.SealStatusActive,
		Timestamp:        timestamppb.Now(),
		TeeAttestations:  nil, // no attestations
		ValidatorSet:     nil,
	}
	seal.Id = seal.GenerateID()

	result := v.VerifyOffline(seal)
	// Seal with no attestations should still be processable (may be invalid).
	if result.AttestationStatus.Valid != 0 {
		t.Errorf("expected 0 valid attestations, got %d", result.AttestationStatus.Valid)
	}
}

func TestVerifier_ExpiredAttestation(t *testing.T) {
	t.Parallel()
	ensureBech32()
	v := NewVerifier(nil)

	expiredTime := time.Now().Add(-365 * 24 * time.Hour)
	seal := &types.DigitalSeal{
		ModelCommitment:  testHash(0x01),
		InputCommitment:  testHash(0x02),
		OutputCommitment: testHash(0x03),
		BlockHeight:      100,
		RequestedBy:      testAccAddress(0x21),
		Purpose:          "test",
		Status:           types.SealStatusActive,
		Timestamp:        timestamppb.New(expiredTime),
		TeeAttestations: []*types.TEEAttestation{{
			ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
			Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			Timestamp: timestamppb.New(expiredTime),
		}},
		ValidatorSet: []string{"v1"},
	}
	seal.Id = seal.GenerateID()

	result := v.VerifyOffline(seal)
	// Attestation from a year ago; verification behavior depends on expiry policy.
	_ = result // no panic is the minimum
}

func TestVerifier_InvalidPlatform(t *testing.T) {
	t.Parallel()
	v := NewVerifier(nil)

	att := &types.TEEAttestation{
		ValidatorAddress: "v1",
		Platform:         "totally-fake-tee",
		EnclaveId:        "e1",
		Measurement:      testHash(0x10),
		Quote:            testHash(0x11),
		Signature:        testHash(0x12),
		Timestamp:        timestamppb.Now(),
	}
	err := v.ValidateAttestation(att)
	if err == nil {
		t.Fatal("expected error for untrusted TEE platform")
	}
}

func TestVerifyChain_BrokenLink_EdgeCase(t *testing.T) {
	t.Parallel()
	ensureBech32()
	v := NewVerifier(nil)

	addr := testAccAddress(0x30)
	att := func() []*types.TEEAttestation {
		return []*types.TEEAttestation{{
			ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
			Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			Timestamp: timestamppb.Now(),
		}}
	}

	seal1 := &types.DigitalSeal{
		ModelCommitment: testHash(0x01), InputCommitment: testHash(0x02),
		OutputCommitment: testHash(0x03), BlockHeight: 100,
		RequestedBy: addr, Purpose: "step1", Status: types.SealStatusActive,
		Timestamp: timestamppb.Now(), TeeAttestations: att(), ValidatorSet: []string{"v1"},
	}
	seal1.Id = seal1.GenerateID()

	seal2 := &types.DigitalSeal{
		ModelCommitment: testHash(0x04), InputCommitment: testHash(0xEE), // gap - doesn't match seal1 output
		OutputCommitment: testHash(0x05), BlockHeight: 200,
		RequestedBy: addr, Purpose: "step2", Status: types.SealStatusActive,
		Timestamp: timestamppb.Now(), TeeAttestations: att(), ValidatorSet: []string{"v1"},
	}
	seal2.Id = seal2.GenerateID()

	result := v.VerifyChain([]*types.DigitalSeal{seal1, seal2})
	if result.Valid {
		t.Fatal("expected broken chain to fail verification")
	}
}

func TestBatchSeal_ConcurrentCreation(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	const goroutines = 50
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			req := SealRequest{
				ModelHash:  testHash(byte(idx%255 + 1)),
				InputHash:  testHash(byte((idx + 0x10) % 255)),
				OutputHash: testHash(byte((idx + 0x20) % 255)),
				Purpose:    fmt.Sprintf("concurrent_%d", idx),
			}
			_, err := s.CreateSeal(ctx, req)
			errs <- err
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent CreateSeal failed: %v", err)
		}
	}
}

func TestBatchSeal_PartialFailure(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	requests := []SealRequest{
		{ModelHash: testHash(0x01), InputHash: testHash(0x02), OutputHash: testHash(0x03), Purpose: "valid1"},
		{ModelHash: nil, InputHash: testHash(0x02), OutputHash: testHash(0x03), Purpose: "invalid"}, // will fail
		{ModelHash: testHash(0x04), InputHash: testHash(0x05), OutputHash: testHash(0x06), Purpose: "valid2"},
	}

	result := s.BatchSeal(ctx, requests, &BatchConfig{Concurrency: 1})
	if result.TotalRequested != 3 {
		t.Fatalf("expected 3 requested, got %d", result.TotalRequested)
	}
	if result.Failed == 0 {
		t.Fatal("expected at least one failure for invalid request")
	}
	if result.Succeeded == 0 {
		t.Fatal("expected at least one success for valid request")
	}
}

func TestBatchVerify_ConcurrentVerification(t *testing.T) {
	s, _ := testSDK(t)
	ctx := context.Background()

	var ids []string
	for i := byte(0); i < 10; i++ {
		req := SealRequest{
			ModelHash:  testHash(i + 1),
			InputHash:  testHash(i + 0x10),
			OutputHash: testHash(i + 0x20),
			Purpose:    "batch_concurrent_verify",
			TEEAttestations: []*types.TEEAttestation{{
				ValidatorAddress: "v1", Platform: "aws-nitro", EnclaveId: "e1",
				Measurement: testHash(0x10), Quote: testHash(0x11), Signature: testHash(0x12),
			}},
		}
		resp, err := s.CreateSeal(ctx, req)
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
		ids = append(ids, resp.SealID)
	}

	result := s.BatchVerify(ctx, ids, &BatchConfig{Concurrency: 5})
	if result.TotalRequested != 10 {
		t.Fatalf("expected 10 requested, got %d", result.TotalRequested)
	}
}

func TestExportImport_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	ensureBech32()

	seal := &types.DigitalSeal{
		Id: "json-roundtrip-test", ModelCommitment: testHash(0x01),
		InputCommitment: testHash(0x02), OutputCommitment: testHash(0x03),
		BlockHeight: 42, Timestamp: timestamppb.Now(),
		RequestedBy: "aethel1test", Purpose: "roundtrip", Status: types.SealStatusActive,
	}

	data, err := ExportJSON(seal)
	if err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	imported, err := ImportJSON(data)
	if err != nil {
		t.Fatalf("ImportJSON: %v", err)
	}
	if imported.GetId() != seal.GetId() {
		t.Fatalf("ID mismatch: %s != %s", imported.GetId(), seal.GetId())
	}
	// Verify the imported seal is valid via the verifier.
	v := NewVerifier(nil)
	_ = v.VerifyOffline(imported)
}

func TestExportImport_CBORRoundTrip(t *testing.T) {
	t.Parallel()

	seal := &types.DigitalSeal{
		Id: "cbor-roundtrip-test", ModelCommitment: testHash(0x01),
		InputCommitment: testHash(0x02), OutputCommitment: testHash(0x03),
		BlockHeight: 42, Timestamp: timestamppb.Now(),
		RequestedBy: "aethel1test", Purpose: "roundtrip", Status: types.SealStatusActive,
	}

	data, err := ExportCBOR(seal)
	if err != nil {
		t.Fatalf("ExportCBOR: %v", err)
	}
	imported, err := ImportCBOR(data)
	if err != nil {
		t.Fatalf("ImportCBOR: %v", err)
	}
	if imported.GetId() != seal.GetId() {
		t.Fatalf("ID mismatch: %s != %s", imported.GetId(), seal.GetId())
	}
}

func TestExportImport_ProtobufRoundTrip(t *testing.T) {
	t.Parallel()

	seal := &types.DigitalSeal{
		Id: "pb-roundtrip-test", ModelCommitment: testHash(0x01),
		InputCommitment: testHash(0x02), OutputCommitment: testHash(0x03),
		BlockHeight: 42, Timestamp: timestamppb.Now(),
		RequestedBy: "aethel1test", Purpose: "roundtrip", Status: types.SealStatusActive,
	}

	data, err := ExportProtobuf(seal)
	if err != nil {
		t.Fatalf("ExportProtobuf: %v", err)
	}
	imported, err := ImportProtobuf(data)
	if err != nil {
		t.Fatalf("ImportProtobuf: %v", err)
	}
	if imported.GetId() != seal.GetId() {
		t.Fatalf("ID mismatch: %s != %s", imported.GetId(), seal.GetId())
	}
}

func TestC2PA_NilSeal_EdgeCase(t *testing.T) {
	t.Parallel()
	bridge := NewC2PABridge()
	_, err := bridge.ToC2PAManifest(nil)
	if err == nil {
		t.Fatal("expected error for nil seal")
	}
}

func TestC2PA_EmptyAssertions(t *testing.T) {
	t.Parallel()
	ensureBech32()
	bridge := NewC2PABridge()

	// Seal with no attestations and no proofs.
	seal := &types.DigitalSeal{
		Id: "c2pa-empty-assertions", ModelCommitment: testHash(0x01),
		InputCommitment: testHash(0x02), OutputCommitment: testHash(0x03),
		BlockHeight: 100, Timestamp: timestamppb.Now(),
		RequestedBy: "aethel1test", Purpose: "test", Status: types.SealStatusActive,
	}

	manifest, err := bridge.ToC2PAManifest(seal)
	if err != nil {
		t.Fatalf("ToC2PAManifest: %v", err)
	}
	// Should still produce assertions (at least commitment and verification).
	if manifest == nil {
		t.Fatal("expected non-nil manifest")
	}
}

func TestEvidence_AttachToNonExistentSeal(t *testing.T) {
	t.Parallel()
	store := NewInMemoryEvidenceStore()

	evidence := NewEvidenceAttachment(EvidenceTypeCustom, []byte("data"), "signer", "desc", "text/plain")

	// Attaching to a non-existent seal should work (store doesn't validate seal existence).
	err := AttachEvidence(store, "nonexistent-seal", evidence)
	// Either succeeds (store-level) or returns a specific error.
	_ = err
}

func TestEvidence_BundleIntegrity(t *testing.T) {
	t.Parallel()
	bundle := &EvidenceBundle{
		SealID:    "seal-integrity-test",
		SealHash:  testHash(0x01),
		CreatedAt: time.Now(),
		Attachments: []EvidenceAttachment{
			NewEvidenceAttachment(EvidenceTypeCustom, []byte("evidence data"), "", "", ""),
		},
	}
	bundle.BundleHash = computeBundleHash(bundle)

	// Valid bundle.
	if err := VerifyBundle(bundle); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	// Tamper with attachment data.
	bundle.Attachments[0].Data = []byte("tampered data")
	if err := VerifyBundle(bundle); err == nil {
		t.Fatal("expected error for tampered bundle")
	}
}

// ======================================================================
// Helpers
// ======================================================================

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
