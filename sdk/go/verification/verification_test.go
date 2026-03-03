package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aethelred/sdk-go/types"
)

type mockClient struct {
	getResp  interface{}
	postResp interface{}
	getErr   error
	postErr  error
	lastPath string
}

func (m *mockClient) Get(_ context.Context, path string, result interface{}) error {
	m.lastPath = path
	if m.getErr != nil {
		return m.getErr
	}
	data, _ := json.Marshal(m.getResp)
	return json.Unmarshal(data, result)
}

func (m *mockClient) Post(_ context.Context, path string, body, result interface{}) error {
	m.lastPath = path
	if m.postErr != nil {
		return m.postErr
	}
	if result == nil {
		return nil
	}
	data, _ := json.Marshal(m.postResp)
	return json.Unmarshal(data, result)
}

func TestNewModule(t *testing.T) {
	t.Parallel()
	m := NewModule(&mockClient{})
	if m == nil {
		t.Fatal("NewModule returned nil")
	}
}

func TestVerifyZKProof(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postResp: VerifyZKProofResponse{
		Valid: true, VerificationTimeMs: 42,
	}}
	m := NewModule(mc)

	resp, err := m.VerifyZKProof(context.Background(), VerifyZKProofRequest{
		Proof:            "proof_bytes_hex",
		PublicInputs:     []string{"input1", "input2"},
		VerifyingKeyHash: "vk_hash",
		ProofSystem:      "PROOF_SYSTEM_GROTH16",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Valid {
		t.Fatal("expected valid proof")
	}
	if resp.VerificationTimeMs != 42 {
		t.Fatalf("VerificationTimeMs = %d", resp.VerificationTimeMs)
	}
	if mc.lastPath != "/aethelred/verify/v1/zkproofs:verify" {
		t.Fatalf("path = %s", mc.lastPath)
	}
}

func TestVerifyTEEAttestation(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postResp: VerifyTEEResponse{
		Valid:    true,
		Platform: types.TEEPlatformIntelSGX,
	}}
	m := NewModule(mc)

	resp, err := m.VerifyTEEAttestation(context.Background(), types.TEEAttestation{
		Platform:    types.TEEPlatformIntelSGX,
		Quote:       "quote_data",
		EnclaveHash: "enclave_hash",
	}, "expected_hash")
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Valid {
		t.Fatal("expected valid attestation")
	}
	if resp.Platform != types.TEEPlatformIntelSGX {
		t.Fatalf("Platform = %s", resp.Platform)
	}
	if mc.lastPath != "/aethelred/verify/v1/tee/attestation:verify" {
		t.Fatalf("path = %s", mc.lastPath)
	}
}

func TestVerifyZKProofError(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postErr: fmt.Errorf("verification service down")}
	m := NewModule(mc)

	_, err := m.VerifyZKProof(context.Background(), VerifyZKProofRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyTEEError(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postErr: fmt.Errorf("service error")}
	m := NewModule(mc)

	_, err := m.VerifyTEEAttestation(context.Background(), types.TEEAttestation{}, "hash")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyZKProofInvalid(t *testing.T) {
	t.Parallel()

	mc := &mockClient{postResp: VerifyZKProofResponse{
		Valid: false, Error: "invalid proof data",
	}}
	m := NewModule(mc)

	resp, err := m.VerifyZKProof(context.Background(), VerifyZKProofRequest{
		Proof: "bad_proof",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Valid {
		t.Fatal("expected invalid proof")
	}
	if resp.Error != "invalid proof data" {
		t.Fatalf("Error = %s", resp.Error)
	}
}
