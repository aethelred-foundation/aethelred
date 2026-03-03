// Package verification provides proof verification operations.
package verification

import (
	"context"

	"github.com/aethelred/sdk-go/types"
)

type Client interface {
	Get(ctx context.Context, path string, result interface{}) error
	Post(ctx context.Context, path string, body, result interface{}) error
}

const basePath = "/aethelred/verify/v1"

type Module struct {
	client Client
}

func NewModule(client Client) *Module {
	return &Module{client: client}
}

type VerifyZKProofRequest struct {
	Proof            string   `json:"proof"`
	PublicInputs     []string `json:"public_inputs"`
	VerifyingKeyHash string   `json:"verifying_key_hash"`
	ProofSystem      string   `json:"proof_system,omitempty"`
}

type VerifyZKProofResponse struct {
	Valid              bool   `json:"valid"`
	VerificationTimeMs uint64 `json:"verification_time_ms"`
	Error              string `json:"error,omitempty"`
}

type VerifyTEEResponse struct {
	Valid       bool             `json:"valid"`
	Platform    types.TEEPlatform `json:"platform"`
	EnclaveHash string           `json:"enclave_hash,omitempty"`
	Error       string           `json:"error,omitempty"`
}

func (m *Module) VerifyZKProof(ctx context.Context, req VerifyZKProofRequest) (*VerifyZKProofResponse, error) {
	var resp VerifyZKProofResponse
	if err := m.client.Post(ctx, basePath+"/zkproofs:verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (m *Module) VerifyTEEAttestation(ctx context.Context, attestation types.TEEAttestation, expectedEnclaveHash string) (*VerifyTEEResponse, error) {
	req := map[string]interface{}{
		"attestation":           attestation,
		"expected_enclave_hash": expectedEnclaveHash,
	}
	var resp VerifyTEEResponse
	if err := m.client.Post(ctx, basePath+"/tee/attestation:verify", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
