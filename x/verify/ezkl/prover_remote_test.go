package ezkl

import (
	"context"
	"strings"
	"testing"

	"cosmossdk.io/log"
)

func TestCallRemoteProver_RejectsInvalidEndpoint(t *testing.T) {
	t.Parallel()

	ps := NewProverService(log.NewNopLogger(), ProverConfig{
		ProverEndpoint: "https://169.254.169.254",
	})

	_, err := ps.CallRemoteProver(context.Background(), &ProofRequest{})
	if err == nil {
		t.Fatal("expected invalid prover endpoint to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid prover endpoint") {
		t.Fatalf("expected invalid prover endpoint error, got %v", err)
	}
}

func TestCallRemoteVerifier_RejectsInvalidEndpoint(t *testing.T) {
	t.Parallel()

	ps := NewProverService(log.NewNopLogger(), ProverConfig{
		ProverEndpoint: "https://169.254.169.254",
	})

	ok, err := ps.CallRemoteVerifier(context.Background(), nil, nil, nil)
	if err == nil {
		t.Fatal("expected invalid verifier endpoint to be rejected")
	}
	if ok {
		t.Fatal("expected verifier result to fail closed")
	}
	if !strings.Contains(err.Error(), "invalid verifier endpoint") {
		t.Fatalf("expected invalid verifier endpoint error, got %v", err)
	}
}
