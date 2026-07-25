package ezkl

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"cosmossdk.io/log"
)

func TestNewProverServiceLoadsAPITokenFromEnvironment(t *testing.T) {
	t.Setenv(zkMLAPITokenEnv, "  environment-token  ")

	ps := NewProverService(log.NewNopLogger(), DefaultProverConfig())

	if ps.config.APIToken != "environment-token" {
		t.Fatalf("expected trimmed API token from %s, got %q", zkMLAPITokenEnv, ps.config.APIToken)
	}

	cfg := DefaultProverConfig()
	cfg.APIToken = " explicit-token "
	ps = NewProverService(log.NewNopLogger(), cfg)
	if ps.config.APIToken != "explicit-token" {
		t.Fatalf("expected explicit API token to override environment, got %q", ps.config.APIToken)
	}
}

func TestRemoteProverAndVerifierSendBearerToken(t *testing.T) {
	seen := make(chan [2]string, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- [2]string{r.URL.Path, r.Header.Get("Authorization")}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/prove":
			_ = json.NewEncoder(w).Encode(&ProofResult{Success: true})
		case "/verify":
			_ = json.NewEncoder(w).Encode(map[string]bool{"verified": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()

	cfg := DefaultProverConfig()
	cfg.ProverEndpoint = backend.URL
	cfg.APIToken = "client-secret"
	ps := NewProverService(log.NewNopLogger(), cfg)
	ps.client = backend.Client()
	ps.clientErr = nil

	if _, err := ps.CallRemoteProver(context.Background(), &ProofRequest{}); err != nil {
		t.Fatalf("remote prover call failed: %v", err)
	}
	proveRequest := <-seen
	if proveRequest[0] != "/prove" || proveRequest[1] != "Bearer client-secret" {
		t.Fatalf("unexpected prover request auth: path=%q authorization=%q", proveRequest[0], proveRequest[1])
	}

	verified, err := ps.CallRemoteVerifier(context.Background(), []byte("proof"), &PublicInputs{}, []byte("vk"))
	if err != nil {
		t.Fatalf("remote verifier call failed: %v", err)
	}
	if !verified {
		t.Fatal("expected remote verifier response to be accepted")
	}
	verifyRequest := <-seen
	if verifyRequest[0] != "/verify" || verifyRequest[1] != "Bearer client-secret" {
		t.Fatalf("unexpected verifier request auth: path=%q authorization=%q", verifyRequest[0], verifyRequest[1])
	}
}

func TestGenerateProofRejectsMalformedRequestsWithoutPanicking(t *testing.T) {
	t.Parallel()

	validHash := make([]byte, sha256.Size)
	testCases := []struct {
		name string
		req  *ProofRequest
	}{
		{name: "nil request", req: nil},
		{
			name: "short model hash",
			req: &ProofRequest{
				ModelHash:        []byte{1},
				CircuitHash:      validHash,
				InputHash:        validHash,
				OutputHash:       validHash,
				VerifyingKeyHash: validHash,
			},
		},
		{
			name: "short input hash",
			req: &ProofRequest{
				ModelHash:        validHash,
				CircuitHash:      validHash,
				InputHash:        []byte{1},
				OutputHash:       validHash,
				VerifyingKeyHash: validHash,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ps := NewProverService(log.NewNopLogger(), DefaultProverConfig())
			if _, err := ps.GenerateProof(context.Background(), tc.req); err == nil {
				t.Fatal("expected malformed proof request to fail")
			}
		})
	}
}

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

func TestSimulatedProofStillRequiresKnownOutputHash(t *testing.T) {
	t.Parallel()

	config := DefaultProverConfig()
	config.AllowSimulated = true
	prover := NewProverService(log.NewNopLogger(), config)
	validHash := make([]byte, sha256.Size)
	result, err := prover.GenerateProof(context.Background(), &ProofRequest{
		ModelHash:        validHash,
		CircuitHash:      validHash,
		InputHash:        validHash,
		VerifyingKeyHash: validHash,
	})
	if err != nil {
		t.Fatalf("expected a structured simulated proof failure, got %v", err)
	}
	if result == nil || result.Success {
		t.Fatal("simulated prover accepted an unknown output commitment")
	}
	if !strings.Contains(result.Error, "output hash must be exactly") {
		t.Fatalf("unexpected simulated prover error: %q", result.Error)
	}
}
