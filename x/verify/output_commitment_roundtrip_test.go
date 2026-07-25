package verify_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/x/verify"
	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

func roundTripHash(label string) []byte {
	digest := sha256.Sum256([]byte(label))
	return digest[:]
}

func roundTripOrchestratorConfig() verify.OrchestratorConfig {
	config := verify.DefaultOrchestratorConfig()
	proverConfig := ezkl.DefaultProverConfig()
	proverConfig.AllowSimulated = true
	nitroConfig := tee.DefaultNitroConfig()
	nitroConfig.AllowSimulated = true
	config.ProverConfig = &proverConfig
	config.NitroConfig = &nitroConfig
	config.CacheEnabled = false
	config.RequireBothForHybrid = true
	config.VerificationTimeout = time.Minute
	return config
}

func TestPureZKOutputCommitmentRoundTrip(t *testing.T) {
	output := []byte("canonical-model-output")
	expectedOutputHash := sha256.Sum256(output)
	orchestrator := verify.NewVerificationOrchestrator(
		log.NewNopLogger(),
		roundTripOrchestratorConfig(),
	)
	request := &verify.VerificationRequest{
		RequestID:          "pure-zk-round-trip",
		ModelHash:          roundTripHash("model"),
		InputHash:          roundTripHash("input"),
		InputData:          []byte("input"),
		ExpectedOutputHash: expectedOutputHash[:],
		OutputData:         output,
		VerificationType:   types.VerificationTypeZKML,
		CircuitHash:        roundTripHash("circuit"),
		VerifyingKeyHash:   roundTripHash("verifying-key"),
	}

	response, err := orchestrator.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("pure ZK verification returned an error: %v", err)
	}
	if !response.Success {
		t.Fatalf("pure ZK verification failed: %s", response.Error)
	}
	if response.ZKMLResult == nil || response.ZKMLResult.PublicInputs == nil {
		t.Fatal("pure ZK response omitted verified public inputs")
	}
	if !bytes.Equal(response.OutputHash, expectedOutputHash[:]) ||
		!bytes.Equal(response.ZKMLResult.OutputHash, expectedOutputHash[:]) ||
		!bytes.Equal(response.ZKMLResult.PublicInputs.OutputCommitment, expectedOutputHash[:]) {
		t.Fatal("canonical OutputHash did not round-trip through verified public inputs")
	}
	doubleHash := sha256.Sum256(expectedOutputHash[:])
	if bytes.Equal(response.OutputHash, doubleHash[:]) {
		t.Fatal("pure ZK response returned a double-hashed output commitment")
	}
}

func TestPureZKRemoteProverReturnsPreviouslyUnknownOutputHash(t *testing.T) {
	remoteOutputHash := sha256.Sum256([]byte("remote-computed-output"))
	remotePublicInputs := &ezkl.PublicInputs{
		ModelCommitment:  roundTripHash("remote-model-commitment"),
		InputCommitment:  roundTripHash("remote-input-commitment"),
		OutputCommitment: remoteOutputHash[:],
		Instances:        [][]byte{roundTripHash("remote-instance")},
	}
	remoteProof := []byte("remote-proof")

	prover := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/prove":
			var request ezkl.ProofRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				http.Error(w, "invalid proof request", http.StatusBadRequest)
				return
			}
			if len(request.OutputHash) != 0 {
				http.Error(w, "expected previously unknown output hash", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(ezkl.ProofResult{
				Success:      true,
				Proof:        remoteProof,
				PublicInputs: remotePublicInputs,
			})
		case "/verify":
			var request struct {
				Proof        []byte             `json:"proof"`
				PublicInputs *ezkl.PublicInputs `json:"public_inputs"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
				!bytes.Equal(request.Proof, remoteProof) ||
				request.PublicInputs == nil ||
				!bytes.Equal(request.PublicInputs.OutputCommitment, remoteOutputHash[:]) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"verified": false,
					"error":    "proof/public-input mismatch",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"verified": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer prover.Close()

	config := roundTripOrchestratorConfig()
	proverConfig := ezkl.DefaultProverConfig()
	proverConfig.ProverEndpoint = prover.URL
	proverConfig.AllowSimulated = false
	config.ProverConfig = &proverConfig
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), config)
	request := &verify.VerificationRequest{
		RequestID:        "remote-pure-zk-round-trip",
		ModelHash:        roundTripHash("remote-model"),
		InputHash:        roundTripHash("remote-input"),
		InputData:        []byte("remote-input"),
		VerificationType: types.VerificationTypeZKML,
		CircuitHash:      roundTripHash("remote-circuit"),
		VerifyingKeyHash: roundTripHash("remote-verifying-key"),
	}

	response, err := orchestrator.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("remote pure ZK verification returned an error: %v", err)
	}
	if !response.Success {
		t.Fatalf("remote pure ZK verification failed: %s", response.Error)
	}
	if !bytes.Equal(response.OutputHash, remoteOutputHash[:]) ||
		response.ZKMLResult == nil ||
		!bytes.Equal(response.ZKMLResult.OutputHash, remoteOutputHash[:]) {
		t.Fatal("remote proof-authenticated OutputHash did not round-trip")
	}
}

func TestOutputHashExtractionRejectsMalformedPublicCommitment(t *testing.T) {
	if _, err := ezkl.OutputHashFromPublicInputs(&ezkl.PublicInputs{
		OutputCommitment: []byte("short"),
	}); err == nil {
		t.Fatal("expected malformed verified output commitment to fail closed")
	}
}

func TestHybridForcesSequentialTEEToZKRoundTrip(t *testing.T) {
	config := roundTripOrchestratorConfig()
	// This legacy setting must not re-enable the unsafe independent goroutines.
	config.ParallelVerification = true
	orchestrator := verify.NewVerificationOrchestrator(log.NewNopLogger(), config)
	if err := orchestrator.Initialize(context.Background()); err != nil {
		t.Fatalf("initialize hybrid orchestrator: %v", err)
	}
	request := &verify.VerificationRequest{
		RequestID:        "hybrid-round-trip",
		ModelHash:        roundTripHash("hybrid-model"),
		InputHash:        roundTripHash("hybrid-input"),
		InputData:        []byte("hybrid-input"),
		VerificationType: types.VerificationTypeHybrid,
		CircuitHash:      roundTripHash("hybrid-circuit"),
		VerifyingKeyHash: roundTripHash("hybrid-verifying-key"),
	}

	response, err := orchestrator.Verify(context.Background(), request)
	if err != nil {
		t.Fatalf("hybrid verification returned an error: %v", err)
	}
	if !response.Success {
		t.Fatalf("hybrid verification failed: %s", response.Error)
	}
	if response.TEEResult == nil ||
		response.ZKMLResult == nil ||
		response.ZKMLResult.PublicInputs == nil {
		t.Fatal("hybrid response omitted verification results")
	}
	if len(response.OutputHash) != sha256.Size ||
		!bytes.Equal(response.OutputHash, response.TEEResult.OutputHash) ||
		!bytes.Equal(response.OutputHash, response.ZKMLResult.OutputHash) ||
		!bytes.Equal(response.OutputHash, response.ZKMLResult.PublicInputs.OutputCommitment) {
		t.Fatal("TEE and zkML did not authenticate the same canonical OutputHash")
	}
	if len(request.ExpectedOutputHash) != 0 {
		t.Fatal("hybrid verification mutated the caller's request")
	}
}
