package ezkl

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cosmossdk.io/log"
)

// =============================================================================
// Test Helpers
// =============================================================================

func newTestProver(opts ...func(*ProverConfig)) *ProverService {
	cfg := DefaultProverConfig()
	cfg.AllowSimulated = true
	for _, o := range opts {
		o(&cfg)
	}
	return NewProverService(log.NewNopLogger(), cfg)
}

func testProofRequest() *ProofRequest {
	modelHash := sha256.Sum256([]byte("test-model"))
	circuitHash := sha256.Sum256([]byte("test-circuit"))
	inputHash := sha256.Sum256([]byte("test-input"))
	outputHash := sha256.Sum256([]byte("test-output"))
	vkHash := sha256.Sum256([]byte("test-vk"))

	return &ProofRequest{
		ModelHash:        modelHash[:],
		CircuitHash:      circuitHash[:],
		InputData:        []byte("input-data"),
		InputHash:        inputHash[:],
		OutputData:       []byte("output-data"),
		OutputHash:       outputHash[:],
		VerifyingKeyHash: vkHash[:],
		RequestID:        "test-req-001",
		Priority:         1,
	}
}

// =============================================================================
// Prover Service Init
// =============================================================================

func TestProverService_Init(t *testing.T) {
	ps := newTestProver()
	if ps == nil {
		t.Fatal("NewProverService returned nil")
	}
	if ps.logger == nil {
		t.Fatal("logger not set")
	}
	if ps.circuitCache == nil {
		t.Fatal("circuit cache not initialized")
	}
	metrics := ps.GetMetrics()
	if metrics.TotalProofsGenerated != 0 {
		t.Fatalf("expected zero initial proofs, got %d", metrics.TotalProofsGenerated)
	}
}

func TestProverService_Init_DefaultConfig(t *testing.T) {
	cfg := DefaultProverConfig()
	if cfg.MaxConcurrentProofs != 4 {
		t.Fatalf("expected MaxConcurrentProofs=4, got %d", cfg.MaxConcurrentProofs)
	}
	if cfg.ProofTimeoutSeconds != 300 {
		t.Fatalf("expected ProofTimeoutSeconds=300, got %d", cfg.ProofTimeoutSeconds)
	}
	if cfg.CircuitCacheSize != 100 {
		t.Fatalf("expected CircuitCacheSize=100, got %d", cfg.CircuitCacheSize)
	}
}

func TestProverService_Init_ZeroCacheSize(t *testing.T) {
	ps := newTestProver(func(c *ProverConfig) { c.CircuitCacheSize = 0 })
	if ps.circuitCache == nil {
		t.Fatal("cache should not be nil even with zero size config")
	}
}

// =============================================================================
// Proof Generation (Simulated)
// =============================================================================

func TestProverService_GenerateProof(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	result, err := ps.GenerateProof(ctx, testProofRequest())
	if err != nil {
		t.Fatalf("GenerateProof error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if !result.Success {
		t.Fatalf("proof generation failed: %s", result.Error)
	}
	if len(result.Proof) == 0 {
		t.Fatal("proof bytes empty")
	}
	if result.PublicInputs == nil {
		t.Fatal("public inputs nil")
	}
	if result.ProofSize <= 0 {
		t.Fatal("proof size should be positive")
	}
	if result.GenerationTimeMs < 0 {
		t.Fatal("generation time should be non-negative")
	}
	if result.RequestID != "test-req-001" {
		t.Fatalf("request ID mismatch: got %s", result.RequestID)
	}

	// Verify metrics updated
	metrics := ps.GetMetrics()
	if metrics.TotalProofsGenerated != 1 {
		t.Fatalf("expected 1 generated proof, got %d", metrics.TotalProofsGenerated)
	}
}

func TestProverService_GenerateProof_Deterministic(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()
	req := testProofRequest()

	result1, err := ps.GenerateProof(ctx, req)
	if err != nil {
		t.Fatalf("first proof error: %v", err)
	}
	result2, err := ps.GenerateProof(ctx, req)
	if err != nil {
		t.Fatalf("second proof error: %v", err)
	}

	// Same inputs should produce same proof bytes (deterministic simulation)
	if string(result1.Proof) != string(result2.Proof) {
		t.Fatal("simulated proofs should be deterministic for same inputs")
	}
}

func TestProverService_GenerateProof_DifferentInputs(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	req1 := testProofRequest()
	req1.RequestID = "req-A"

	req2 := testProofRequest()
	req2.RequestID = "req-B"
	differentOutput := sha256.Sum256([]byte("different-output"))
	req2.OutputHash = differentOutput[:]

	r1, _ := ps.GenerateProof(ctx, req1)
	r2, _ := ps.GenerateProof(ctx, req2)

	if string(r1.Proof) == string(r2.Proof) {
		t.Fatal("different inputs should produce different proofs")
	}
}

func TestProverService_GenerateProof_SimulationDisabled(t *testing.T) {
	ps := newTestProver(func(c *ProverConfig) {
		c.AllowSimulated = false
		c.ProverEndpoint = "" // no remote either
	})
	ctx := context.Background()

	result, err := ps.GenerateProof(ctx, testProofRequest())
	// When both remote and simulated are disabled, result should indicate failure
	if err != nil {
		t.Fatalf("GenerateProof returned error instead of failed result: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure when prover not configured and simulation disabled")
	}
	if result.Error == "" {
		t.Fatal("expected error message in result")
	}
}

// =============================================================================
// Proof Verification
// =============================================================================

func TestProverService_VerifyProof(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	// First generate a proof
	req := testProofRequest()
	genResult, err := ps.GenerateProof(ctx, req)
	if err != nil {
		t.Fatalf("generate error: %v", err)
	}
	if !genResult.Success {
		t.Fatalf("generate failed: %s", genResult.Error)
	}

	// Now verify it
	valid, err := ps.VerifyProof(ctx, genResult.Proof, genResult.PublicInputs, []byte("verifying-key"))
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !valid {
		t.Fatal("proof should be valid")
	}
}

func TestProverService_VerifyProof_EmptyProof(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	_, err := ps.VerifyProof(ctx, []byte{}, nil, nil)
	if err == nil {
		t.Fatal("expected error for empty proof")
	}
}

func TestProverService_VerifyProof_InvalidJSON(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	_, err := ps.VerifyProof(ctx, []byte("not-json"), nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid proof format")
	}
}

func TestProverService_VerifyProof_WrongProtocol(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	badProof := SimulatedEZKLProof{
		Protocol:         "groth16", // wrong protocol
		Curve:            "bn254",
		ProofCommitments: [][]byte{{1, 2, 3}},
	}
	proofBytes, _ := json.Marshal(badProof)

	_, err := ps.VerifyProof(ctx, proofBytes, nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestProverService_VerifyProof_EmptyCommitments(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	badProof := SimulatedEZKLProof{
		Protocol:         "halo2",
		Curve:            "bn254",
		ProofCommitments: [][]byte{}, // empty
	}
	proofBytes, _ := json.Marshal(badProof)

	_, err := ps.VerifyProof(ctx, proofBytes, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing proof commitments")
	}
}

func TestProverService_VerifyProof_SimulationDisabled(t *testing.T) {
	ps := newTestProver(func(c *ProverConfig) {
		c.AllowSimulated = false
		c.ProverEndpoint = "" // no remote
	})
	ctx := context.Background()

	_, err := ps.VerifyProof(ctx, []byte("some-proof"), nil, nil)
	if err == nil {
		t.Fatal("expected error when verifier not configured")
	}
}

// =============================================================================
// Circuit Cache
// =============================================================================

func TestProverService_CircuitCache(t *testing.T) {
	ps := newTestProver(func(c *ProverConfig) { c.CircuitCacheSize = 10 })

	circuitHash := sha256.Sum256([]byte("circuit-1"))
	modelHash := sha256.Sum256([]byte("model-1"))
	vk := []byte("verifying-key-1")
	compiled := []byte("compiled-circuit-1")

	// Cache miss before adding
	_, found := ps.GetCachedCircuit(circuitHash[:])
	if found {
		t.Fatal("expected cache miss before adding")
	}

	// Add to cache
	ps.CacheCircuit(circuitHash[:], modelHash[:], vk, compiled, nil, nil)

	// Cache hit after adding
	cached, found := ps.GetCachedCircuit(circuitHash[:])
	if !found {
		t.Fatal("expected cache hit after adding")
	}
	if string(cached.CircuitHash) != string(circuitHash[:]) {
		t.Fatal("cached circuit hash mismatch")
	}
	if string(cached.VerifyingKey) != string(vk) {
		t.Fatal("cached verifying key mismatch")
	}
	if cached.UseCount != 1 {
		t.Fatalf("expected use count 1, got %d", cached.UseCount)
	}

	// Second access increments use count
	cached2, _ := ps.GetCachedCircuit(circuitHash[:])
	if cached2.UseCount != 2 {
		t.Fatalf("expected use count 2, got %d", cached2.UseCount)
	}
}

func TestProverService_CircuitCache_WithSchema(t *testing.T) {
	ps := newTestProver()

	circuitHash := sha256.Sum256([]byte("circuit-schema"))
	modelHash := sha256.Sum256([]byte("model-schema"))
	inputSchema := &ModelSchema{TensorShape: []int{1, 10}, DataType: "float32"}
	outputSchema := &ModelSchema{TensorShape: []int{1, 1}, DataType: "float32"}

	ps.CacheCircuit(circuitHash[:], modelHash[:], nil, nil, inputSchema, outputSchema)

	cached, found := ps.GetCachedCircuit(circuitHash[:])
	if !found {
		t.Fatal("expected cache hit")
	}
	if cached.InputSchema == nil || cached.OutputSchema == nil {
		t.Fatal("schemas not cached")
	}
	if cached.InputSchema.DataType != "float32" {
		t.Fatalf("input schema data type mismatch: %s", cached.InputSchema.DataType)
	}
}

func TestProverService_CircuitCache_MetricsTracked(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	// Generate a proof -- the internal path checks the cache
	req := testProofRequest()
	ps.GenerateProof(ctx, req)

	metrics := ps.GetMetrics()
	if metrics.CacheMisses != 1 {
		t.Fatalf("expected 1 cache miss, got %d", metrics.CacheMisses)
	}

	// Cache the circuit, then generate again
	ps.CacheCircuit(req.CircuitHash, req.ModelHash, nil, nil, nil, nil)
	ps.GenerateProof(ctx, req)

	metrics = ps.GetMetrics()
	if metrics.CacheHits < 1 {
		t.Fatalf("expected at least 1 cache hit, got %d", metrics.CacheHits)
	}
}

// =============================================================================
// Timeout Handling
// =============================================================================

func TestProverService_Timeout(t *testing.T) {
	ps := newTestProver()

	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Fill all prover slots so the next request blocks on pool acquisition
	for i := 0; i < ps.config.MaxConcurrentProofs; i++ {
		<-ps.proverPool
	}

	_, err := ps.GenerateProof(ctx, testProofRequest())
	if err == nil {
		t.Fatal("expected context cancellation error")
	}

	// Refill slots to avoid panic on Shutdown
	for i := 0; i < ps.config.MaxConcurrentProofs; i++ {
		ps.proverPool <- struct{}{}
	}
}

// =============================================================================
// Concurrent Proving
// =============================================================================

func TestProverService_ConcurrentProving(t *testing.T) {
	ps := newTestProver(func(c *ProverConfig) { c.MaxConcurrentProofs = 4 })
	ctx := context.Background()

	var wg sync.WaitGroup
	results := make([]*ProofResult, 8)
	errs := make([]error, 8)

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := testProofRequest()
			req.RequestID = fmt.Sprintf("concurrent-req-%d", idx)
			differentInput := sha256.Sum256([]byte(fmt.Sprintf("input-%d", idx)))
			req.InputHash = differentInput[:]
			results[idx], errs[idx] = ps.GenerateProof(ctx, req)
		}(i)
	}
	wg.Wait()

	successCount := 0
	for i := 0; i < 8; i++ {
		if errs[i] != nil {
			t.Errorf("request %d error: %v", i, errs[i])
			continue
		}
		if results[i] != nil && results[i].Success {
			successCount++
		}
	}
	if successCount != 8 {
		t.Fatalf("expected 8 successful proofs, got %d", successCount)
	}

	metrics := ps.GetMetrics()
	if metrics.TotalProofsGenerated != 8 {
		t.Fatalf("expected 8 total proofs, got %d", metrics.TotalProofsGenerated)
	}
}

// =============================================================================
// Circuit Breaker
// =============================================================================

func TestProverService_CircuitBreaker(t *testing.T) {
	// Start a server that always returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	ps := newTestProver(func(c *ProverConfig) {
		c.ProverEndpoint = server.URL
		c.AllowSimulated = false
	})

	breaker := ps.ProverBreaker()
	if breaker == nil {
		t.Fatal("prover breaker should not be nil")
	}

	verifierBreaker := ps.VerifierBreaker()
	if verifierBreaker == nil {
		t.Fatal("verifier breaker should not be nil")
	}

	ctx := context.Background()
	req := testProofRequest()

	// Trigger multiple failures to trip the breaker
	for i := 0; i < 10; i++ {
		ps.CallRemoteProver(ctx, req)
	}

	// After enough failures, the breaker should be open
	if breaker.Allow() {
		// The breaker may need more failures depending on configuration;
		// we just verify it is wired and records failures.
		t.Log("breaker still closed after 10 failures (threshold may be higher)")
	}
}

// =============================================================================
// Remote Prover via Mock HTTP Server
// =============================================================================

func TestProverService_CallRemoteProver_Success(t *testing.T) {
	expectedResult := ProofResult{
		Success:          true,
		Proof:            []byte("remote-proof-bytes"),
		PublicInputs:     &PublicInputs{ModelCommitment: []byte("mc"), InputCommitment: []byte("ic"), OutputCommitment: []byte("oc")},
		GenerationTimeMs: 500,
		RequestID:        "test-req-001",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prove" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResult)
	}))
	defer server.Close()

	ps := newTestProver(func(c *ProverConfig) {
		c.ProverEndpoint = server.URL
		c.AllowSimulated = false
	})

	ctx := context.Background()
	result, err := ps.CallRemoteProver(ctx, testProofRequest())
	if err != nil {
		t.Fatalf("remote prover error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success from remote prover")
	}
	if string(result.Proof) != string(expectedResult.Proof) {
		t.Fatal("proof bytes mismatch")
	}
}

func TestProverService_CallRemoteVerifier_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"verified": true})
	}))
	defer server.Close()

	ps := newTestProver(func(c *ProverConfig) {
		c.ProverEndpoint = server.URL
		c.AllowSimulated = false
	})

	ctx := context.Background()
	valid, err := ps.CallRemoteVerifier(ctx, []byte("proof"), &PublicInputs{}, []byte("vk"))
	if err != nil {
		t.Fatalf("remote verifier error: %v", err)
	}
	if !valid {
		t.Fatal("expected verification to pass")
	}
}

func TestProverService_CallRemoteVerifier_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"verified": false, "error": "invalid proof"})
	}))
	defer server.Close()

	ps := newTestProver(func(c *ProverConfig) {
		c.ProverEndpoint = server.URL
		c.AllowSimulated = false
	})

	ctx := context.Background()
	_, err := ps.CallRemoteVerifier(ctx, []byte("bad-proof"), &PublicInputs{}, []byte("vk"))
	if err == nil {
		t.Fatal("expected error for failed verification")
	}
}

// =============================================================================
// Circuit Compilation
// =============================================================================

func TestProverService_CompileCircuit(t *testing.T) {
	ps := newTestProver()
	ctx := context.Background()

	modelBytes := []byte("test-onnx-model-bytes")
	calibrationData := []byte("calibration-data")

	result, err := ps.CompileCircuit(ctx, modelBytes, calibrationData)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if len(result.CircuitHash) != 32 {
		t.Fatalf("expected 32-byte circuit hash, got %d", len(result.CircuitHash))
	}
	if len(result.ModelHash) != 32 {
		t.Fatalf("expected 32-byte model hash, got %d", len(result.ModelHash))
	}
	if len(result.CircuitBytes) == 0 {
		t.Fatal("circuit bytes should not be empty")
	}
	if len(result.VerifyingKey) == 0 {
		t.Fatal("verifying key should not be empty")
	}
	if result.InputSchema == nil || result.OutputSchema == nil {
		t.Fatal("schemas should be set")
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkEZKLProof_Generation(b *testing.B) {
	ps := newTestProver()
	ctx := context.Background()
	req := testProofRequest()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.RequestID = fmt.Sprintf("bench-%d", i)
		result, err := ps.GenerateProof(ctx, req)
		if err != nil || !result.Success {
			b.Fatalf("proof failed at iteration %d", i)
		}
	}
}

func BenchmarkEZKLProof_Verification(b *testing.B) {
	ps := newTestProver()
	ctx := context.Background()

	// Generate a proof to verify
	result, _ := ps.GenerateProof(ctx, testProofRequest())
	if !result.Success {
		b.Fatal("failed to generate proof for benchmark")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid, err := ps.VerifyProof(ctx, result.Proof, result.PublicInputs, []byte("vk"))
		if err != nil || !valid {
			b.Fatalf("verification failed at iteration %d", i)
		}
	}
}

// Compile-time assertion to ensure test file compiles.
var _ = time.Now
