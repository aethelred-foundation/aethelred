package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"cosmossdk.io/log"
)

// ---------------------------------------------------------------------------
// MockTEEClient tests
// ---------------------------------------------------------------------------

func TestMockTEEClient_Init(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)
	if client == nil {
		t.Fatal("expected non-nil mock TEE client")
	}
	if client.IsHealthy(context.Background()) != true {
		t.Fatal("fresh mock client should be healthy")
	}
}

func TestMockTEEClient_Execute(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)

	modelHash := sha256.Sum256([]byte("test-model"))
	inputHash := sha256.Sum256([]byte("test-input"))

	req := &TEEExecutionRequest{
		JobID:     "job-001",
		ModelHash: modelHash[:],
		InputHash: inputHash[:],
		Timeout:   5 * time.Second,
	}

	// Override latency to keep test fast.
	client.mu.Lock()
	client.latencyMs = 1
	client.mu.Unlock()

	result, err := client.Execute(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got error: %s", result.ErrorMessage)
	}
	if result.JobID != "job-001" {
		t.Fatalf("expected job-001, got %s", result.JobID)
	}
	if len(result.OutputHash) == 0 {
		t.Fatal("expected non-empty output hash")
	}
	if result.Attestation == nil {
		t.Fatal("expected attestation data")
	}
	if result.Attestation.Platform != "mock-tee" {
		t.Fatalf("expected mock-tee platform, got %s", result.Attestation.Platform)
	}
}

func TestMockTEEClient_SetResult(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)
	client.mu.Lock()
	client.latencyMs = 1
	client.mu.Unlock()

	expectedOutput := sha256.Sum256([]byte("predetermined"))
	client.SetResult("job-preset", &TEEExecutionResult{
		JobID:      "job-preset",
		Success:    true,
		OutputHash: expectedOutput[:],
	})

	result, err := client.Execute(context.Background(), &TEEExecutionRequest{
		JobID: "job-preset",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JobID != "job-preset" {
		t.Fatalf("expected job-preset, got %s", result.JobID)
	}
	if hex.EncodeToString(result.OutputHash) != hex.EncodeToString(expectedOutput[:]) {
		t.Fatal("output hash does not match predetermined result")
	}
}

func TestMockTEEClient_Failure(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)
	client.mu.Lock()
	client.latencyMs = 1
	client.mu.Unlock()

	client.SetFailure(true, 1.0)

	result, err := client.Execute(context.Background(), &TEEExecutionRequest{
		JobID:     "job-fail",
		ModelHash: make([]byte, 32),
		InputHash: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Fatal("expected failure")
	}
	if result.ErrorCode != ErrorCodeTEEFailure {
		t.Fatalf("expected TEE_FAILURE error code, got %s", result.ErrorCode)
	}
}

func TestMockTEEClient_HealthCheck(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)

	if !client.IsHealthy(context.Background()) {
		t.Fatal("expected healthy")
	}

	client.SetFailure(true, 1.0)
	if client.IsHealthy(context.Background()) {
		t.Fatal("expected unhealthy after SetFailure")
	}
}

func TestMockTEEClient_Capabilities(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)

	caps := client.GetCapabilities()
	if caps == nil {
		t.Fatal("expected non-nil capabilities")
	}
	if caps.Platform != "mock-tee" {
		t.Fatalf("expected mock-tee platform, got %s", caps.Platform)
	}
	if !caps.SupportsZKML {
		t.Fatal("mock should support zkML")
	}
}

func TestMockTEEClient_Close(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)
	if err := client.Close(); err != nil {
		t.Fatalf("expected nil error on close, got %v", err)
	}
}

func TestMockTEEClient_ConcurrentExecution(t *testing.T) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)
	client.mu.Lock()
	client.latencyMs = 1
	client.mu.Unlock()

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := client.Execute(context.Background(), &TEEExecutionRequest{
				JobID:     "concurrent-job",
				ModelHash: make([]byte, 32),
				InputHash: make([]byte, 32),
			})
			if err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("unexpected concurrent error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NitroEnclaveClient tests
// ---------------------------------------------------------------------------

func TestNitroEnclaveClient_Init(t *testing.T) {
	logger := log.NewNopLogger()
	client, err := NewNitroEnclaveClient(logger, "test://endpoint")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.enclaveID == "" {
		t.Fatal("expected non-empty enclave ID")
	}
}

func TestNitroEnclaveClient_Execute(t *testing.T) {
	logger := log.NewNopLogger()
	client, _ := NewNitroEnclaveClient(logger, "test://endpoint")

	modelHash := sha256.Sum256([]byte("model-data"))
	inputHash := sha256.Sum256([]byte("input-data"))

	result, err := client.Execute(context.Background(), &TEEExecutionRequest{
		JobID:     "nitro-job-1",
		ModelHash: modelHash[:],
		InputHash: inputHash[:],
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got: %s", result.ErrorMessage)
	}
	if result.Attestation == nil {
		t.Fatal("expected attestation data")
	}
	if result.Attestation.Platform != "aws-nitro" {
		t.Fatalf("expected aws-nitro, got %s", result.Attestation.Platform)
	}
}

func TestNitroEnclaveClient_ExecuteWithZKProof(t *testing.T) {
	logger := log.NewNopLogger()
	client, _ := NewNitroEnclaveClient(logger, "test://endpoint")

	result, err := client.Execute(context.Background(), &TEEExecutionRequest{
		JobID:          "zk-job",
		ModelHash:      make([]byte, 32),
		InputHash:      make([]byte, 32),
		RequireZKProof: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Fatal("expected success")
	}
	if result.ZKProof == nil {
		t.Fatal("expected ZK proof data when RequireZKProof=true")
	}
	if result.ZKProof.ProofSystem != "ezkl" {
		t.Fatalf("expected ezkl proof system, got %s", result.ZKProof.ProofSystem)
	}
}

func TestNitroEnclaveClient_Capabilities(t *testing.T) {
	logger := log.NewNopLogger()
	client, _ := NewNitroEnclaveClient(logger, "test://endpoint")
	caps := client.GetCapabilities()
	if caps.Platform != "aws-nitro" {
		t.Fatalf("expected aws-nitro, got %s", caps.Platform)
	}
	if caps.MaxModelSize != 1024*1024*1024 {
		t.Fatal("unexpected max model size")
	}
}

func TestNitroEnclaveClient_HealthAndClose(t *testing.T) {
	logger := log.NewNopLogger()
	client, _ := NewNitroEnclaveClient(logger, "test://endpoint")
	if !client.IsHealthy(context.Background()) {
		t.Fatal("expected healthy")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RemoteTEEClient tests (with httptest server)
// ---------------------------------------------------------------------------

func TestRemoteTEEClient_Init_EmptyEndpoint(t *testing.T) {
	logger := log.NewNopLogger()
	_, err := NewRemoteTEEClient(logger, "")
	if err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestRemoteTEEClient_Init_ValidEndpoint(t *testing.T) {
	logger := log.NewNopLogger()
	client, err := NewRemoteTEEClient(logger, "http://localhost:9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Breaker() == nil {
		t.Fatal("expected non-nil circuit breaker")
	}
}

func TestRemoteTEEClient_IsHealthy_ServerDown(t *testing.T) {
	logger := log.NewNopLogger()
	// Use a port that's unlikely to be listening.
	client, err := NewRemoteTEEClient(logger, "http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if client.IsHealthy(ctx) {
		t.Fatal("expected unhealthy when server is down")
	}
}

func TestRemoteTEEClient_IsHealthy_ServerUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	logger := log.NewNopLogger()
	client, err := NewRemoteTEEClient(logger, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !client.IsHealthy(context.Background()) {
		t.Fatal("expected healthy when server responds 200")
	}
}

func TestRemoteTEEClient_Close(t *testing.T) {
	logger := log.NewNopLogger()
	client, _ := NewRemoteTEEClient(logger, "http://localhost:9999")
	if err := client.Close(); err != nil {
		t.Fatalf("close should be no-op, got error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TEEClientFactory tests
// ---------------------------------------------------------------------------

func TestTEEClientFactory_CreateMock(t *testing.T) {
	factory := NewTEEClientFactory(log.NewNopLogger())
	client, err := factory.Create("mock", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestTEEClientFactory_CreateRemote_MissingEndpoint(t *testing.T) {
	factory := NewTEEClientFactory(log.NewNopLogger())
	_, err := factory.Create("remote", map[string]string{})
	if err == nil {
		t.Fatal("expected error for remote platform without endpoint")
	}
}

func TestTEEClientFactory_CreateRemote_WithEndpoint(t *testing.T) {
	factory := NewTEEClientFactory(log.NewNopLogger())
	client, err := factory.Create("remote", map[string]string{
		"endpoint": "http://localhost:8080",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestTEEClientFactory_CreateNitroSimulated(t *testing.T) {
	factory := NewTEEClientFactory(log.NewNopLogger())
	client, err := factory.Create("nitro-simulated", map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestTEEClientFactory_UnsupportedPlatform(t *testing.T) {
	factory := NewTEEClientFactory(log.NewNopLogger())
	_, err := factory.Create("unknown-platform", nil)
	if err == nil {
		t.Fatal("expected error for unsupported platform")
	}
}

// ---------------------------------------------------------------------------
// generateEnclaveID
// ---------------------------------------------------------------------------

func TestGenerateEnclaveID_Unique(t *testing.T) {
	ids := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := generateEnclaveID()
		if ids[id] {
			t.Fatalf("duplicate enclave ID generated: %s", id)
		}
		ids[id] = true
	}
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkMockTEEClient_Execute(b *testing.B) {
	logger := log.NewNopLogger()
	client := NewMockTEEClient(logger)
	client.mu.Lock()
	client.latencyMs = 0
	client.mu.Unlock()

	req := &TEEExecutionRequest{
		JobID:     "bench-job",
		ModelHash: make([]byte, 32),
		InputHash: make([]byte, 32),
	}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Execute(ctx, req)
	}
}
