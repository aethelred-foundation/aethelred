package sdk

import (
	"context"
	"sync"
	"testing"

	"github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// benchKeeper is a concurrency-safe minimal mock keeper for benchmarks.
type benchKeeper struct {
	mu    sync.Mutex
	seals map[string]*types.DigitalSeal
}

func newBenchKeeper() *benchKeeper {
	return &benchKeeper{seals: make(map[string]*types.DigitalSeal)}
}

func (k *benchKeeper) CreateSeal(_ context.Context, seal *types.DigitalSeal) error {
	k.mu.Lock()
	k.seals[seal.Id] = seal
	k.mu.Unlock()
	return nil
}

func (k *benchKeeper) GetSeal(_ context.Context, id string) (*types.DigitalSeal, error) {
	k.mu.Lock()
	s := k.seals[id]
	k.mu.Unlock()
	return s, nil
}

func (k *benchKeeper) SetSeal(_ context.Context, seal *types.DigitalSeal) error {
	k.mu.Lock()
	k.seals[seal.Id] = seal
	k.mu.Unlock()
	return nil
}

func (k *benchKeeper) RevokeSeal(_ context.Context, id string, _ string) error {
	k.mu.Lock()
	if s, ok := k.seals[id]; ok {
		s.Status = types.SealStatusRevoked
	}
	k.mu.Unlock()
	return nil
}

func (k *benchKeeper) VerifySeal(_ context.Context, id string) (bool, error) {
	k.mu.Lock()
	s, ok := k.seals[id]
	k.mu.Unlock()
	if !ok {
		return false, nil
	}
	return s.Status == types.SealStatusActive, nil
}

func (k *benchKeeper) ListSeals(_ context.Context, _ int, _ int) ([]*types.DigitalSeal, error) {
	return nil, nil
}

func (k *benchKeeper) ListSealsByModel(_ context.Context, _ []byte) ([]*types.DigitalSeal, error) {
	return nil, nil
}

func (k *benchKeeper) ListSealsByRequester(_ context.Context, _ string) ([]*types.DigitalSeal, error) {
	return nil, nil
}

func setupBenchSDK(b *testing.B) *SealSDK {
	b.Helper()
	keeper := newBenchKeeper()
	s, err := NewSealSDK(Config{
		ChainID:       "bench-chain",
		SignerAddress: "aethelred1bench",
	}, keeper)
	if err != nil {
		b.Fatalf("setup: NewSealSDK failed: %v", err)
	}
	return s
}

func makeBenchSealRequest() SealRequest {
	return SealRequest{
		ModelHash:  ComputeHash([]byte("benchmark-model-data")),
		InputHash:  ComputeHash([]byte("benchmark-input-data")),
		OutputHash: ComputeHash([]byte("benchmark-output-data")),
		Purpose:    "benchmarking",
	}
}

func BenchmarkCreateSeal(b *testing.B) {
	s := setupBenchSDK(b)
	req := makeBenchSealRequest()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.CreateSeal(ctx, req)
	}
}

func BenchmarkVerifySeal(b *testing.B) {
	s := setupBenchSDK(b)
	ctx := context.Background()
	resp, err := s.CreateSeal(ctx, makeBenchSealRequest())
	if err != nil {
		b.Fatalf("setup: CreateSeal failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.VerifySeal(ctx, resp.SealID)
	}
}

func BenchmarkVerifyOffline(b *testing.B) {
	verifier := NewVerifier(nil)
	seal := types.NewDigitalSeal(
		ComputeHash([]byte("model")),
		ComputeHash([]byte("input")),
		ComputeHash([]byte("output")),
		100,
		"aethelred1bench",
		"benchmarking",
	)
	seal.Activate()
	seal.TeeAttestations = []*types.TEEAttestation{
		{
			ValidatorAddress: "aethelred1val1",
			Platform:         "aws-nitro",
			EnclaveId:        "enclave-001",
			Measurement:      ComputeHash([]byte("measurement")),
			Quote:            ComputeHash([]byte("quote")),
			Signature:        make([]byte, 64),
			Timestamp:        timestamppb.Now(),
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.VerifyOffline(seal)
	}
}

func BenchmarkBatchSeal_10(b *testing.B) {
	s := setupBenchSDK(b)
	ctx := context.Background()
	requests := make([]SealRequest, 10)
	for j := range requests {
		requests[j] = makeBenchSealRequest()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.BatchSeal(ctx, requests, nil)
	}
}

func BenchmarkBatchSeal_100(b *testing.B) {
	s := setupBenchSDK(b)
	ctx := context.Background()
	requests := make([]SealRequest, 100)
	for j := range requests {
		requests[j] = makeBenchSealRequest()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.BatchSeal(ctx, requests, nil)
	}
}

func BenchmarkExportJSON(b *testing.B) {
	seal := types.NewDigitalSeal(
		ComputeHash([]byte("model")),
		ComputeHash([]byte("input")),
		ComputeHash([]byte("output")),
		100,
		"aethelred1bench",
		"benchmarking",
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := ExportJSON(seal)
		_ = data
	}
}

func BenchmarkComputeHash(b *testing.B) {
	data := make([]byte, 4096)
	for j := range data {
		data[j] = byte(j % 256)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeHash(data)
	}
}
