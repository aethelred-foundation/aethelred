package verify

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"cosmossdk.io/log"

	"github.com/aethelred/aethelred/x/verify/ezkl"
	"github.com/aethelred/aethelred/x/verify/tee"
	"github.com/aethelred/aethelred/x/verify/types"
)

func TestVerificationCacheKeyBindsProofDomain(t *testing.T) {
	hash := func(label string) []byte {
		sum := sha256.Sum256([]byte(label))
		return sum[:]
	}
	orchestrator := &VerificationOrchestrator{}
	base := VerificationRequest{
		ModelHash:          hash("model"),
		InputHash:          hash("input"),
		ExpectedOutputHash: hash("output"),
		CircuitHash:        hash("circuit-a"),
		VerifyingKeyHash:   hash("verifying-key-a"),
		BlockHeight:        42,
		ChainID:            "aethelred-testnet-1",
		VerificationType:   types.VerificationTypeZKML,
	}
	baseKey := orchestrator.getCacheKey(&base)

	for _, mutation := range []struct {
		name   string
		mutate func(*VerificationRequest)
	}{
		{
			name: "circuit hash",
			mutate: func(req *VerificationRequest) {
				req.CircuitHash = hash("circuit-b")
			},
		},
		{
			name: "verifying key hash",
			mutate: func(req *VerificationRequest) {
				req.VerifyingKeyHash = hash("verifying-key-b")
			},
		},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := base
			mutation.mutate(&changed)
			if baseKey == orchestrator.getCacheKey(&changed) {
				t.Fatalf("cache key did not bind %s", mutation.name)
			}
		})
	}
}

func TestVerificationCacheKeySeparatesVariableLengthFields(t *testing.T) {
	orchestrator := &VerificationOrchestrator{}
	first := &VerificationRequest{
		ModelHash:        []byte("a"),
		InputHash:        []byte("bc"),
		VerificationType: types.VerificationTypeTEE,
	}
	second := &VerificationRequest{
		ModelHash:        []byte("ab"),
		InputHash:        []byte("c"),
		VerificationType: types.VerificationTypeTEE,
	}

	if orchestrator.getCacheKey(first) == orchestrator.getCacheKey(second) {
		t.Fatal("cache key is ambiguous across variable-length request fields")
	}
}

func TestVerificationCacheDeepCopiesResponses(t *testing.T) {
	cache := NewVerificationCache(time.Minute, 4)
	original := cacheTestResponse("original")
	cache.Set("key", original)

	// Mutating the caller-owned response after insertion must not affect the
	// immutable cache snapshot.
	mutateCacheTestResponse(original)
	first, ok := cache.Get("key")
	if !ok {
		t.Fatal("expected cache hit")
	}
	assertCacheTestResponseUnchanged(t, first, "original")

	// Mutating a retrieved response must not affect subsequent cache hits.
	mutateCacheTestResponse(first)
	second, ok := cache.Get("key")
	if !ok {
		t.Fatal("expected second cache hit")
	}
	assertCacheTestResponseUnchanged(t, second, "original")
	if first == second || first.TEEResult == second.TEEResult ||
		first.ZKMLResult == second.ZKMLResult {
		t.Fatal("cache returned shared response pointers")
	}
}

func TestVerificationOrchestratorCacheHitUsesCurrentRequestID(t *testing.T) {
	orchestrator := cachedOnlyOrchestrator()
	req := cacheTestRequest("current-request")
	orchestrator.resultCache.Set(
		orchestrator.getCacheKey(req),
		cacheTestResponse("original-request"),
	)

	response, err := orchestrator.Verify(context.Background(), req)
	if err != nil {
		t.Fatalf("verify cached response: %v", err)
	}
	if response.RequestID != req.RequestID {
		t.Fatalf(
			"cache hit returned request ID %q, want %q",
			response.RequestID,
			req.RequestID,
		)
	}
	if !response.FromCache {
		t.Fatal("expected cached response")
	}

	stored, ok := orchestrator.resultCache.Get(orchestrator.getCacheKey(req))
	if !ok {
		t.Fatal("expected stored response")
	}
	if stored.RequestID != "original-request" || stored.FromCache {
		t.Fatalf(
			"cache hit mutated stored metadata: request_id=%q from_cache=%t",
			stored.RequestID,
			stored.FromCache,
		)
	}
}

func TestVerificationOrchestratorConcurrentCacheHitsAreIsolated(t *testing.T) {
	orchestrator := cachedOnlyOrchestrator()
	base := cacheTestRequest("")
	orchestrator.resultCache.Set(
		orchestrator.getCacheKey(base),
		cacheTestResponse("seed-request"),
	)

	const (
		workers    = 32
		iterations = 100
	)
	var waitGroup sync.WaitGroup
	errors := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				req := cacheTestRequest(fmt.Sprintf("request-%d-%d", worker, iteration))
				response, err := orchestrator.Verify(context.Background(), req)
				if err != nil {
					errors <- err
					return
				}
				if response.RequestID != req.RequestID {
					errors <- fmt.Errorf(
						"got request ID %q, want %q",
						response.RequestID,
						req.RequestID,
					)
					return
				}
				if !response.FromCache {
					errors <- fmt.Errorf("expected cache hit for %q", req.RequestID)
					return
				}
				mutateCacheTestResponse(response)
			}
		}()
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	stored, ok := orchestrator.resultCache.Get(orchestrator.getCacheKey(base))
	if !ok {
		t.Fatal("expected stored response after concurrent hits")
	}
	assertCacheTestResponseUnchanged(t, stored, "seed-request")
	if stored.FromCache {
		t.Fatal("concurrent hits mutated cached FromCache metadata")
	}
}

func cachedOnlyOrchestrator() *VerificationOrchestrator {
	return &VerificationOrchestrator{
		logger: log.NewNopLogger(),
		config: OrchestratorConfig{
			CacheEnabled:        true,
			CacheTTL:            time.Minute,
			CacheSize:           4,
			VerificationTimeout: time.Minute,
		},
		resultCache: NewVerificationCache(time.Minute, 4),
		metrics:     &OrchestratorMetrics{mutex: &sync.Mutex{}},
	}
}

func cacheTestRequest(requestID string) *VerificationRequest {
	hash := sha256.Sum256([]byte("cache-domain"))
	return &VerificationRequest{
		RequestID:        requestID,
		ModelHash:        append([]byte(nil), hash[:]...),
		InputHash:        append([]byte(nil), hash[:]...),
		VerificationType: types.VerificationTypeTEE,
	}
}

func cacheTestResponse(requestID string) *VerificationResponse {
	return &VerificationResponse{
		RequestID:        requestID,
		Success:          true,
		VerificationType: types.VerificationTypeHybrid,
		OutputHash:       []byte{1, 2, 3},
		TEEResult: &TEEVerificationResult{
			Success:    true,
			OutputHash: []byte{4, 5, 6},
			AttestationDoc: &tee.NitroAttestationDocument{
				PCRs:        map[int][]byte{0: {7, 8, 9}},
				Certificate: []byte{10, 11},
				CABundle:    []byte{12, 13},
				PublicKey:   []byte{14, 15},
				UserData:    []byte{16, 17},
				Nonce:       []byte{18, 19},
				Signature:   []byte{20, 21},
			},
		},
		ZKMLResult: &ZKMLVerificationResult{
			Success:    true,
			Proof:      []byte{22, 23},
			OutputHash: []byte{24, 25},
			PublicInputs: &ezkl.PublicInputs{
				ModelCommitment:  []byte{26, 27},
				InputCommitment:  []byte{28, 29},
				OutputCommitment: []byte{30, 31},
				ScaleFactors:     []float64{1.25, 2.5},
				Instances:        [][]byte{{32, 33}},
			},
		},
	}
}

func mutateCacheTestResponse(response *VerificationResponse) {
	response.RequestID = "mutated"
	response.FromCache = true
	response.OutputHash[0] ^= 0xFF
	response.TEEResult.OutputHash[0] ^= 0xFF
	response.TEEResult.AttestationDoc.PCRs[0][0] ^= 0xFF
	response.TEEResult.AttestationDoc.Certificate[0] ^= 0xFF
	response.TEEResult.AttestationDoc.CABundle[0] ^= 0xFF
	response.TEEResult.AttestationDoc.PublicKey[0] ^= 0xFF
	response.TEEResult.AttestationDoc.UserData[0] ^= 0xFF
	response.TEEResult.AttestationDoc.Nonce[0] ^= 0xFF
	response.TEEResult.AttestationDoc.Signature[0] ^= 0xFF
	response.ZKMLResult.Proof[0] ^= 0xFF
	response.ZKMLResult.OutputHash[0] ^= 0xFF
	response.ZKMLResult.PublicInputs.ModelCommitment[0] ^= 0xFF
	response.ZKMLResult.PublicInputs.InputCommitment[0] ^= 0xFF
	response.ZKMLResult.PublicInputs.OutputCommitment[0] ^= 0xFF
	response.ZKMLResult.PublicInputs.ScaleFactors[0] = -1
	response.ZKMLResult.PublicInputs.Instances[0][0] ^= 0xFF
}

func assertCacheTestResponseUnchanged(
	t *testing.T,
	response *VerificationResponse,
	requestID string,
) {
	t.Helper()
	if response.RequestID != requestID {
		t.Fatalf("request ID changed: got %q, want %q", response.RequestID, requestID)
	}
	if response.FromCache {
		t.Fatal("cached snapshot FromCache changed")
	}
	if response.OutputHash[0] != 1 ||
		response.TEEResult.OutputHash[0] != 4 ||
		response.TEEResult.AttestationDoc.PCRs[0][0] != 7 ||
		response.TEEResult.AttestationDoc.Certificate[0] != 10 ||
		response.TEEResult.AttestationDoc.CABundle[0] != 12 ||
		response.TEEResult.AttestationDoc.PublicKey[0] != 14 ||
		response.TEEResult.AttestationDoc.UserData[0] != 16 ||
		response.TEEResult.AttestationDoc.Nonce[0] != 18 ||
		response.TEEResult.AttestationDoc.Signature[0] != 20 ||
		response.ZKMLResult.Proof[0] != 22 ||
		response.ZKMLResult.OutputHash[0] != 24 ||
		response.ZKMLResult.PublicInputs.ModelCommitment[0] != 26 ||
		response.ZKMLResult.PublicInputs.InputCommitment[0] != 28 ||
		response.ZKMLResult.PublicInputs.OutputCommitment[0] != 30 ||
		response.ZKMLResult.PublicInputs.ScaleFactors[0] != 1.25 ||
		response.ZKMLResult.PublicInputs.Instances[0][0] != 32 {
		t.Fatal("cached response was mutated through a shared nested reference")
	}
}
