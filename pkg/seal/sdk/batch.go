package sdk

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aethelred/aethelred/x/seal/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultBatchConcurrency is the default number of parallel workers for batch operations.
const DefaultBatchConcurrency = 10

// BatchSealResult holds the outcome of a single seal creation within a batch.
type BatchSealResult struct {
	// Index is the position in the original request slice.
	Index int

	// Response is the seal response on success.
	Response *SealResponse

	// Err is non-nil if this seal creation failed.
	Err error
}

// BatchVerifyResult holds the outcome of a single seal verification within a batch.
type BatchVerifyResult struct {
	// Index is the position in the original request slice.
	Index int

	// SealID is the ID that was verified.
	SealID string

	// Response is the verification response on success.
	Response *SealResponse

	// Err is non-nil if verification failed.
	Err error
}

// BatchResult aggregates the results of a batch operation.
type BatchResult struct {
	// TotalRequested is the number of items in the batch.
	TotalRequested int

	// Succeeded is the number that completed successfully.
	Succeeded int

	// Failed is the number that returned errors.
	Failed int

	// Duration is the wall-clock time for the entire batch.
	Duration time.Duration

	// SealResults contains individual seal creation outcomes (batch seal only).
	SealResults []BatchSealResult

	// VerifyResults contains individual verification outcomes (batch verify only).
	VerifyResults []BatchVerifyResult
}

// BatchConfig controls batch operation behavior.
type BatchConfig struct {
	// Concurrency is the maximum number of parallel workers.
	// Defaults to DefaultBatchConcurrency if zero.
	Concurrency int

	// StopOnError halts the batch at the first error when true.
	StopOnError bool
}

// BatchSeal creates multiple seals in parallel, respecting the concurrency limit.
func (s *SealSDK) BatchSeal(ctx context.Context, requests []SealRequest, cfg *BatchConfig) *BatchResult {
	start := time.Now()

	concurrency := DefaultBatchConcurrency
	if cfg != nil && cfg.Concurrency > 0 {
		concurrency = cfg.Concurrency
	}
	stopOnError := cfg != nil && cfg.StopOnError

	result := &BatchResult{
		TotalRequested: len(requests),
		SealResults:    make([]BatchSealResult, len(requests)),
	}

	if len(requests) == 0 {
		result.Duration = time.Since(start)
		return result
	}

	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrency)
		mu      sync.Mutex
		stopped bool
	)

	for i, req := range requests {
		if stopped {
			result.SealResults[i] = BatchSealResult{
				Index: i,
				Err:   fmt.Errorf("batch halted due to prior error"),
			}
			continue
		}

		wg.Add(1)
		sem <- struct{}{} // acquire semaphore slot

		go func(idx int, r SealRequest) {
			defer wg.Done()
			defer func() { <-sem }() // release semaphore slot

			// Check if context has been cancelled
			select {
			case <-ctx.Done():
				mu.Lock()
				result.SealResults[idx] = BatchSealResult{
					Index: idx,
					Err:   ctx.Err(),
				}
				mu.Unlock()
				return
			default:
			}

			resp, err := s.CreateSeal(ctx, r)

			mu.Lock()
			defer mu.Unlock()

			result.SealResults[idx] = BatchSealResult{
				Index:    idx,
				Response: resp,
				Err:      err,
			}

			if err != nil {
				result.Failed++
				if stopOnError {
					stopped = true
				}
			} else {
				result.Succeeded++
			}
		}(i, req)
	}

	wg.Wait()

	result.Duration = time.Since(start)
	return result
}

// BatchVerify verifies multiple seals in parallel, respecting the concurrency limit.
func (s *SealSDK) BatchVerify(ctx context.Context, sealIDs []string, cfg *BatchConfig) *BatchResult {
	start := time.Now()

	concurrency := DefaultBatchConcurrency
	if cfg != nil && cfg.Concurrency > 0 {
		concurrency = cfg.Concurrency
	}
	stopOnError := cfg != nil && cfg.StopOnError

	result := &BatchResult{
		TotalRequested: len(sealIDs),
		VerifyResults:  make([]BatchVerifyResult, len(sealIDs)),
	}

	if len(sealIDs) == 0 {
		result.Duration = time.Since(start)
		return result
	}

	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, concurrency)
		mu      sync.Mutex
		stopped bool
	)

	for i, id := range sealIDs {
		if stopped {
			result.VerifyResults[i] = BatchVerifyResult{
				Index:  i,
				SealID: id,
				Err:    fmt.Errorf("batch halted due to prior error"),
			}
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, sealID string) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				mu.Lock()
				result.VerifyResults[idx] = BatchVerifyResult{
					Index:  idx,
					SealID: sealID,
					Err:    ctx.Err(),
				}
				mu.Unlock()
				return
			default:
			}

			resp, err := s.VerifySeal(ctx, sealID)

			mu.Lock()
			defer mu.Unlock()

			result.VerifyResults[idx] = BatchVerifyResult{
				Index:    idx,
				SealID:   sealID,
				Response: resp,
				Err:      err,
			}

			if err != nil {
				result.Failed++
				if stopOnError {
					stopped = true
				}
			} else {
				result.Succeeded++
			}
		}(i, id)
	}

	wg.Wait()

	result.Duration = time.Since(start)
	return result
}

// BatchOfflineVerify performs offline verification of multiple seals in parallel.
func BatchOfflineVerify(verifier *Verifier, seals []*SealResponse, concurrency int) []*VerificationResult {
	if concurrency <= 0 {
		concurrency = DefaultBatchConcurrency
	}

	results := make([]*VerificationResult, len(seals))

	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, concurrency)
	)

	for i, sealResp := range seals {
		wg.Add(1)
		sem <- struct{}{}

		go func(idx int, resp *SealResponse) {
			defer wg.Done()
			defer func() { <-sem }()

			// Reconstruct a minimal DigitalSeal for offline verification
			seal := responseToMinimalSeal(resp)
			results[idx] = verifier.VerifyOffline(seal)
		}(i, sealResp)
	}

	wg.Wait()

	return results
}

// responseToMinimalSeal reconstructs a DigitalSeal from a SealResponse for
// offline verification purposes.
func responseToMinimalSeal(resp *SealResponse) *types.DigitalSeal {
	if resp == nil {
		return &types.DigitalSeal{}
	}

	seal := &types.DigitalSeal{
		Id:               resp.SealID,
		Status:           resp.Status,
		TeeAttestations:  resp.Attestations,
		ZkProof:          resp.Proof,
		RegulatoryInfo:   resp.RegulatoryInfo,
		BlockHeight:      resp.BlockHeight,
		RequestedBy:      resp.RequestedBy,
		Purpose:          resp.Purpose,
		ValidatorSet:     resp.ValidatorSet,
	}

	if !resp.Timestamp.IsZero() {
		seal.Timestamp = timestamppb.New(resp.Timestamp)
	}

	return seal
}
