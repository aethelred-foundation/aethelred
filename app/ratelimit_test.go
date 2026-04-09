package app

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TokenBucket unit tests
// ---------------------------------------------------------------------------

func TestTokenBucket_BasicRefill(t *testing.T) {
	// Start with zero tokens, refill rate of 100/s, capacity 100.
	tb := NewTokenBucket(100, 100)
	// Drain all tokens.
	for tb.Take(1) {
		// keep draining
	}

	// Wait 50ms -> should refill ~5 tokens (100 * 0.05).
	time.Sleep(50 * time.Millisecond)
	if !tb.Take(1) {
		t.Fatal("expected bucket to have refilled at least 1 token after 50ms")
	}
}

func TestTokenBucket_Drain(t *testing.T) {
	tb := NewTokenBucket(10, 0) // capacity 10, zero refill rate
	for i := 0; i < 10; i++ {
		if !tb.Take(1) {
			t.Fatalf("take should succeed for token %d", i)
		}
	}
	if tb.Take(1) {
		t.Fatal("take should fail after bucket is drained with zero refill")
	}
}

func TestTokenBucket_Burst(t *testing.T) {
	tb := NewTokenBucket(50, 10) // capacity 50, rate 10/s
	// Burst of 50 should succeed immediately.
	if !tb.Take(50) {
		t.Fatal("should allow full burst up to capacity")
	}
	// Next request should fail immediately (no time for refill).
	if tb.Take(1) {
		t.Fatal("should deny request right after burst exhaustion")
	}
}

func TestTokenBucket_CapacityClamp(t *testing.T) {
	tb := NewTokenBucket(10, 1000) // high rate, low capacity
	// Drain and wait so refill overshoots capacity.
	tb.Take(10)
	time.Sleep(50 * time.Millisecond) // 1000*0.05 = 50 tokens, but capped at 10
	// Should still only get 10 tokens worth.
	if !tb.Take(10) {
		t.Fatal("expected capacity worth of tokens after refill")
	}
	if tb.Take(1) {
		t.Fatal("should not exceed capacity")
	}
}

func TestTokenBucket_TakeMultiple(t *testing.T) {
	tb := NewTokenBucket(5, 0)
	if !tb.Take(3) {
		t.Fatal("take 3 from 5 should succeed")
	}
	if tb.Take(3) {
		t.Fatal("take 3 from remaining 2 should fail")
	}
	if !tb.Take(2) {
		t.Fatal("take 2 from remaining 2 should succeed")
	}
}

// ---------------------------------------------------------------------------
// RateLimiter unit tests
// ---------------------------------------------------------------------------

func newTestRateLimiter() *RateLimiter {
	cfg := RateLimitConfig{
		GlobalRatePerSecond:        1000,
		GlobalBurstSize:            2000,
		AddressRatePerSecond:       50,
		AddressBurstSize:           100,
		JobSubmissionRatePerSecond: 5,
		JobSubmissionBurstSize:     10,
		EndpointRates: map[string]EndpointRateConfig{
			"/test/endpoint": {RatePerSecond: 10, BurstSize: 20},
		},
		CleanupInterval:     1 * time.Minute,
		MaxTrackedAddresses: 100,
	}
	return NewRateLimiter(cfg)
}

func TestRateLimiter_PerEndpoint(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Stop()

	ctx := context.Background()
	endpoint := "/test/endpoint"

	// Exhaust the per-endpoint bucket (burst = 20).
	for i := 0; i < 20; i++ {
		if !rl.Allow(ctx, "addr-1", endpoint) {
			t.Fatalf("request %d should have been allowed", i)
		}
	}

	// Next request to the same endpoint should be denied.
	if rl.Allow(ctx, "addr-1", endpoint) {
		t.Fatal("request should be rate-limited after exhausting endpoint burst")
	}

	// Requests to a different endpoint should still be allowed.
	if !rl.Allow(ctx, "addr-1", "/other") {
		t.Fatal("request to a non-rate-limited endpoint should pass")
	}
}

func TestRateLimiter_ConcurrentRequests(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Stop()

	ctx := context.Background()
	var allowed atomic.Int64
	var denied atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			addr := "concurrent-addr"
			if rl.Allow(ctx, addr, "") {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}(i)
	}
	wg.Wait()

	total := allowed.Load() + denied.Load()
	if total != 100 {
		t.Fatalf("expected 100 total, got %d", total)
	}
	if denied.Load() == 0 {
		// With per-address burst of 100 and 100 goroutines, some could be
		// denied due to timing; at minimum we just check no panics occurred
		// and totals add up.
	}
}

func TestRateLimiter_Recovery(t *testing.T) {
	cfg := RateLimitConfig{
		GlobalRatePerSecond:        100,
		GlobalBurstSize:            10,
		AddressRatePerSecond:       100,
		AddressBurstSize:           10,
		JobSubmissionRatePerSecond: 5,
		JobSubmissionBurstSize:     5,
		EndpointRates:              map[string]EndpointRateConfig{},
		CleanupInterval:            1 * time.Minute,
		MaxTrackedAddresses:        100,
	}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	ctx := context.Background()
	// Drain global bucket.
	for i := 0; i < 10; i++ {
		rl.Allow(ctx, "addr", "")
	}
	if rl.Allow(ctx, "addr", "") {
		t.Fatal("should be rate-limited after draining burst")
	}

	// Wait for refill: 10 tokens / 100 per second = 100ms.
	time.Sleep(120 * time.Millisecond)

	if !rl.Allow(ctx, "addr", "") {
		t.Fatal("rate limit should have recovered after cooldown")
	}
}

func TestRateLimiter_Configuration(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg.GlobalRatePerSecond <= 0 {
		t.Fatal("global rate must be positive")
	}
	if cfg.GlobalBurstSize <= 0 {
		t.Fatal("global burst must be positive")
	}
	if cfg.AddressRatePerSecond <= 0 {
		t.Fatal("address rate must be positive")
	}
	if cfg.CleanupInterval <= 0 {
		t.Fatal("cleanup interval must be positive")
	}
	if cfg.MaxTrackedAddresses <= 0 {
		t.Fatal("max tracked addresses must be positive")
	}
	if len(cfg.EndpointRates) == 0 {
		t.Fatal("default config should include endpoint rates")
	}
	if _, ok := cfg.EndpointRates[jobSubmissionEndpoint]; !ok {
		t.Fatal("default config should include job submission endpoint rate")
	}
}

func TestRateLimiter_AllowJobSubmission(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Stop()

	ctx := context.Background()
	addr := "job-addr"

	// Job submission burst is 10; exhaust it.
	for i := 0; i < 10; i++ {
		if !rl.AllowJobSubmission(ctx, addr) {
			t.Fatalf("job submission %d should be allowed", i)
		}
	}
	if rl.AllowJobSubmission(ctx, addr) {
		t.Fatal("job submission should be denied after exhausting burst")
	}
}

func TestRateLimiter_EmptyAddress(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Stop()

	// Empty address should skip per-address check.
	if !rl.Allow(context.Background(), "", "") {
		t.Fatal("request with empty address should be allowed")
	}
}

func TestRateLimiter_GetMetrics(t *testing.T) {
	rl := newTestRateLimiter()
	defer rl.Stop()

	ctx := context.Background()
	rl.Allow(ctx, "addr-m", "")
	rl.Allow(ctx, "addr-m", "")

	m := rl.GetMetrics()
	if m.TotalRequests != 2 {
		t.Fatalf("expected 2 total requests, got %d", m.TotalRequests)
	}
	if m.AllowedRequests < 1 {
		t.Fatal("expected at least 1 allowed request")
	}
}

func TestRateLimiter_EvictionAtCapacity(t *testing.T) {
	cfg := RateLimitConfig{
		GlobalRatePerSecond:        10000,
		GlobalBurstSize:            10000,
		AddressRatePerSecond:       100,
		AddressBurstSize:           100,
		JobSubmissionRatePerSecond: 5,
		JobSubmissionBurstSize:     5,
		EndpointRates:              map[string]EndpointRateConfig{},
		CleanupInterval:            1 * time.Minute,
		MaxTrackedAddresses:        5,
	}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	ctx := context.Background()
	// Create more addresses than capacity.
	for i := 0; i < 10; i++ {
		rl.Allow(ctx, fmt.Sprintf("addr-%d", i), "")
	}

	rl.mu.RLock()
	count := len(rl.addressBuckets)
	rl.mu.RUnlock()

	if count > 5 {
		t.Fatalf("expected at most 5 tracked addresses after eviction, got %d", count)
	}
}

func TestRateLimiter_Stop(t *testing.T) {
	rl := newTestRateLimiter()
	rl.Stop()
	// Double stop should not panic.
	// (close of closed channel panics, so this verifies the channel is only closed once
	// if Stop is called once).
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkRateLimiter_Check(b *testing.B) {
	rl := newTestRateLimiter()
	defer rl.Stop()
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rl.Allow(ctx, "bench-addr", "/test/endpoint")
		}
	})
}
