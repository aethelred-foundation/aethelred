package circuitbreaker

import (
	"sync"
	"testing"
	"time"
)

func TestState_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		state State
		want  string
	}{
		{Closed, "closed"},
		{Open, "open"},
		{HalfOpen, "half_open"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.want {
				t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func TestNew_Defaults(t *testing.T) {
	t.Parallel()
	b := New("test", 0, 0)
	if b.Name() != "test" {
		t.Errorf("expected name 'test', got %q", b.Name())
	}
	if b.failureThreshold != defaultFailureThreshold {
		t.Errorf("expected default threshold %d, got %d", defaultFailureThreshold, b.failureThreshold)
	}
	if b.cooldown != defaultCooldown {
		t.Errorf("expected default cooldown %v, got %v", defaultCooldown, b.cooldown)
	}
	if b.State() != Closed {
		t.Errorf("expected Closed, got %v", b.State())
	}
}

func TestNew_CustomValues(t *testing.T) {
	t.Parallel()
	b := New("custom", 5, 10*time.Second)
	if b.failureThreshold != 5 {
		t.Errorf("expected threshold 5, got %d", b.failureThreshold)
	}
	if b.cooldown != 10*time.Second {
		t.Errorf("expected 10s cooldown, got %v", b.cooldown)
	}
}

func TestNewDefault(t *testing.T) {
	t.Parallel()
	b := NewDefault("default")
	if b.Name() != "default" {
		t.Errorf("expected name 'default', got %q", b.Name())
	}
	if b.failureThreshold != defaultFailureThreshold {
		t.Error("expected default failure threshold")
	}
}

func TestAllow_Closed(t *testing.T) {
	t.Parallel()
	b := New("test", 5, time.Second)
	if !b.Allow() {
		t.Error("closed breaker should allow")
	}
}

func TestAllow_Open_BeforeCooldown(t *testing.T) {
	t.Parallel()
	b := New("test", 1, 10*time.Second)
	b.RecordFailure()
	if b.State() != Open {
		t.Fatal("expected Open state")
	}
	if b.Allow() {
		t.Error("open breaker before cooldown should not allow")
	}
}

func TestAllow_Open_AfterCooldown(t *testing.T) {
	t.Parallel()
	b := New("test", 1, 1*time.Millisecond)
	b.RecordFailure()
	time.Sleep(5 * time.Millisecond)
	if !b.Allow() {
		t.Error("open breaker after cooldown should allow (half-open)")
	}
	if b.State() != HalfOpen {
		t.Errorf("expected HalfOpen, got %v", b.State())
	}
}

func TestAllow_HalfOpen(t *testing.T) {
	t.Parallel()
	b := New("test", 1, 1*time.Millisecond)
	b.RecordFailure()
	time.Sleep(5 * time.Millisecond)
	b.Allow() // transitions to HalfOpen
	if !b.Allow() {
		t.Error("half-open breaker should allow")
	}
}

func TestRecordSuccess_ClosesFromHalfOpen(t *testing.T) {
	t.Parallel()
	b := New("test", 1, 1*time.Millisecond)
	b.RecordFailure()
	time.Sleep(5 * time.Millisecond)
	b.Allow() // transitions to HalfOpen
	b.RecordSuccess()
	if b.State() != Closed {
		t.Errorf("expected Closed after success in half-open, got %v", b.State())
	}
}

func TestRecordSuccess_ResetsFailCount(t *testing.T) {
	t.Parallel()
	b := New("test", 5, time.Second)
	b.RecordFailure()
	b.RecordFailure()
	b.RecordSuccess()
	snap := b.Snapshot()
	if snap.ConsecutiveFailures != 0 {
		t.Errorf("expected 0 consecutive failures after success, got %d", snap.ConsecutiveFailures)
	}
}

func TestRecordFailure_OpensAtThreshold(t *testing.T) {
	t.Parallel()
	b := New("test", 3, time.Second)
	b.RecordFailure()
	b.RecordFailure()
	if b.State() != Closed {
		t.Error("should still be closed after 2 failures (threshold=3)")
	}
	b.RecordFailure()
	if b.State() != Open {
		t.Errorf("expected Open after 3 failures, got %v", b.State())
	}
}

func TestRecordFailure_TracksTrips(t *testing.T) {
	t.Parallel()
	b := New("test", 1, 1*time.Millisecond)
	b.RecordFailure() // trip 1
	snap := b.Snapshot()
	if snap.TotalTrips != 1 {
		t.Errorf("expected 1 trip, got %d", snap.TotalTrips)
	}
	// Already open, another failure should not increment trips
	b.RecordFailure()
	snap = b.Snapshot()
	if snap.TotalTrips != 1 {
		t.Errorf("expected 1 trip (already open), got %d", snap.TotalTrips)
	}
}

func TestSnapshot(t *testing.T) {
	t.Parallel()
	b := New("snap-test", 3, time.Second)
	b.RecordFailure()
	snap := b.Snapshot()
	if snap.Name != "snap-test" {
		t.Errorf("expected name 'snap-test', got %q", snap.Name)
	}
	if snap.State != Closed {
		t.Errorf("expected Closed, got %v", snap.State)
	}
	if snap.ConsecutiveFailures != 1 {
		t.Errorf("expected 1 failure, got %d", snap.ConsecutiveFailures)
	}
}

func TestMetrics(t *testing.T) {
	t.Parallel()
	b := New("metrics-test", 1, time.Second)
	b.RecordFailure()
	m := b.Metrics()
	if m.State != Open {
		t.Errorf("expected Open, got %v", m.State)
	}
	if m.FailureCount != 1 {
		t.Errorf("expected FailureCount=1, got %d", m.FailureCount)
	}
	if m.OpenCount != 1 {
		t.Errorf("expected OpenCount=1, got %d", m.OpenCount)
	}
}

func TestReset(t *testing.T) {
	t.Parallel()
	b := New("reset-test", 1, time.Second)
	b.RecordFailure()
	if b.State() != Open {
		t.Fatal("expected Open")
	}
	b.Reset()
	if b.State() != Closed {
		t.Errorf("expected Closed after Reset, got %v", b.State())
	}
	snap := b.Snapshot()
	if snap.ConsecutiveFailures != 0 {
		t.Errorf("expected 0 failures after Reset, got %d", snap.ConsecutiveFailures)
	}
}

func TestNewWithConfig(t *testing.T) {
	t.Parallel()
	cfg := Config{
		FailureThreshold: 7,
		OpenTimeout:      5 * time.Second,
	}
	b := NewWithConfig(cfg)
	if b.failureThreshold != 7 {
		t.Errorf("expected threshold 7, got %d", b.failureThreshold)
	}
	if b.cooldown != 5*time.Second {
		t.Errorf("expected 5s cooldown, got %v", b.cooldown)
	}
}

func TestNewWithConfig_Defaults(t *testing.T) {
	t.Parallel()
	cfg := Config{} // all zeros
	b := NewWithConfig(cfg)
	if b.failureThreshold != defaultFailureThreshold {
		t.Error("expected default threshold for zero config")
	}
	if b.cooldown != defaultCooldown {
		t.Error("expected default cooldown for zero config")
	}
}

func TestNewWithConfig_HalfOpenTimeoutFallback(t *testing.T) {
	t.Parallel()
	cfg := Config{
		FailureThreshold: 2,
		HalfOpenTimeout:  3 * time.Second,
		// OpenTimeout is 0, should fallback to HalfOpenTimeout
	}
	b := NewWithConfig(cfg)
	if b.cooldown != 3*time.Second {
		t.Errorf("expected HalfOpenTimeout fallback 3s, got %v", b.cooldown)
	}
}

func TestStateConstants(t *testing.T) {
	t.Parallel()
	if StateClosed != Closed {
		t.Error("StateClosed mismatch")
	}
	if StateOpen != Open {
		t.Error("StateOpen mismatch")
	}
	if StateHalfOpen != HalfOpen {
		t.Error("StateHalfOpen mismatch")
	}
}

// ---------------------------------------------------------------------------
// Additional tests for task requirements
// ---------------------------------------------------------------------------

// TestBreaker_ClosedState verifies normal operation in the closed state:
// requests are allowed and failures below threshold keep the breaker closed.
func TestBreaker_ClosedState(t *testing.T) {
	t.Parallel()
	b := New("closed-test", 5, time.Second)

	// All requests should be allowed.
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("request %d should be allowed in closed state", i)
		}
	}

	// Record failures below threshold -- state stays closed.
	b.RecordFailure()
	b.RecordFailure()
	if b.State() != Closed {
		t.Errorf("expected Closed after 2 failures (threshold=5), got %v", b.State())
	}

	snap := b.Snapshot()
	if snap.ConsecutiveFailures != 2 {
		t.Errorf("expected 2 consecutive failures, got %d", snap.ConsecutiveFailures)
	}
}

// TestBreaker_OpenState verifies the breaker opens after threshold failures
// and rejects requests until cooldown expires.
func TestBreaker_OpenState(t *testing.T) {
	t.Parallel()
	b := New("open-test", 3, 10*time.Second)

	// Push to open state.
	for i := 0; i < 3; i++ {
		b.RecordFailure()
	}
	if b.State() != Open {
		t.Fatalf("expected Open, got %v", b.State())
	}

	// Requests should be rejected while open.
	if b.Allow() {
		t.Error("open breaker should reject requests before cooldown")
	}

	snap := b.Snapshot()
	if snap.TotalTrips != 1 {
		t.Errorf("expected 1 trip, got %d", snap.TotalTrips)
	}
}

// TestBreaker_HalfOpenState verifies the half-open state: after cooldown,
// a single test request is allowed.
func TestBreaker_HalfOpenState(t *testing.T) {
	t.Parallel()
	b := New("halfopen-test", 1, 1*time.Millisecond)

	b.RecordFailure() // opens
	if b.State() != Open {
		t.Fatal("expected Open")
	}

	time.Sleep(5 * time.Millisecond) // wait past cooldown

	// First Allow() transitions to HalfOpen.
	if !b.Allow() {
		t.Error("should allow test request after cooldown")
	}
	if b.State() != HalfOpen {
		t.Errorf("expected HalfOpen, got %v", b.State())
	}

	// Another Allow() while half-open should also succeed (allows test traffic).
	if !b.Allow() {
		t.Error("half-open should allow requests")
	}
}

// TestBreaker_Recovery verifies full recovery from open -> half-open -> closed.
func TestBreaker_Recovery(t *testing.T) {
	t.Parallel()
	b := New("recovery-test", 2, 1*time.Millisecond)

	// Trip the breaker.
	b.RecordFailure()
	b.RecordFailure()
	if b.State() != Open {
		t.Fatal("expected Open")
	}

	// Wait for cooldown.
	time.Sleep(5 * time.Millisecond)

	// Allow transitions to HalfOpen.
	if !b.Allow() {
		t.Error("should transition to half-open")
	}
	if b.State() != HalfOpen {
		t.Fatal("expected HalfOpen")
	}

	// Success in half-open transitions to Closed.
	b.RecordSuccess()
	if b.State() != Closed {
		t.Errorf("expected Closed after recovery, got %v", b.State())
	}

	// All requests should work again.
	for i := 0; i < 5; i++ {
		if !b.Allow() {
			t.Errorf("request %d should be allowed after recovery", i)
		}
	}
}

// TestBreaker_FailOpenPolicy simulates fail-open behaviour: when the breaker
// is open and cooldown expires, it allows a test request through (half-open).
// If that test request succeeds, the circuit closes, meaning the system
// defaults to allowing traffic (fail-open policy).
func TestBreaker_FailOpenPolicy(t *testing.T) {
	t.Parallel()
	b := New("fail-open", 1, 1*time.Millisecond)

	b.RecordFailure() // trip
	time.Sleep(5 * time.Millisecond)

	// After cooldown, the breaker transitions to half-open and allows traffic.
	allowed := b.Allow()
	if !allowed {
		t.Error("fail-open: should allow test request after cooldown")
	}

	// Simulate successful test request.
	b.RecordSuccess()
	if b.State() != Closed {
		t.Error("fail-open: should be closed after successful test")
	}

	// Steady-state: all requests pass.
	for i := 0; i < 10; i++ {
		if !b.Allow() {
			t.Fatalf("fail-open: request %d rejected after recovery", i)
		}
	}
}

// TestBreaker_FailClosedPolicy tests that when the breaker is open, all
// requests are rejected (fail-closed behaviour).
func TestBreaker_FailClosedPolicy(t *testing.T) {
	t.Parallel()
	b := New("fail-closed", 2, 10*time.Second) // long cooldown

	// Trip the breaker.
	b.RecordFailure()
	b.RecordFailure()
	if b.State() != Open {
		t.Fatal("expected Open")
	}

	// While open, all requests are rejected (fail-closed).
	for i := 0; i < 10; i++ {
		if b.Allow() {
			t.Fatalf("fail-closed: request %d should be rejected while open", i)
		}
	}

	// Verify metrics reflect the open state.
	m := b.Metrics()
	if m.State != Open {
		t.Errorf("expected Open in metrics, got %v", m.State)
	}
}

// TestBreaker_ConcurrentTrips tests that concurrent failure injection is safe
// and the breaker transitions correctly under contention.
func TestBreaker_ConcurrentTrips(t *testing.T) {
	t.Parallel()
	b := New("concurrent-trip", 5, time.Second)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			b.RecordFailure()
		}()
	}
	wg.Wait()

	// After 50 failures with threshold=5, breaker must be open.
	if b.State() != Open {
		t.Errorf("expected Open after concurrent failures, got %v", b.State())
	}

	snap := b.Snapshot()
	if snap.ConsecutiveFailures < 5 {
		t.Errorf("expected at least 5 consecutive failures, got %d", snap.ConsecutiveFailures)
	}
}

// TestBreaker_ConcurrentAllowAndRecord tests mixed concurrent Allow/Record calls.
func TestBreaker_ConcurrentAllowAndRecord(t *testing.T) {
	t.Parallel()
	b := New("concurrent-mixed", 3, 1*time.Millisecond)

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			_ = b.Allow()
			if n%3 == 0 {
				b.RecordFailure()
			} else {
				b.RecordSuccess()
			}
			_ = b.State()
			_ = b.Snapshot()
		}(i)
	}
	wg.Wait()

	// No panics, no data races -- that is the assertion.
}

// TestBreaker_ResetAfterSuccess tests that success resets the consecutive
// failure counter, preventing the breaker from tripping.
func TestBreaker_ResetAfterSuccess(t *testing.T) {
	t.Parallel()
	b := New("reset-after-success", 3, time.Second)

	// Accumulate 2 failures (below threshold).
	b.RecordFailure()
	b.RecordFailure()
	snap := b.Snapshot()
	if snap.ConsecutiveFailures != 2 {
		t.Fatalf("expected 2 failures, got %d", snap.ConsecutiveFailures)
	}

	// Success resets the counter.
	b.RecordSuccess()
	snap = b.Snapshot()
	if snap.ConsecutiveFailures != 0 {
		t.Errorf("expected 0 failures after success, got %d", snap.ConsecutiveFailures)
	}

	// Now 2 more failures should not trip (total 2 < threshold 3).
	b.RecordFailure()
	b.RecordFailure()
	if b.State() != Closed {
		t.Error("breaker should still be closed after 2 failures post-reset")
	}

	// Third failure trips it.
	b.RecordFailure()
	if b.State() != Open {
		t.Error("expected Open after 3 consecutive failures")
	}
}

// TestBreaker_ReOpenFromHalfOpen verifies that a failure in half-open state
// re-opens the breaker.
func TestBreaker_ReOpenFromHalfOpen(t *testing.T) {
	t.Parallel()
	b := New("reopen-halfopen", 1, 1*time.Millisecond)

	b.RecordFailure() // trip
	time.Sleep(5 * time.Millisecond)
	b.Allow() // half-open

	if b.State() != HalfOpen {
		t.Fatal("expected HalfOpen")
	}

	// Failure in half-open should re-trip.
	b.RecordFailure()
	if b.State() != Open {
		t.Errorf("expected Open after failure in half-open, got %v", b.State())
	}
}

// TestBreaker_MultipleTrips tracks total trip count across multiple cycles.
func TestBreaker_MultipleTrips(t *testing.T) {
	t.Parallel()
	b := New("multi-trip", 1, 1*time.Millisecond)

	for cycle := 0; cycle < 3; cycle++ {
		b.RecordFailure() // trip
		time.Sleep(5 * time.Millisecond)
		b.Allow() // half-open
		b.RecordSuccess() // close
	}

	snap := b.Snapshot()
	if snap.TotalTrips != 3 {
		t.Errorf("expected 3 total trips, got %d", snap.TotalTrips)
	}
}

// BenchmarkBreaker_Check measures the latency of Allow() checks.
func BenchmarkBreaker_Check(b *testing.B) {
	br := New("bench", 100, time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = br.Allow()
	}
}

// BenchmarkBreaker_Check_Open measures Allow() when the breaker is open.
func BenchmarkBreaker_Check_Open(b *testing.B) {
	br := New("bench-open", 1, time.Hour)
	br.RecordFailure()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = br.Allow()
	}
}
