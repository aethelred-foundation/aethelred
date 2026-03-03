package circuitbreaker

import (
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
