package circuitbreaker

import (
	"sync"
	"time"
)

// State represents the state of a circuit breaker.
type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	case HalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

const (
	defaultFailureThreshold int64         = 3
	defaultCooldown         time.Duration = 30 * time.Second
)

// Breaker protects a subsystem from cascading failures by tracking
// consecutive errors. When the threshold is exceeded, it opens and rejects
// all requests for the cooldown period before allowing a single test request
// (half-open).
type Breaker struct {
	mu               sync.Mutex
	name             string
	failureThreshold int64
	cooldown         time.Duration
	consecutiveFails int64
	state            State
	lastFailTime     time.Time
	totalTrips       int64
}

// New creates a new circuit breaker.
func New(name string, failureThreshold int64, cooldown time.Duration) *Breaker {
	if failureThreshold <= 0 {
		failureThreshold = defaultFailureThreshold
	}
	if cooldown <= 0 {
		cooldown = defaultCooldown
	}
	return &Breaker{
		name:             name,
		failureThreshold: failureThreshold,
		cooldown:         cooldown,
		state:            Closed,
	}
}

// NewDefault creates a breaker with default thresholds.
func NewDefault(name string) *Breaker {
	return New(name, defaultFailureThreshold, defaultCooldown)
}

// Allow returns true if the circuit is closed or half-open (allowing a test
// request). Returns false if the circuit is open and the cooldown has not
// elapsed.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case Closed:
		return true
	case Open:
		if time.Since(b.lastFailTime) >= b.cooldown {
			b.state = HalfOpen
			return true
		}
		return false
	case HalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful operation. If the breaker is half-open,
// it transitions to closed.
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.consecutiveFails = 0
	if b.state == HalfOpen {
		b.state = Closed
	}
}

// RecordFailure records a failed operation. If consecutive failures exceed
// the threshold, the breaker opens.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.consecutiveFails++
	b.lastFailTime = time.Now()

	if b.consecutiveFails >= b.failureThreshold {
		if b.state != Open {
			b.totalTrips++
		}
		b.state = Open
	}
}

// Snapshot returns the breaker state for metrics/inspection.
func (b *Breaker) Snapshot() Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()

	return Snapshot{
		Name:                b.name,
		State:               b.state,
		ConsecutiveFailures: b.consecutiveFails,
		TotalTrips:          b.totalTrips,
	}
}

// Name returns the breaker name.
func (b *Breaker) Name() string {
	return b.name
}

// Snapshot captures breaker state for metrics.
type Snapshot struct {
	Name                string
	State               State
	ConsecutiveFailures int64
	TotalTrips          int64
}

// State returns the current state of the circuit breaker.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Metrics returns the circuit breaker metrics for observability.
type Metrics struct {
	State         State
	FailureCount  int64
	SuccessCount  int64
	RejectedCount int64
	OpenCount     int64
}

// Metrics returns the current metrics (alias for Snapshot compatibility).
func (b *Breaker) Metrics() Metrics {
	snap := b.Snapshot()
	return Metrics{
		State:        snap.State,
		FailureCount: snap.ConsecutiveFailures,
		OpenCount:    snap.TotalTrips,
	}
}

// Reset resets the circuit breaker to closed state.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = Closed
	b.consecutiveFails = 0
}

// Config represents circuit breaker configuration for testing.
type Config struct {
	FailureThreshold int
	SuccessThreshold int
	HalfOpenTimeout  time.Duration
	OpenTimeout      time.Duration
}

// NewWithConfig creates a circuit breaker with explicit configuration.
// This is primarily for testing purposes.
func NewWithConfig(cfg Config) *Breaker {
	threshold := int64(cfg.FailureThreshold)
	if threshold <= 0 {
		threshold = defaultFailureThreshold
	}
	cooldown := cfg.OpenTimeout
	if cooldown <= 0 {
		cooldown = cfg.HalfOpenTimeout
	}
	if cooldown <= 0 {
		cooldown = defaultCooldown
	}
	return &Breaker{
		name:             "configured",
		failureThreshold: threshold,
		cooldown:         cooldown,
		state:            Closed,
	}
}

// Constants for state comparison in tests
const (
	StateClosed   = Closed
	StateOpen     = Open
	StateHalfOpen = HalfOpen
)
