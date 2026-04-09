// Package shared provides cross-cutting observability, validation, and retry
// utilities used by all Aethelred packages. It defines common interfaces for
// structured logging and metrics collection that allow callers to plug in
// their preferred observability backends (e.g., Prometheus, OpenTelemetry,
// Zap, zerolog) while providing no-op defaults for lightweight testing.
package shared

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

// ---------------------------------------------------------------------------
// Logger interface
// ---------------------------------------------------------------------------

// Logger provides structured logging for Aethelred packages.
// Implementations may target any backend (e.g., zerolog, zap, slog).
// The fields variadic follows the key-value pair convention:
//
//	logger.Info("seal created", "seal_id", id, "block_height", height)
type Logger interface {
	Info(msg string, fields ...any)
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
	Debug(msg string, fields ...any)
}

// ---------------------------------------------------------------------------
// MetricsCollector interface
// ---------------------------------------------------------------------------

// MetricsCollector provides metrics collection hooks that can be backed by
// Prometheus, OpenTelemetry, or any other metrics system.
type MetricsCollector interface {
	// IncrementCounter atomically increments a counter metric.
	IncrementCounter(name string, labels ...string)

	// ObserveHistogram records a single observation in a histogram metric.
	ObserveHistogram(name string, value float64, labels ...string)

	// SetGauge sets a gauge metric to the given value.
	SetGauge(name string, value float64, labels ...string)
}

// ---------------------------------------------------------------------------
// No-op implementations
// ---------------------------------------------------------------------------

// NoopLogger is a no-op logger used when no logger is configured.
// All methods silently discard their arguments.
type NoopLogger struct{}

func (NoopLogger) Info(msg string, fields ...any)  {}
func (NoopLogger) Warn(msg string, fields ...any)  {}
func (NoopLogger) Error(msg string, fields ...any) {}
func (NoopLogger) Debug(msg string, fields ...any) {}

// NoopMetrics is a no-op metrics collector used when no metrics backend
// is configured. All methods silently discard their arguments.
type NoopMetrics struct{}

func (NoopMetrics) IncrementCounter(name string, labels ...string)                {}
func (NoopMetrics) ObserveHistogram(name string, value float64, labels ...string) {}
func (NoopMetrics) SetGauge(name string, value float64, labels ...string)         {}

// ---------------------------------------------------------------------------
// Retry utilities
// ---------------------------------------------------------------------------

// Retry executes fn up to attempts times with exponential backoff and
// jitter between retries. Returns the last error if all attempts fail.
// The base delay is doubled on each retry, capped at 30 seconds, with
// up to 25% random jitter to prevent thundering herd effects.
//
// Example:
//
//	err := shared.Retry(3, 100*time.Millisecond, func() error {
//	    return client.Send(request)
//	})
func Retry(attempts int, baseDelay time.Duration, fn func() error) error {
	if attempts <= 0 {
		return fmt.Errorf("shared/retry: attempts must be positive")
	}

	var lastErr error
	delay := baseDelay

	for i := 0; i < attempts; i++ {
		lastErr = fn()
		if lastErr == nil {
			return nil
		}

		// Don't sleep after the last failed attempt.
		if i < attempts-1 {
			jitter := time.Duration(rand.Int63n(int64(delay) / 4))
			time.Sleep(delay + jitter)
			delay = time.Duration(math.Min(float64(delay*2), float64(30*time.Second)))
		}
	}

	return fmt.Errorf("shared/retry: all %d attempts failed: %w", attempts, lastErr)
}

// RetryWithResult executes fn up to attempts times with exponential
// backoff, returning the result value on success. Uses the same backoff
// strategy as Retry.
//
// Example:
//
//	resp, err := shared.RetryWithResult(3, 100*time.Millisecond, func() (*Response, error) {
//	    return client.Get(url)
//	})
func RetryWithResult[T any](attempts int, baseDelay time.Duration, fn func() (T, error)) (T, error) {
	var zero T
	if attempts <= 0 {
		return zero, fmt.Errorf("shared/retry: attempts must be positive")
	}

	var lastErr error
	delay := baseDelay

	for i := 0; i < attempts; i++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err

		// Don't sleep after the last failed attempt.
		if i < attempts-1 {
			jitter := time.Duration(rand.Int63n(int64(delay) / 4))
			time.Sleep(delay + jitter)
			delay = time.Duration(math.Min(float64(delay*2), float64(30*time.Second)))
		}
	}

	return zero, fmt.Errorf("shared/retry: all %d attempts failed: %w", attempts, lastErr)
}
