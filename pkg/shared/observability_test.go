package shared

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// NoopLogger tests
// ---------------------------------------------------------------------------

func TestNoopLogger_AllLevels(t *testing.T) {
	t.Parallel()
	var l NoopLogger

	// These must not panic, even with varied argument types.
	l.Info("test message")
	l.Warn("test message", "key", 42)
	l.Error("test message", "key", "value", "count", 3)
	l.Debug("test message", "nested", map[string]int{"a": 1})
}

func TestNoopLogger_Satisfies_LoggerInterface(t *testing.T) {
	t.Parallel()
	var _ Logger = NoopLogger{}
	var _ Logger = &NoopLogger{}
}

func TestNoopLogger_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	var l NoopLogger
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			l.Info("concurrent", "goroutine", n)
			l.Warn("concurrent", "goroutine", n)
			l.Error("concurrent", "goroutine", n)
			l.Debug("concurrent", "goroutine", n)
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// NoopMetrics tests
// ---------------------------------------------------------------------------

func TestNoopMetrics_AllMethods(t *testing.T) {
	t.Parallel()
	var m NoopMetrics

	m.IncrementCounter("requests_total", "method", "GET")
	m.ObserveHistogram("request_duration_seconds", 0.123, "path", "/api/v1/seal")
	m.SetGauge("active_connections", 42.0, "region", "us-east-1")

	// With no labels.
	m.IncrementCounter("simple_counter")
	m.ObserveHistogram("simple_histogram", 1.5)
	m.SetGauge("simple_gauge", 100.0)
}

func TestNoopMetrics_Satisfies_MetricsCollectorInterface(t *testing.T) {
	t.Parallel()
	var _ MetricsCollector = NoopMetrics{}
	var _ MetricsCollector = &NoopMetrics{}
}

func TestNoopMetrics_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	var m NoopMetrics
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			m.IncrementCounter("concurrent_counter", "goroutine", "test")
			m.ObserveHistogram("concurrent_histogram", float64(n))
			m.SetGauge("concurrent_gauge", float64(n))
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Retry tests
// ---------------------------------------------------------------------------

func TestRetry_SucceedsOnFirstAttempt(t *testing.T) {
	t.Parallel()

	calls := 0
	err := Retry(3, time.Millisecond, func() error {
		calls++
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetry_SucceedsOnSecondAttempt(t *testing.T) {
	t.Parallel()

	calls := 0
	err := Retry(3, time.Millisecond, func() error {
		calls++
		if calls < 2 {
			return errors.New("transient failure")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
}

func TestRetry_AllAttemptsFail(t *testing.T) {
	t.Parallel()

	calls := 0
	sentinel := errors.New("permanent failure")
	err := Retry(3, time.Millisecond, func() error {
		calls++
		return sentinel
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetry_ZeroAttempts(t *testing.T) {
	t.Parallel()

	err := Retry(0, time.Millisecond, func() error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for zero attempts")
	}
}

func TestRetry_NegativeAttempts(t *testing.T) {
	t.Parallel()

	err := Retry(-1, time.Millisecond, func() error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for negative attempts")
	}
}

func TestRetry_SingleAttempt(t *testing.T) {
	t.Parallel()

	calls := 0
	err := Retry(1, time.Millisecond, func() error {
		calls++
		return errors.New("fail")
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetry_ConcurrentUsage(t *testing.T) {
	t.Parallel()

	var wg sync.WaitGroup
	var successCount atomic.Int32

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := Retry(3, time.Millisecond, func() error {
				return nil
			})
			if err == nil {
				successCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if successCount.Load() != 20 {
		t.Fatalf("expected 20 successes, got %d", successCount.Load())
	}
}

// ---------------------------------------------------------------------------
// RetryWithResult tests
// ---------------------------------------------------------------------------

func TestRetryWithResult_SucceedsOnFirstAttempt(t *testing.T) {
	t.Parallel()

	calls := 0
	result, err := RetryWithResult(3, time.Millisecond, func() (string, error) {
		calls++
		return "ok", nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected 'ok', got %q", result)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call, got %d", calls)
	}
}

func TestRetryWithResult_SucceedsOnThirdAttempt(t *testing.T) {
	t.Parallel()

	calls := 0
	result, err := RetryWithResult(5, time.Millisecond, func() (int, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("not yet")
		}
		return 42, nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if result != 42 {
		t.Fatalf("expected 42, got %d", result)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetryWithResult_AllAttemptsFail(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("permanent")
	result, err := RetryWithResult(2, time.Millisecond, func() (string, error) {
		return "", sentinel
	})

	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel, got: %v", err)
	}
	if result != "" {
		t.Fatalf("expected zero value, got %q", result)
	}
}

func TestRetryWithResult_ZeroAttempts(t *testing.T) {
	t.Parallel()

	_, err := RetryWithResult(0, time.Millisecond, func() (int, error) {
		return 0, nil
	})
	if err == nil {
		t.Fatal("expected error for zero attempts")
	}
}

func TestRetryWithResult_StructResult(t *testing.T) {
	t.Parallel()

	type payload struct {
		Value int
		Name  string
	}

	calls := 0
	result, err := RetryWithResult(3, time.Millisecond, func() (payload, error) {
		calls++
		if calls < 2 {
			return payload{}, errors.New("retry")
		}
		return payload{Value: 100, Name: "test"}, nil
	})

	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if result.Value != 100 || result.Name != "test" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// ---------------------------------------------------------------------------
// recordingLogger verifies Logger is callable with any implementation
// ---------------------------------------------------------------------------

type recordingLogger struct {
	mu       sync.Mutex
	messages []string
}

func (r *recordingLogger) Info(msg string, fields ...any)  { r.record("INFO", msg) }
func (r *recordingLogger) Warn(msg string, fields ...any)  { r.record("WARN", msg) }
func (r *recordingLogger) Error(msg string, fields ...any) { r.record("ERROR", msg) }
func (r *recordingLogger) Debug(msg string, fields ...any) { r.record("DEBUG", msg) }

func (r *recordingLogger) record(level, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.messages = append(r.messages, level+": "+msg)
}

func TestCustomLoggerImplementation(t *testing.T) {
	t.Parallel()

	var logger Logger = &recordingLogger{}
	logger.Info("hello")
	logger.Warn("caution")
	logger.Error("failure")
	logger.Debug("trace")

	rl := logger.(*recordingLogger)
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if len(rl.messages) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(rl.messages))
	}
}

// ---------------------------------------------------------------------------
// recordingMetrics verifies MetricsCollector is callable
// ---------------------------------------------------------------------------

type recordingMetrics struct {
	mu       sync.Mutex
	counters map[string]int
}

func (r *recordingMetrics) IncrementCounter(name string, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counters == nil {
		r.counters = make(map[string]int)
	}
	r.counters[name]++
}

func (r *recordingMetrics) ObserveHistogram(name string, value float64, labels ...string) {}
func (r *recordingMetrics) SetGauge(name string, value float64, labels ...string)         {}

func TestCustomMetricsImplementation(t *testing.T) {
	t.Parallel()

	var metrics MetricsCollector = &recordingMetrics{}
	metrics.IncrementCounter("test_counter", "env", "test")
	metrics.IncrementCounter("test_counter", "env", "test")
	metrics.IncrementCounter("other_counter")

	rm := metrics.(*recordingMetrics)
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.counters["test_counter"] != 2 {
		t.Fatalf("expected test_counter=2, got %d", rm.counters["test_counter"])
	}
	if rm.counters["other_counter"] != 1 {
		t.Fatalf("expected other_counter=1, got %d", rm.counters["other_counter"])
	}
}
