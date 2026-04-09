package audit

// Logger provides structured logging for the audit package.
type Logger interface {
	Info(msg string, fields ...any)
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
}

// MetricsCollector provides metrics collection hooks for the audit package.
type MetricsCollector interface {
	IncrementCounter(name string, labels ...string)
	ObserveHistogram(name string, value float64, labels ...string)
	SetGauge(name string, value float64, labels ...string)
}

// NoopLogger is a no-op logger used when no logger is configured.
type NoopLogger struct{}

func (n NoopLogger) Info(msg string, fields ...any)  {}
func (n NoopLogger) Warn(msg string, fields ...any)  {}
func (n NoopLogger) Error(msg string, fields ...any) {}

// NoopMetrics is a no-op metrics collector.
type NoopMetrics struct{}

func (n NoopMetrics) IncrementCounter(name string, labels ...string)                {}
func (n NoopMetrics) ObserveHistogram(name string, value float64, labels ...string) {}
func (n NoopMetrics) SetGauge(name string, value float64, labels ...string)         {}
