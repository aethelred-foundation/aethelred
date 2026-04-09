package fhir

// Logger defines the logging interface for the FHIR integration package.
// Implementations may route to any structured logging backend.
type Logger interface {
	// Info logs an informational message with structured key-value pairs.
	Info(msg string, keysAndValues ...interface{})

	// Warn logs a warning message with structured key-value pairs.
	Warn(msg string, keysAndValues ...interface{})

	// Error logs an error message with structured key-value pairs.
	Error(msg string, keysAndValues ...interface{})
}

// MetricsCollector defines the metrics interface for the FHIR integration
// package. Implementations may route to Prometheus, OpenTelemetry, or any
// other metrics backend.
type MetricsCollector interface {
	// IncCounter increments a named counter by 1.
	IncCounter(name string, labels ...string)

	// ObserveHistogram records an observation for a named histogram.
	ObserveHistogram(name string, value float64, labels ...string)
}

// nopLogger is a no-op implementation of Logger used when none is provided.
type nopLogger struct{}

func (nopLogger) Info(string, ...interface{})  {}
func (nopLogger) Warn(string, ...interface{})  {}
func (nopLogger) Error(string, ...interface{}) {}

// nopMetrics is a no-op implementation of MetricsCollector.
type nopMetrics struct{}

func (nopMetrics) IncCounter(string, ...string)              {}
func (nopMetrics) ObserveHistogram(string, float64, ...string) {}
