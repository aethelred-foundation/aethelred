package billing

// Logger defines the logging interface for the billing package.
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
}

// MetricsCollector defines the metrics interface for the billing package.
type MetricsCollector interface {
	IncCounter(name string, labels ...string)
	ObserveHistogram(name string, value float64, labels ...string)
}
