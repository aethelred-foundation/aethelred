package epcis

// Logger defines the logging interface for the EPCIS integration package.
type Logger interface {
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
}

// MetricsCollector defines the metrics interface for the EPCIS integration package.
type MetricsCollector interface {
	IncCounter(name string, labels ...string)
	ObserveHistogram(name string, value float64, labels ...string)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...interface{})  {}
func (nopLogger) Warn(string, ...interface{})  {}
func (nopLogger) Error(string, ...interface{}) {}

type nopMetrics struct{}

func (nopMetrics) IncCounter(string, ...string)              {}
func (nopMetrics) ObserveHistogram(string, float64, ...string) {}
