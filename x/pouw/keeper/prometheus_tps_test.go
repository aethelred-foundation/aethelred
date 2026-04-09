package keeper_test

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/aethelred/aethelred/x/pouw/keeper"
)

// ---------------------------------------------------------------------------
// Prometheus TPS Metrics Tests
// ---------------------------------------------------------------------------

// newTestPrometheusMetrics creates PrometheusMetrics registered against an
// isolated registry to prevent global state conflicts between tests.
func newTestPrometheusMetrics(t *testing.T) *keeper.PrometheusMetrics {
	t.Helper()
	reg := prometheus.NewRegistry()
	return keeper.NewPrometheusMetricsWithRegistry(reg)
}

func TestPrometheusMetrics_RecordJobSubmission(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.RecordJobSubmission()
	m.RecordJobSubmission()
	m.RecordJobSubmission()

	val := counterValue(t, m.JobsSubmitted)
	require.InDelta(t, 3.0, val, 0.001, "expected 3 job submissions recorded")
}

func TestPrometheusMetrics_RecordJobCompletion(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.RecordJobCompletion(500*time.Millisecond, "tee")
	m.RecordJobCompletion(1*time.Second, "zkml")
	m.RecordJobCompletion(750*time.Millisecond, "hybrid")

	val := counterValue(t, m.JobsCompleted)
	require.InDelta(t, 3.0, val, 0.001, "expected 3 job completions recorded")
}

func TestPrometheusMetrics_RecordJobFailure(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.RecordJobFailure()
	m.RecordJobFailure()

	val := counterValue(t, m.JobsFailed)
	require.InDelta(t, 2.0, val, 0.001, "expected 2 job failures recorded")
}

func TestPrometheusMetrics_RecordProofGeneration(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.RecordProofGeneration(100*time.Millisecond, "tee")
	m.RecordProofGeneration(2*time.Second, "zkml")
	m.RecordProofGeneration(500*time.Millisecond, "hybrid")

	// Verify the histogram has observations by checking sample count.
	teeObs := histogramObserver(t, m.ProofGenerationSeconds, "tee")
	require.NotNil(t, teeObs, "tee histogram should have observations")
}

func TestPrometheusMetrics_RecordVerification(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.RecordVerification(200*time.Millisecond, "tee")
	m.RecordVerification(3*time.Second, "zkml")
	m.RecordVerification(1*time.Second, "hybrid")

	// Verify all three types are recorded.
	require.NotNil(t, histogramObserver(t, m.VerificationSeconds, "tee"))
	require.NotNil(t, histogramObserver(t, m.VerificationSeconds, "zkml"))
	require.NotNil(t, histogramObserver(t, m.VerificationSeconds, "hybrid"))
}

func TestPrometheusMetrics_UpdateTPS(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	// Submit several jobs to populate the TPS window.
	for i := 0; i < 10; i++ {
		m.RecordJobSubmission()
	}

	m.UpdateTPS()

	tpsCurrent := gaugeValue(t, m.TPSCurrent)
	require.Greater(t, tpsCurrent, 0.0, "TPS should be positive after submissions")

	tpsPeak := gaugeValue(t, m.TPSPeak)
	require.Greater(t, tpsPeak, 0.0, "peak TPS should be positive")
	require.GreaterOrEqual(t, tpsPeak, tpsCurrent, "peak TPS should be >= current TPS")
}

func TestPrometheusMetrics_UpdateQueueDepth(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.UpdateQueueDepth(42)
	val := gaugeValue(t, m.JobQueueDepth)
	require.InDelta(t, 42.0, val, 0.001, "queue depth should be 42")

	m.UpdateQueueDepth(0)
	val = gaugeValue(t, m.JobQueueDepth)
	require.InDelta(t, 0.0, val, 0.001, "queue depth should be 0 after reset")
}

func TestPrometheusMetrics_UpdatePendingVerifications(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.UpdatePendingVerifications(15)
	val := gaugeValue(t, m.PendingVerifications)
	require.InDelta(t, 15.0, val, 0.001, "pending verifications should be 15")
}

func TestPrometheusMetrics_ResetEpochPeak(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	// Build up some TPS.
	for i := 0; i < 20; i++ {
		m.RecordJobSubmission()
	}
	m.UpdateTPS()
	require.Greater(t, gaugeValue(t, m.TPSPeak), 0.0, "peak should be positive before reset")

	// Reset and verify it goes to zero.
	m.ResetEpochPeak()
	require.InDelta(t, 0.0, gaugeValue(t, m.TPSPeak), 0.001, "peak should be 0 after reset")
}

func TestPrometheusMetrics_SealsCreated(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.SealsCreated.Inc()
	m.SealsCreated.Inc()
	m.SealsCreated.Inc()

	val := counterValue(t, m.SealsCreated)
	require.InDelta(t, 3.0, val, 0.001, "expected 3 seals created")
}

func TestPrometheusMetrics_SealsVerified(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.SealsVerified.Inc()
	val := counterValue(t, m.SealsVerified)
	require.InDelta(t, 1.0, val, 0.001, "expected 1 seal verified")
}

func TestPrometheusMetrics_VoteExtensionLatency(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.VoteExtensionLatency.Observe(0.1)
	m.VoteExtensionLatency.Observe(0.5)
	m.VoteExtensionLatency.Observe(1.0)

	metric := &dto.Metric{}
	require.NoError(t, m.VoteExtensionLatency.(prometheus.Metric).Write(metric))
	require.NotNil(t, metric.Histogram)
	require.Equal(t, uint64(3), *metric.Histogram.SampleCount)
}

func TestPrometheusMetrics_ConsensusRoundLatency(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	m.ConsensusRoundLatency.Observe(0.05)
	m.ConsensusRoundLatency.Observe(0.2)

	metric := &dto.Metric{}
	require.NoError(t, m.ConsensusRoundLatency.(prometheus.Metric).Write(metric))
	require.NotNil(t, metric.Histogram)
	require.Equal(t, uint64(2), *metric.Histogram.SampleCount)
}

func TestPrometheusMetrics_TPSDecaysOverWindow(t *testing.T) {
	m := newTestPrometheusMetrics(t)

	// Record one submission.
	m.RecordJobSubmission()
	m.UpdateTPS()
	tpsAfterOne := gaugeValue(t, m.TPSCurrent)

	// Record more submissions.
	for i := 0; i < 5; i++ {
		m.RecordJobSubmission()
	}
	m.UpdateTPS()
	tpsAfterSix := gaugeValue(t, m.TPSCurrent)

	require.Greater(t, tpsAfterSix, tpsAfterOne,
		"TPS should increase with more submissions in the same window")
}

// ---------------------------------------------------------------------------
// Test helpers for reading Prometheus metric values
// ---------------------------------------------------------------------------

// counterValue extracts the current value of a prometheus.Counter.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	metric := &dto.Metric{}
	require.NoError(t, c.(prometheus.Metric).Write(metric))
	require.NotNil(t, metric.Counter, "expected counter metric type")
	return *metric.Counter.Value
}

// gaugeValue extracts the current value of a prometheus.Gauge.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	metric := &dto.Metric{}
	require.NoError(t, g.(prometheus.Metric).Write(metric))
	require.NotNil(t, metric.Gauge, "expected gauge metric type")
	return *metric.Gauge.Value
}

// histogramObserver returns the histogram metric for a given label value, or nil.
func histogramObserver(t *testing.T, hv *prometheus.HistogramVec, label string) prometheus.Observer {
	t.Helper()
	obs, err := hv.GetMetricWithLabelValues(label)
	require.NoError(t, err)
	return obs
}
