package keeper

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ---------------------------------------------------------------------------
// Prometheus-native TPS and proof performance metrics
// ---------------------------------------------------------------------------
//
// This file provides production-grade Prometheus instrumentation for the PoUW
// module, covering TPS tracking, proof latency histograms, queue depth gauges,
// consensus timing, and seal lifecycle counters.
//
// These metrics complement the in-process ModuleMetrics (metrics.go) by
// exposing data in the standard Prometheus exposition format, enabling
// integration with Grafana dashboards, PagerDuty alerting, and long-term
// metric storage via Thanos or Cortex.
//
// All metrics use the "aethelred_pouw" namespace for consistent naming.
// ---------------------------------------------------------------------------

const (
	metricsNamespace = "aethelred"
	metricsSubsystem = "pouw"
)

// PrometheusMetrics provides production Prometheus metrics for the PoUW module.
type PrometheusMetrics struct {
	// --- TPS tracking ---

	// JobsSubmitted counts total job submissions.
	JobsSubmitted prometheus.Counter

	// JobsCompleted counts total completed jobs.
	JobsCompleted prometheus.Counter

	// JobsFailed counts total failed jobs.
	JobsFailed prometheus.Counter

	// TPSCurrent is the rolling 1-minute transactions-per-second gauge.
	TPSCurrent prometheus.Gauge

	// TPSPeak is the peak TPS observed in the current epoch.
	TPSPeak prometheus.Gauge

	// --- Proof performance ---

	// ProofGenerationSeconds records proof generation latency by type.
	ProofGenerationSeconds *prometheus.HistogramVec

	// VerificationSeconds records verification latency by type.
	VerificationSeconds *prometheus.HistogramVec

	// --- Queue ---

	// JobQueueDepth is the current number of pending jobs.
	JobQueueDepth prometheus.Gauge

	// PendingVerifications is the count of jobs awaiting verification.
	PendingVerifications prometheus.Gauge

	// --- Consensus ---

	// VoteExtensionLatency records vote extension processing time.
	VoteExtensionLatency prometheus.Histogram

	// ConsensusRoundLatency records consensus round completion time.
	ConsensusRoundLatency prometheus.Histogram

	// --- Seals ---

	// SealsCreated counts digital seals created.
	SealsCreated prometheus.Counter

	// SealsVerified counts digital seals verified.
	SealsVerified prometheus.Counter

	// --- Internal TPS tracking state ---
	mu              sync.Mutex
	recentJobTimes  []time.Time
	tpsWindowSize   time.Duration
	currentPeakTPS  float64
}

// NewPrometheusMetrics creates and registers all Prometheus metrics for the
// PoUW module. Panics on duplicate registration (use a custom registry in
// tests to avoid conflicts).
func NewPrometheusMetrics() *PrometheusMetrics {
	return newPrometheusMetricsWithRegisterer(prometheus.DefaultRegisterer)
}

// NewPrometheusMetricsWithRegistry creates metrics registered against the
// given registerer. This is intended for testing to avoid global state conflicts.
func NewPrometheusMetricsWithRegistry(reg prometheus.Registerer) *PrometheusMetrics {
	return newPrometheusMetricsWithRegisterer(reg)
}

func newPrometheusMetricsWithRegisterer(reg prometheus.Registerer) *PrometheusMetrics {
	m := &PrometheusMetrics{
		tpsWindowSize: 60 * time.Second,
	}

	// TPS counters.
	m.JobsSubmitted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "jobs_submitted_total",
		Help:      "Total number of compute jobs submitted.",
	})
	m.JobsCompleted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "jobs_completed_total",
		Help:      "Total number of compute jobs completed successfully.",
	})
	m.JobsFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "jobs_failed_total",
		Help:      "Total number of compute jobs that failed.",
	})

	// TPS gauges.
	m.TPSCurrent = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "tps_current",
		Help:      "Rolling 1-minute transactions per second.",
	})
	m.TPSPeak = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "tps_peak",
		Help:      "Peak TPS observed in current epoch.",
	})

	// Proof performance histograms with type label.
	proofBuckets := prometheus.ExponentialBuckets(0.001, 2, 15)
	m.ProofGenerationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "proof_generation_seconds",
		Help:      "Proof generation latency in seconds, partitioned by proof type.",
		Buckets:   proofBuckets,
	}, []string{"type"})

	m.VerificationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "verification_seconds",
		Help:      "Verification latency in seconds, partitioned by verification type.",
		Buckets:   proofBuckets,
	}, []string{"type"})

	// Queue gauges.
	m.JobQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "job_queue_depth",
		Help:      "Current number of pending jobs in the queue.",
	})
	m.PendingVerifications = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "pending_verifications",
		Help:      "Number of jobs awaiting verification results.",
	})

	// Consensus histograms.
	consensusBuckets := prometheus.ExponentialBuckets(0.01, 2, 12)
	m.VoteExtensionLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "vote_extension_latency_seconds",
		Help:      "Latency of vote extension processing in seconds.",
		Buckets:   consensusBuckets,
	})
	m.ConsensusRoundLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "consensus_round_latency_seconds",
		Help:      "Duration of consensus rounds in seconds.",
		Buckets:   consensusBuckets,
	})

	// Seal counters.
	m.SealsCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "seals_created_total",
		Help:      "Total number of digital seals created.",
	})
	m.SealsVerified = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "seals_verified_total",
		Help:      "Total number of digital seals verified.",
	})

	// Register all collectors.
	reg.MustRegister(
		m.JobsSubmitted,
		m.JobsCompleted,
		m.JobsFailed,
		m.TPSCurrent,
		m.TPSPeak,
		m.ProofGenerationSeconds,
		m.VerificationSeconds,
		m.JobQueueDepth,
		m.PendingVerifications,
		m.VoteExtensionLatency,
		m.ConsensusRoundLatency,
		m.SealsCreated,
		m.SealsVerified,
	)

	return m
}

// RecordJobSubmission increments the job submission counter and records the
// timestamp for TPS calculation.
func (m *PrometheusMetrics) RecordJobSubmission() {
	m.JobsSubmitted.Inc()

	m.mu.Lock()
	m.recentJobTimes = append(m.recentJobTimes, time.Now())
	m.mu.Unlock()
}

// RecordJobCompletion records a job completion event with its total duration
// and verification type.
func (m *PrometheusMetrics) RecordJobCompletion(duration time.Duration, verificationType string) {
	m.JobsCompleted.Inc()
	m.VerificationSeconds.WithLabelValues(verificationType).Observe(duration.Seconds())
}

// RecordJobFailure increments the failed job counter.
func (m *PrometheusMetrics) RecordJobFailure() {
	m.JobsFailed.Inc()
}

// RecordProofGeneration records proof generation latency by proof type.
func (m *PrometheusMetrics) RecordProofGeneration(duration time.Duration, proofType string) {
	m.ProofGenerationSeconds.WithLabelValues(proofType).Observe(duration.Seconds())
}

// RecordVerification records verification latency by verification type.
func (m *PrometheusMetrics) RecordVerification(duration time.Duration, verificationType string) {
	m.VerificationSeconds.WithLabelValues(verificationType).Observe(duration.Seconds())
}

// UpdateTPS recalculates the rolling TPS from recent job timestamps and
// updates the peak TPS if the current value exceeds it. This should be
// called periodically, typically from BeginBlock.
func (m *PrometheusMetrics) UpdateTPS() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-m.tpsWindowSize)

	// Prune expired timestamps.
	validIdx := 0
	for _, t := range m.recentJobTimes {
		if t.After(cutoff) {
			m.recentJobTimes[validIdx] = t
			validIdx++
		}
	}
	m.recentJobTimes = m.recentJobTimes[:validIdx]

	// Calculate TPS: count / window_seconds.
	windowSeconds := m.tpsWindowSize.Seconds()
	if windowSeconds <= 0 {
		windowSeconds = 60.0
	}
	currentTPS := float64(len(m.recentJobTimes)) / windowSeconds

	m.TPSCurrent.Set(currentTPS)

	if currentTPS > m.currentPeakTPS {
		m.currentPeakTPS = currentTPS
		m.TPSPeak.Set(m.currentPeakTPS)
	}
}

// UpdateQueueDepth sets the current job queue depth gauge.
func (m *PrometheusMetrics) UpdateQueueDepth(depth int) {
	m.JobQueueDepth.Set(float64(depth))
}

// UpdatePendingVerifications sets the pending verifications gauge.
func (m *PrometheusMetrics) UpdatePendingVerifications(count int) {
	m.PendingVerifications.Set(float64(count))
}

// ResetEpochPeak resets the peak TPS gauge at the start of a new epoch.
func (m *PrometheusMetrics) ResetEpochPeak() {
	m.mu.Lock()
	m.currentPeakTPS = 0
	m.mu.Unlock()
	m.TPSPeak.Set(0)
}
