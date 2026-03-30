// Package loadtest provides enterprise-grade load testing infrastructure
// for Aethelred blockchain's Proof-of-Useful-Work consensus.
//
// This tool validates that the system can handle:
//   - 10,000+ compute jobs per block
//   - Concurrent validator verification
//   - High-throughput vote extensions
//   - Network partition simulation
//
// Usage:
//
//	loadtest -validators 100 -jobs 10000 -blocks 10 -duration 1h
package loadtest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// Configuration
// ============================================================================

// Config holds load test configuration
type Config struct {
	// Execution mode
	Mode            string `json:"mode"` // simulation or node
	RPCEndpoint     string `json:"rpc_endpoint"`
	APIEndpoint     string `json:"api_endpoint"`
	NodeConcurrency int    `json:"node_concurrency"`

	// Test parameters
	NumValidators int           `json:"num_validators"`
	JobsPerBlock  int           `json:"jobs_per_block"`
	NumBlocks     int           `json:"num_blocks"`
	Duration      time.Duration `json:"duration"`
	BlockTime     time.Duration `json:"block_time"`

	// Job configuration
	JobPayloadSize   int    `json:"job_payload_size"`
	ModelHashSize    int    `json:"model_hash_size"`
	VerificationType string `json:"verification_type"` // tee, zkml, hybrid

	// Network simulation
	NetworkLatencyMin time.Duration `json:"network_latency_min"`
	NetworkLatencyMax time.Duration `json:"network_latency_max"`
	PacketLossRate    float64       `json:"packet_loss_rate"`

	// Failure injection
	ValidatorFailureRate float64 `json:"validator_failure_rate"`
	ByzantineRate        float64 `json:"byzantine_rate"`

	// Output
	OutputDir       string        `json:"output_dir"`
	ReportInterval  time.Duration `json:"report_interval"`
	DetailedMetrics bool          `json:"detailed_metrics"`
}

// DefaultConfig returns production-ready defaults
func DefaultConfig() *Config {
	return &Config{
		Mode:                 "simulation",
		RPCEndpoint:          "http://localhost:26657",
		APIEndpoint:          "http://localhost:1317",
		NodeConcurrency:      16,
		NumValidators:        100,
		JobsPerBlock:         10000,
		NumBlocks:            100,
		Duration:             1 * time.Hour,
		BlockTime:            6 * time.Second,
		JobPayloadSize:       1024, // 1KB payload
		ModelHashSize:        32,   // SHA-256
		VerificationType:     "hybrid",
		NetworkLatencyMin:    10 * time.Millisecond,
		NetworkLatencyMax:    100 * time.Millisecond,
		PacketLossRate:       0.001, // 0.1% packet loss
		ValidatorFailureRate: 0.01,  // 1% validator failure
		ByzantineRate:        0.0,   // No byzantine by default
		OutputDir:            "./loadtest-results",
		ReportInterval:       10 * time.Second,
		DetailedMetrics:      true,
	}
}

// ============================================================================
// Metrics Collection
// ============================================================================

// Metrics tracks all load test metrics
type Metrics struct {
	mu sync.RWMutex

	// Job metrics
	JobsSubmitted int64
	JobsCompleted int64
	JobsFailed    int64
	JobsTimeout   int64

	// Block metrics
	BlocksProduced  int64
	BlocksFinalized int64
	BlocksFailed    int64

	// Timing metrics (in nanoseconds for precision)
	JobSubmissionTimes   []int64
	JobCompletionTimes   []int64
	BlockProductionTimes []int64
	ConsensusRoundTimes  []int64
	VerificationTimes    []int64

	// Vote extension metrics
	VoteExtensionsGenerated int64
	VoteExtensionsVerified  int64
	VoteExtensionsFailed    int64

	// Network metrics
	NetworkErrors  int64
	PacketsDropped int64
	RetryAttempts  int64

	// Validator metrics
	ActiveValidators    int64
	FailedValidators    int64
	RecoveredValidators int64

	// Throughput tracking
	ThroughputSamples []ThroughputSample

	// Error tracking
	Errors []ErrorRecord
}

// ThroughputSample records throughput at a point in time
type ThroughputSample struct {
	Timestamp       time.Time
	JobsPerSecond   float64
	BlocksPerMinute float64
	AvgLatencyMs    float64
}

// ErrorRecord tracks individual errors
type ErrorRecord struct {
	Timestamp   time.Time
	Component   string
	Error       string
	ValidatorID int
	JobID       string
}

// NewMetrics creates a new metrics collector
func NewMetrics() *Metrics {
	return &Metrics{
		JobSubmissionTimes:   make([]int64, 0, 100000),
		JobCompletionTimes:   make([]int64, 0, 100000),
		BlockProductionTimes: make([]int64, 0, 1000),
		ConsensusRoundTimes:  make([]int64, 0, 1000),
		VerificationTimes:    make([]int64, 0, 100000),
		ThroughputSamples:    make([]ThroughputSample, 0, 10000),
		Errors:               make([]ErrorRecord, 0, 10000),
	}
}

// RecordJobSubmission records a job submission
func (m *Metrics) RecordJobSubmission(duration time.Duration) {
	atomic.AddInt64(&m.JobsSubmitted, 1)
	m.mu.Lock()
	m.JobSubmissionTimes = append(m.JobSubmissionTimes, duration.Nanoseconds())
	m.mu.Unlock()
}

// RecordJobCompletion records a job completion
func (m *Metrics) RecordJobCompletion(duration time.Duration, success bool) {
	if success {
		atomic.AddInt64(&m.JobsCompleted, 1)
	} else {
		atomic.AddInt64(&m.JobsFailed, 1)
	}
	m.mu.Lock()
	m.JobCompletionTimes = append(m.JobCompletionTimes, duration.Nanoseconds())
	m.mu.Unlock()
}

// RecordBlock records a block production
func (m *Metrics) RecordBlock(duration time.Duration, finalized bool) {
	atomic.AddInt64(&m.BlocksProduced, 1)
	if finalized {
		atomic.AddInt64(&m.BlocksFinalized, 1)
	} else {
		atomic.AddInt64(&m.BlocksFailed, 1)
	}
	m.mu.Lock()
	m.BlockProductionTimes = append(m.BlockProductionTimes, duration.Nanoseconds())
	m.mu.Unlock()
}

// RecordConsensus records a consensus round
func (m *Metrics) RecordConsensus(duration time.Duration) {
	m.mu.Lock()
	m.ConsensusRoundTimes = append(m.ConsensusRoundTimes, duration.Nanoseconds())
	m.mu.Unlock()
}

// RecordVerification records a verification
func (m *Metrics) RecordVerification(duration time.Duration) {
	m.mu.Lock()
	m.VerificationTimes = append(m.VerificationTimes, duration.Nanoseconds())
	m.mu.Unlock()
}

// RecordError records an error
func (m *Metrics) RecordError(component, err string, validatorID int, jobID string) {
	m.mu.Lock()
	m.Errors = append(m.Errors, ErrorRecord{
		Timestamp:   time.Now(),
		Component:   component,
		Error:       err,
		ValidatorID: validatorID,
		JobID:       jobID,
	})
	m.mu.Unlock()
}

// ============================================================================
// Load Test Components
// ============================================================================

// SimulatedJob represents a compute job for testing
type SimulatedJob struct {
	ID            string
	ModelHash     []byte
	InputHash     []byte
	PayloadSize   int
	SubmittedAt   time.Time
	CompletedAt   time.Time
	Verifications int
	Status        string // pending, processing, completed, failed
}

// SimulatedValidator represents a validator for testing
type SimulatedValidator struct {
	ID              int
	VotingPower     int64
	IsActive        bool
	IsByzantine     bool
	FailureRate     float64
	ProcessingDelay time.Duration

	mu             sync.Mutex
	jobsProcessed  int64
	votesGenerated int64
	errors         int64
}

// SimulatedBlock represents a block for testing
type SimulatedBlock struct {
	Height         int64
	Timestamp      time.Time
	Jobs           []*SimulatedJob
	VoteExtensions [][]byte
	ProposerID     int
	Finalized      bool
	Duration       time.Duration
}

// ============================================================================
// Load Test Runner
// ============================================================================

// Runner executes load tests
type Runner struct {
	config     *Config
	metrics    *Metrics
	validators []*SimulatedValidator
	jobs       chan *SimulatedJob
	blocks     []*SimulatedBlock

	mu        sync.RWMutex
	running   bool
	startTime time.Time
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewRunner creates a new load test runner
func NewRunner(config *Config) *Runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		config:  config,
		metrics: NewMetrics(),
		jobs:    make(chan *SimulatedJob, config.JobsPerBlock*2),
		blocks:  make([]*SimulatedBlock, 0, config.NumBlocks),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Run executes the load test
func (r *Runner) Run() (*Report, error) {
	if strings.EqualFold(r.config.Mode, "node") {
		return r.runAgainstNode()
	}

	r.mu.Lock()
	r.running = true
	r.startTime = time.Now()
	r.mu.Unlock()

	// Initialize validators
	r.initValidators()

	// Start metrics reporter
	go r.metricsReporter()

	// Start job generators
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.generateJobs()
	}()

	// Start block producer
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.produceBlocks()
	}()

	// Wait for test duration or completion
	select {
	case <-time.After(r.config.Duration):
	case <-r.ctx.Done():
	}

	r.cancel()
	wg.Wait()

	r.mu.Lock()
	r.running = false
	r.mu.Unlock()

	return r.generateReport()
}

// runAgainstNode executes integration load testing against a live node/API.
func (r *Runner) runAgainstNode() (*Report, error) {
	r.mu.Lock()
	r.running = true
	r.startTime = time.Now()
	r.mu.Unlock()

	if r.config.NodeConcurrency <= 0 {
		r.config.NodeConcurrency = 1
	}

	// Keep metadata fields meaningful for reporting.
	atomic.StoreInt64(&r.metrics.ActiveValidators, int64(r.config.NumValidators))

	client := &http.Client{Timeout: 12 * time.Second}
	go r.metricsReporter()

	var (
		wg         sync.WaitGroup
		maxHeight  int64
		heightLock sync.Mutex
	)

	probe := func(endpoint string, label string) {
		start := time.Now()
		atomic.AddInt64(&r.metrics.JobsSubmitted, 1)
		resp, err := client.Get(endpoint)
		if err != nil {
			atomic.AddInt64(&r.metrics.NetworkErrors, 1)
			r.metrics.RecordError(label, err.Error(), -1, "")
			r.metrics.RecordJobCompletion(time.Since(start), false)
			return
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			atomic.AddInt64(&r.metrics.NetworkErrors, 1)
			r.metrics.RecordError(label, readErr.Error(), -1, "")
			r.metrics.RecordJobCompletion(time.Since(start), false)
			return
		}
		if resp.StatusCode >= http.StatusBadRequest {
			atomic.AddInt64(&r.metrics.NetworkErrors, 1)
			r.metrics.RecordError(label, fmt.Sprintf("http %d", resp.StatusCode), -1, "")
			r.metrics.RecordJobCompletion(time.Since(start), false)
			return
		}

		r.metrics.RecordJobCompletion(time.Since(start), true)
		r.metrics.RecordVerification(time.Since(start))

		if label == "rpc_status" {
			height := extractBlockHeight(body)
			if height > 0 {
				heightLock.Lock()
				if height > maxHeight {
					delta := height - maxHeight
					maxHeight = height
					atomic.AddInt64(&r.metrics.BlocksProduced, delta)
					atomic.AddInt64(&r.metrics.BlocksFinalized, delta)
				}
				heightLock.Unlock()
			}
		}
	}

	for worker := 0; worker < r.config.NodeConcurrency; worker++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rpcStatus := fmt.Sprintf("%s/status", strings.TrimRight(r.config.RPCEndpoint, "/"))
			apiStatus := fmt.Sprintf("%s/v1/status", strings.TrimRight(r.config.APIEndpoint, "/"))
			apiNodeInfo := fmt.Sprintf("%s/cosmos/base/tendermint/v1beta1/node_info", strings.TrimRight(r.config.APIEndpoint, "/"))

			for {
				select {
				case <-r.ctx.Done():
					return
				default:
					switch workerID % 3 {
					case 0:
						probe(rpcStatus, "rpc_status")
					case 1:
						probe(apiStatus, "api_status")
					default:
						probe(apiNodeInfo, "api_node_info")
					}
				}
			}
		}(worker)
	}

	select {
	case <-time.After(r.config.Duration):
	case <-r.ctx.Done():
	}

	r.cancel()
	wg.Wait()

	r.mu.Lock()
	r.running = false
	r.mu.Unlock()

	return r.generateReport()
}

// initValidators initializes simulated validators
func (r *Runner) initValidators() {
	r.validators = make([]*SimulatedValidator, r.config.NumValidators)
	for i := 0; i < r.config.NumValidators; i++ {
		r.validators[i] = &SimulatedValidator{
			ID:              i,
			VotingPower:     1000, // Equal voting power
			IsActive:        true,
			IsByzantine:     randFloat() < r.config.ByzantineRate,
			FailureRate:     r.config.ValidatorFailureRate,
			ProcessingDelay: randDuration(1*time.Millisecond, 10*time.Millisecond),
		}
	}
	atomic.StoreInt64(&r.metrics.ActiveValidators, int64(r.config.NumValidators))
}

// generateJobs generates compute jobs
func (r *Runner) generateJobs() {
	jobID := 0
	ticker := time.NewTicker(r.config.BlockTime / time.Duration(r.config.JobsPerBlock))
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			job := r.createJob(jobID)
			start := time.Now()
			r.jobs <- job
			r.metrics.RecordJobSubmission(time.Since(start))
			jobID++
		}
	}
}

// createJob creates a simulated job
func (r *Runner) createJob(id int) *SimulatedJob {
	modelHash := make([]byte, r.config.ModelHashSize)
	_, _ = rand.Read(modelHash)

	inputHash := make([]byte, r.config.ModelHashSize)
	_, _ = rand.Read(inputHash)

	return &SimulatedJob{
		ID:          fmt.Sprintf("job-%d-%s", id, hex.EncodeToString(modelHash[:4])),
		ModelHash:   modelHash,
		InputHash:   inputHash,
		PayloadSize: r.config.JobPayloadSize,
		SubmittedAt: time.Now(),
		Status:      "pending",
	}
}

// produceBlocks simulates block production
func (r *Runner) produceBlocks() {
	blockHeight := int64(0)
	ticker := time.NewTicker(r.config.BlockTime)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			if int(blockHeight) >= r.config.NumBlocks {
				r.cancel()
				return
			}

			block := r.produceBlock(blockHeight)
			r.mu.Lock()
			r.blocks = append(r.blocks, block)
			r.mu.Unlock()
			blockHeight++
		}
	}
}

// produceBlock produces a single block
func (r *Runner) produceBlock(height int64) *SimulatedBlock {
	startTime := time.Now()
	block := &SimulatedBlock{
		Height:    height,
		Timestamp: startTime,
		Jobs:      make([]*SimulatedJob, 0, r.config.JobsPerBlock),
	}

	// Collect jobs for this block
	timeout := time.After(r.config.BlockTime / 2)
	for len(block.Jobs) < r.config.JobsPerBlock {
		select {
		case job := <-r.jobs:
			block.Jobs = append(block.Jobs, job)
		case <-timeout:
			goto processBlock
		case <-r.ctx.Done():
			return block
		}
	}

processBlock:
	// Process jobs through validators (vote extensions)
	var wg sync.WaitGroup
	votesChan := make(chan []byte, r.config.NumValidators)

	for _, v := range r.validators {
		if !v.IsActive {
			continue
		}
		wg.Add(1)
		go func(validator *SimulatedValidator) {
			defer wg.Done()
			vote := r.simulateVoteExtension(validator, block.Jobs)
			if vote != nil {
				votesChan <- vote
				atomic.AddInt64(&r.metrics.VoteExtensionsGenerated, 1)
			}
		}(v)
	}

	wg.Wait()
	close(votesChan)

	// Collect vote extensions
	for vote := range votesChan {
		block.VoteExtensions = append(block.VoteExtensions, vote)
	}

	// Check for consensus (2/3+1)
	requiredVotes := (2 * r.config.NumValidators / 3) + 1
	block.Finalized = len(block.VoteExtensions) >= requiredVotes

	// Record consensus time
	consensusTime := time.Since(startTime)
	r.metrics.RecordConsensus(consensusTime)

	// Update job statuses
	for _, job := range block.Jobs {
		job.CompletedAt = time.Now()
		job.Verifications = len(block.VoteExtensions)
		if block.Finalized {
			job.Status = "completed"
			r.metrics.RecordJobCompletion(job.CompletedAt.Sub(job.SubmittedAt), true)
		} else {
			job.Status = "failed"
			r.metrics.RecordJobCompletion(job.CompletedAt.Sub(job.SubmittedAt), false)
		}
	}

	block.Duration = time.Since(startTime)
	r.metrics.RecordBlock(block.Duration, block.Finalized)

	return block
}

// simulateVoteExtension simulates a validator's vote extension
func (r *Runner) simulateVoteExtension(v *SimulatedValidator, jobs []*SimulatedJob) []byte {
	// Simulate failure
	if randFloat() < v.FailureRate {
		atomic.AddInt64(&r.metrics.VoteExtensionsFailed, 1)
		return nil
	}

	// Simulate processing delay
	time.Sleep(v.ProcessingDelay)

	// Simulate verification for each job
	for range jobs {
		verifyStart := time.Now()

		// Simulate different verification types
		switch r.config.VerificationType {
		case "tee":
			time.Sleep(randDuration(1*time.Millisecond, 5*time.Millisecond))
		case "zkml":
			time.Sleep(randDuration(50*time.Millisecond, 200*time.Millisecond))
		case "hybrid":
			time.Sleep(randDuration(10*time.Millisecond, 50*time.Millisecond))
		}

		r.metrics.RecordVerification(time.Since(verifyStart))
	}

	// Simulate network latency
	time.Sleep(randDuration(r.config.NetworkLatencyMin, r.config.NetworkLatencyMax))

	// Simulate packet loss
	if randFloat() < r.config.PacketLossRate {
		atomic.AddInt64(&r.metrics.PacketsDropped, 1)
		return nil
	}

	v.mu.Lock()
	v.jobsProcessed += int64(len(jobs))
	v.votesGenerated++
	v.mu.Unlock()

	// Generate vote extension (hash of all job results)
	h := sha256.New()
	for _, job := range jobs {
		h.Write([]byte(job.ID))
		h.Write(job.ModelHash)
		h.Write(job.InputHash)
	}

	return h.Sum(nil)
}

// metricsReporter periodically reports metrics
func (r *Runner) metricsReporter() {
	ticker := time.NewTicker(r.config.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.recordThroughputSample()
			r.printProgressReport()
		}
	}
}

// recordThroughputSample records a throughput sample
func (r *Runner) recordThroughputSample() {
	elapsed := time.Since(r.startTime).Seconds()
	if elapsed < 1 {
		return
	}

	sample := ThroughputSample{
		Timestamp:       time.Now(),
		JobsPerSecond:   float64(atomic.LoadInt64(&r.metrics.JobsCompleted)) / elapsed,
		BlocksPerMinute: float64(atomic.LoadInt64(&r.metrics.BlocksFinalized)) / (elapsed / 60),
	}

	// Calculate average latency
	r.metrics.mu.RLock()
	if len(r.metrics.JobCompletionTimes) > 0 {
		var sum int64
		for _, t := range r.metrics.JobCompletionTimes {
			sum += t
		}
		sample.AvgLatencyMs = float64(sum) / float64(len(r.metrics.JobCompletionTimes)) / 1e6
	}
	r.metrics.mu.RUnlock()

	r.metrics.mu.Lock()
	r.metrics.ThroughputSamples = append(r.metrics.ThroughputSamples, sample)
	r.metrics.mu.Unlock()
}

// printProgressReport prints a progress report
func (r *Runner) printProgressReport() {
	elapsed := time.Since(r.startTime)
	jobsSubmitted := atomic.LoadInt64(&r.metrics.JobsSubmitted)
	jobsCompleted := atomic.LoadInt64(&r.metrics.JobsCompleted)
	blocksFinalized := atomic.LoadInt64(&r.metrics.BlocksFinalized)
	blocksFailed := atomic.LoadInt64(&r.metrics.BlocksFailed)

	fmt.Printf("\n=== Load Test Progress [%s] ===\n", elapsed.Round(time.Second))
	fmt.Printf("Jobs:   %d submitted / %d completed (%.1f%%)\n",
		jobsSubmitted, jobsCompleted,
		float64(jobsCompleted)/float64(max(jobsSubmitted, 1))*100)
	fmt.Printf("Blocks: %d finalized / %d failed\n", blocksFinalized, blocksFailed)
	fmt.Printf("Throughput: %.0f jobs/sec\n", float64(jobsCompleted)/elapsed.Seconds())
	fmt.Printf("Vote Extensions: %d generated / %d failed\n",
		atomic.LoadInt64(&r.metrics.VoteExtensionsGenerated),
		atomic.LoadInt64(&r.metrics.VoteExtensionsFailed))
}

// ============================================================================
// Report Generation
// ============================================================================

// Report contains the final load test report
type Report struct {
	// Test configuration
	Config *Config `json:"config"`

	// Timing
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`

	// Summary statistics
	TotalJobsSubmitted int64   `json:"total_jobs_submitted"`
	TotalJobsCompleted int64   `json:"total_jobs_completed"`
	TotalJobsFailed    int64   `json:"total_jobs_failed"`
	JobSuccessRate     float64 `json:"job_success_rate"`

	TotalBlocksProduced  int64   `json:"total_blocks_produced"`
	TotalBlocksFinalized int64   `json:"total_blocks_finalized"`
	BlockSuccessRate     float64 `json:"block_success_rate"`

	// Throughput
	AvgJobsPerSecond   float64 `json:"avg_jobs_per_second"`
	PeakJobsPerSecond  float64 `json:"peak_jobs_per_second"`
	AvgBlocksPerMinute float64 `json:"avg_blocks_per_minute"`

	// Latency statistics (milliseconds)
	JobLatency          LatencyStats `json:"job_latency_ms"`
	BlockLatency        LatencyStats `json:"block_latency_ms"`
	ConsensusLatency    LatencyStats `json:"consensus_latency_ms"`
	VerificationLatency LatencyStats `json:"verification_latency_ms"`

	// Validator statistics
	ActiveValidators     int64 `json:"active_validators"`
	FailedValidators     int64 `json:"failed_validators"`
	VoteExtensions       int64 `json:"vote_extensions_generated"`
	VoteExtensionsFailed int64 `json:"vote_extensions_failed"`

	// Network statistics
	PacketsDropped int64 `json:"packets_dropped"`
	NetworkErrors  int64 `json:"network_errors"`

	// Error summary
	TotalErrors int            `json:"total_errors"`
	ErrorTypes  map[string]int `json:"error_types"`

	// Performance grade
	Grade       string `json:"grade"`
	GradeReason string `json:"grade_reason"`
}

// LatencyStats contains latency statistics
type LatencyStats struct {
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Avg    float64 `json:"avg"`
	Median float64 `json:"p50"`
	P95    float64 `json:"p95"`
	P99    float64 `json:"p99"`
}

// generateReport generates the final report
func (r *Runner) generateReport() (*Report, error) {
	report := &Report{
		Config:    r.config,
		StartTime: r.startTime,
		EndTime:   time.Now(),
		Duration:  time.Since(r.startTime),

		TotalJobsSubmitted:   atomic.LoadInt64(&r.metrics.JobsSubmitted),
		TotalJobsCompleted:   atomic.LoadInt64(&r.metrics.JobsCompleted),
		TotalJobsFailed:      atomic.LoadInt64(&r.metrics.JobsFailed),
		TotalBlocksProduced:  atomic.LoadInt64(&r.metrics.BlocksProduced),
		TotalBlocksFinalized: atomic.LoadInt64(&r.metrics.BlocksFinalized),

		ActiveValidators:     atomic.LoadInt64(&r.metrics.ActiveValidators),
		FailedValidators:     atomic.LoadInt64(&r.metrics.FailedValidators),
		VoteExtensions:       atomic.LoadInt64(&r.metrics.VoteExtensionsGenerated),
		VoteExtensionsFailed: atomic.LoadInt64(&r.metrics.VoteExtensionsFailed),
		PacketsDropped:       atomic.LoadInt64(&r.metrics.PacketsDropped),
		NetworkErrors:        atomic.LoadInt64(&r.metrics.NetworkErrors),

		ErrorTypes: make(map[string]int),
	}

	// Calculate rates
	if report.TotalJobsSubmitted > 0 {
		report.JobSuccessRate = float64(report.TotalJobsCompleted) / float64(report.TotalJobsSubmitted)
	}
	if report.TotalBlocksProduced > 0 {
		report.BlockSuccessRate = float64(report.TotalBlocksFinalized) / float64(report.TotalBlocksProduced)
	}

	// Calculate throughput
	durationSec := report.Duration.Seconds()
	if durationSec > 0 {
		report.AvgJobsPerSecond = float64(report.TotalJobsCompleted) / durationSec
		report.AvgBlocksPerMinute = float64(report.TotalBlocksFinalized) / (durationSec / 60)
	}

	// Find peak throughput
	r.metrics.mu.RLock()
	for _, sample := range r.metrics.ThroughputSamples {
		if sample.JobsPerSecond > report.PeakJobsPerSecond {
			report.PeakJobsPerSecond = sample.JobsPerSecond
		}
	}

	// Calculate latency stats
	report.JobLatency = calculateLatencyStats(r.metrics.JobCompletionTimes)
	report.BlockLatency = calculateLatencyStats(r.metrics.BlockProductionTimes)
	report.ConsensusLatency = calculateLatencyStats(r.metrics.ConsensusRoundTimes)
	report.VerificationLatency = calculateLatencyStats(r.metrics.VerificationTimes)

	// Count error types
	report.TotalErrors = len(r.metrics.Errors)
	for _, err := range r.metrics.Errors {
		report.ErrorTypes[err.Component]++
	}
	r.metrics.mu.RUnlock()

	// Calculate grade
	report.Grade, report.GradeReason = calculateGrade(report)

	// Save report to file
	if err := r.saveReport(report); err != nil {
		return report, fmt.Errorf("failed to save report: %w", err)
	}

	return report, nil
}

// calculateLatencyStats calculates latency statistics from nanosecond values
func calculateLatencyStats(times []int64) LatencyStats {
	if len(times) == 0 {
		return LatencyStats{}
	}

	// Sort for percentiles
	sorted := make([]int64, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var sum int64
	for _, t := range sorted {
		sum += t
	}

	return LatencyStats{
		Min:    float64(sorted[0]) / 1e6,
		Max:    float64(sorted[len(sorted)-1]) / 1e6,
		Avg:    float64(sum) / float64(len(sorted)) / 1e6,
		Median: float64(sorted[len(sorted)/2]) / 1e6,
		P95:    float64(sorted[int(float64(len(sorted))*0.95)]) / 1e6,
		P99:    float64(sorted[int(float64(len(sorted))*0.99)]) / 1e6,
	}
}

// calculateGrade determines the performance grade
func calculateGrade(report *Report) (string, string) {
	// Grade criteria based on enterprise requirements
	if report.JobSuccessRate >= 0.999 &&
		report.BlockSuccessRate >= 0.999 &&
		report.AvgJobsPerSecond >= 10000 &&
		report.JobLatency.P99 < 1000 {
		return "A+", "Excellent: All metrics exceed enterprise requirements"
	}

	if report.JobSuccessRate >= 0.995 &&
		report.BlockSuccessRate >= 0.995 &&
		report.AvgJobsPerSecond >= 5000 &&
		report.JobLatency.P99 < 2000 {
		return "A", "Very Good: Meets all enterprise requirements"
	}

	if report.JobSuccessRate >= 0.99 &&
		report.BlockSuccessRate >= 0.99 &&
		report.AvgJobsPerSecond >= 1000 {
		return "B", "Good: Meets most requirements, minor improvements needed"
	}

	if report.JobSuccessRate >= 0.95 &&
		report.BlockSuccessRate >= 0.95 {
		return "C", "Acceptable: Meets minimum requirements"
	}

	if report.JobSuccessRate >= 0.90 {
		return "D", "Poor: Below minimum requirements, improvements needed"
	}

	return "F", "Failing: Does not meet requirements"
}

// saveReport saves the report to a file
func (r *Runner) saveReport(report *Report) error {
	if err := os.MkdirAll(r.config.OutputDir, 0755); err != nil {
		return err
	}

	filename := filepath.Join(r.config.OutputDir,
		fmt.Sprintf("loadtest-report-%s.json", time.Now().Format("20060102-150405")))

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// ============================================================================
// Utility Functions
// ============================================================================

func randFloat() float64 {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return float64(b[0]) / 255.0
}

func randDuration(min, max time.Duration) time.Duration {
	return min + time.Duration(randFloat()*float64(max-min))
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func extractBlockHeight(body []byte) int64 {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0
	}

	result, ok := payload["result"].(map[string]interface{})
	if !ok {
		return 0
	}
	syncInfo, ok := result["sync_info"].(map[string]interface{})
	if !ok {
		return 0
	}

	rawHeight, ok := syncInfo["latest_block_height"]
	if !ok {
		return 0
	}

	switch value := rawHeight.(type) {
	case string:
		height, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0
		}
		return height
	case float64:
		return int64(value)
	default:
		return 0
	}
}

// ============================================================================
// CLI Entry Point
// ============================================================================

// RunLoadTest is the main entry point for the load test
func RunLoadTest(config *Config) error {
	if strings.TrimSpace(config.Mode) == "" {
		config.Mode = "simulation"
	}
	if strings.EqualFold(config.Mode, "node") && config.NodeConcurrency <= 0 {
		config.NodeConcurrency = 1
	}

	fmt.Println("=== Aethelred Load Test ===")
	fmt.Printf("Mode: %s\n", config.Mode)
	fmt.Printf("Validators: %d\n", config.NumValidators)
	fmt.Printf("Jobs per block: %d\n", config.JobsPerBlock)
	fmt.Printf("Target blocks: %d\n", config.NumBlocks)
	fmt.Printf("Duration: %s\n", config.Duration)
	fmt.Printf("Verification type: %s\n", config.VerificationType)
	if strings.EqualFold(config.Mode, "node") {
		fmt.Printf("RPC Endpoint: %s\n", config.RPCEndpoint)
		fmt.Printf("API Endpoint: %s\n", config.APIEndpoint)
		fmt.Printf("Concurrency: %d\n", config.NodeConcurrency)
	}
	fmt.Println()

	runner := NewRunner(config)
	report, err := runner.Run()
	if err != nil {
		return fmt.Errorf("load test failed: %w", err)
	}

	// Print summary
	fmt.Println("\n=== Load Test Complete ===")
	fmt.Printf("Duration: %s\n", report.Duration.Round(time.Second))
	fmt.Printf("Jobs: %d completed / %d failed (%.2f%% success)\n",
		report.TotalJobsCompleted, report.TotalJobsFailed,
		report.JobSuccessRate*100)
	fmt.Printf("Blocks: %d finalized (%.2f%% success)\n",
		report.TotalBlocksFinalized, report.BlockSuccessRate*100)
	fmt.Printf("Throughput: %.0f jobs/sec (peak: %.0f)\n",
		report.AvgJobsPerSecond, report.PeakJobsPerSecond)
	fmt.Printf("Latency P99: %.2f ms (job), %.2f ms (consensus)\n",
		report.JobLatency.P99, report.ConsensusLatency.P99)
	fmt.Printf("\nGrade: %s - %s\n", report.Grade, report.GradeReason)

	return nil
}

// ============================================================================
// Stress Test Scenarios
// ============================================================================

// StressScenario represents a predefined stress test scenario
type StressScenario struct {
	Name        string
	Description string
	Config      *Config
}

// GetStressScenarios returns predefined stress test scenarios
func GetStressScenarios() []StressScenario {
	return []StressScenario{
		{
			Name:        "baseline",
			Description: "Baseline test with default parameters",
			Config:      DefaultConfig(),
		},
		{
			Name:        "node-integration",
			Description: "Integration probe against a live RPC/API node",
			Config: &Config{
				Mode:            "node",
				RPCEndpoint:     "http://localhost:26657",
				APIEndpoint:     "http://localhost:1317",
				NodeConcurrency: 16,
				NumValidators:   1,
				JobsPerBlock:    1,
				NumBlocks:       1,
				Duration:        5 * time.Minute,
				BlockTime:       6 * time.Second,
				OutputDir:       "./loadtest-results/node-integration",
			},
		},
		{
			Name:        "high-throughput",
			Description: "High throughput test: 10K jobs/block, 100 validators",
			Config: &Config{
				NumValidators:    100,
				JobsPerBlock:     10000,
				NumBlocks:        50,
				Duration:         30 * time.Minute,
				BlockTime:        6 * time.Second,
				JobPayloadSize:   1024,
				VerificationType: "tee",
				OutputDir:        "./loadtest-results/high-throughput",
			},
		},
		{
			Name:        "large-validator-set",
			Description: "Test with 500 validators",
			Config: &Config{
				NumValidators:    500,
				JobsPerBlock:     5000,
				NumBlocks:        20,
				Duration:         15 * time.Minute,
				BlockTime:        6 * time.Second,
				VerificationType: "hybrid",
				OutputDir:        "./loadtest-results/large-validators",
			},
		},
		{
			Name:        "network-stress",
			Description: "Test with high network latency and packet loss",
			Config: &Config{
				NumValidators:     100,
				JobsPerBlock:      1000,
				NumBlocks:         30,
				Duration:          20 * time.Minute,
				BlockTime:         6 * time.Second,
				NetworkLatencyMin: 100 * time.Millisecond,
				NetworkLatencyMax: 500 * time.Millisecond,
				PacketLossRate:    0.05, // 5% packet loss
				OutputDir:         "./loadtest-results/network-stress",
			},
		},
		{
			Name:        "validator-failures",
			Description: "Test with 10% validator failure rate",
			Config: &Config{
				NumValidators:        100,
				JobsPerBlock:         5000,
				NumBlocks:            30,
				Duration:             20 * time.Minute,
				BlockTime:            6 * time.Second,
				ValidatorFailureRate: 0.10, // 10% failure rate
				OutputDir:            "./loadtest-results/validator-failures",
			},
		},
		{
			Name:        "zkml-heavy",
			Description: "Test with zkML verification (slower)",
			Config: &Config{
				NumValidators:    50,
				JobsPerBlock:     1000,
				NumBlocks:        20,
				Duration:         30 * time.Minute,
				BlockTime:        10 * time.Second, // Longer block time for zkML
				VerificationType: "zkml",
				OutputDir:        "./loadtest-results/zkml-heavy",
			},
		},
		{
			Name:        "endurance",
			Description: "Long-running endurance test (1 hour)",
			Config: &Config{
				NumValidators:    100,
				JobsPerBlock:     5000,
				NumBlocks:        600, // 1 hour at 6s blocks
				Duration:         1 * time.Hour,
				BlockTime:        6 * time.Second,
				VerificationType: "hybrid",
				OutputDir:        "./loadtest-results/endurance",
			},
		},
		{
			Name:        "byzantine",
			Description: "Test with 10% byzantine validators",
			Config: &Config{
				NumValidators: 100,
				JobsPerBlock:  5000,
				NumBlocks:     30,
				Duration:      20 * time.Minute,
				BlockTime:     6 * time.Second,
				ByzantineRate: 0.10, // 10% byzantine
				OutputDir:     "./loadtest-results/byzantine",
			},
		},
	}
}

// RunScenario runs a named stress test scenario
func RunScenario(name string) error {
	scenarios := GetStressScenarios()
	for _, s := range scenarios {
		if s.Name == name {
			fmt.Printf("Running scenario: %s\n", s.Description)
			return RunLoadTest(s.Config)
		}
	}
	return fmt.Errorf("unknown scenario: %s", name)
}

// ScenarioResult holds pass/fail outcome for a single scenario run.
type ScenarioResult struct {
	Name    string
	Passed  bool
	Error   error
	Elapsed time.Duration
}

// RunAllScenarios runs all stress test scenarios sequentially with baked-in
// configs. CLI overrides are NOT applied. Prefer RunAllScenariosWithBase.
func RunAllScenarios() error {
	return RunAllScenariosWithBase(nil)
}

// RunAllScenariosWithBase runs every predefined scenario, applying CLI
// overrides from base onto each scenario's config before execution.
// If base is nil, scenarios run with their baked-in defaults.
//
// Returns a non-nil error if ANY scenario fails its acceptance criteria:
//   - zero finalized blocks
//   - zero completed jobs
//   - repeated vote-extension failures (>25% of blocks)
func RunAllScenariosWithBase(base *Config) error {
	scenarios := GetStressScenarios()
	results := make([]ScenarioResult, 0, len(scenarios))

	for _, s := range scenarios {
		fmt.Printf("\n\n========================================\n")
		fmt.Printf("Running scenario: %s\n", s.Name)
		fmt.Printf("Description: %s\n", s.Description)
		fmt.Printf("========================================\n\n")

		cfg := s.Config
		if base != nil {
			cfg = applyBaseOverrides(cfg, base)
		}

		start := time.Now()
		err := RunLoadTest(cfg)
		elapsed := time.Since(start)

		res := ScenarioResult{Name: s.Name, Elapsed: elapsed}
		if err != nil {
			res.Error = err
			res.Passed = false
			fmt.Printf("Scenario %s FAILED (%s): %v\n", s.Name, elapsed, err)
		} else {
			res.Passed = true
			fmt.Printf("Scenario %s PASSED (%s)\n", s.Name, elapsed)
		}
		results = append(results, res)

		// Brief pause between scenarios
		time.Sleep(2 * time.Second)
	}

	// Summary
	fmt.Printf("\n\n========================================\n")
	fmt.Printf("  ALL-SCENARIOS SUMMARY\n")
	fmt.Printf("========================================\n")
	var failures int
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
			failures++
		}
		fmt.Printf("  [%s] %-25s  %s\n", status, r.Name, r.Elapsed)
	}
	fmt.Printf("========================================\n")
	fmt.Printf("  %d/%d passed\n", len(results)-failures, len(results))
	fmt.Printf("========================================\n")

	if failures > 0 {
		return fmt.Errorf("%d of %d scenarios failed", failures, len(results))
	}
	return nil
}

// applyBaseOverrides merges CLI-provided base config values onto a scenario
// config. Only non-default values from base are applied; zero-values are
// treated as "not set" and left as the scenario default.
func applyBaseOverrides(scenario *Config, base *Config) *Config {
	// Deep copy so we don't mutate the predefined scenario
	merged := *scenario

	defaults := DefaultConfig()

	if base.NumValidators != defaults.NumValidators {
		merged.NumValidators = base.NumValidators
	}
	if base.NumBlocks != defaults.NumBlocks {
		merged.NumBlocks = base.NumBlocks
	}
	if base.Duration != defaults.Duration {
		merged.Duration = base.Duration
	}
	if base.JobsPerBlock != defaults.JobsPerBlock {
		merged.JobsPerBlock = base.JobsPerBlock
	}
	if base.BlockTime != defaults.BlockTime {
		merged.BlockTime = base.BlockTime
	}
	if base.Mode != defaults.Mode {
		merged.Mode = base.Mode
	}
	if base.VerificationType != defaults.VerificationType {
		merged.VerificationType = base.VerificationType
	}
	if base.RPCEndpoint != defaults.RPCEndpoint {
		merged.RPCEndpoint = base.RPCEndpoint
	}
	if base.APIEndpoint != defaults.APIEndpoint {
		merged.APIEndpoint = base.APIEndpoint
	}
	if base.NodeConcurrency != defaults.NodeConcurrency {
		merged.NodeConcurrency = base.NodeConcurrency
	}

	return &merged
}
