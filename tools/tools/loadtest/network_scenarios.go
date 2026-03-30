// Package loadtest provides enterprise-grade load testing infrastructure
// for Aethelred blockchain's Proof-of-Useful-Work consensus.
//
// This file contains advanced network simulation scenarios:
//   - Network partition simulation
//   - Eclipse attack simulation
//   - Split-brain scenarios
//   - Byzantine fault injection

package loadtest

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mrand "math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// scenarioSeed returns a deterministic seed from the AETHELRED_SCENARIO_SEED
// environment variable, or a random seed if unset.  Every scenario runner
// creates its own *mrand.Rand from this seed so results are reproducible.
func scenarioSeed() int64 {
	if v := os.Getenv("AETHELRED_SCENARIO_SEED"); v != "" {
		if seed, err := strconv.ParseInt(v, 10, 64); err == nil {
			return seed
		}
	}
	// Fall back to crypto/rand for non-deterministic runs.
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return int64(binary.LittleEndian.Uint64(buf[:]))
}

// ============================================================================
// Network Partition Simulation
// ============================================================================

// PartitionConfig defines network partition parameters
type PartitionConfig struct {
	// Number of partitions to create
	NumPartitions int

	// Distribution of validators across partitions (percentages)
	// e.g., []float64{0.4, 0.4, 0.2} creates 3 partitions with 40%, 40%, 20%
	PartitionDistribution []float64

	// Duration of partition in blocks
	PartitionDurationBlocks int64

	// Probability of partition healing per block
	HealingProbability float64

	// Whether partitions can communicate at reduced bandwidth
	PartialConnectivity bool

	// Bandwidth reduction factor for partial connectivity (0-1)
	BandwidthReduction float64

	// Message delay between partitions (milliseconds)
	CrossPartitionDelayMs int64

	// Probability of message loss between partitions
	CrossPartitionLossRate float64
}

// DefaultPartitionConfig returns default partition configuration
func DefaultPartitionConfig() *PartitionConfig {
	return &PartitionConfig{
		NumPartitions:           2,
		PartitionDistribution:   []float64{0.5, 0.5}, // 50/50 split
		PartitionDurationBlocks: 20,
		HealingProbability:      0.1, // 10% chance per block
		PartialConnectivity:     false,
		BandwidthReduction:      0.1,
		CrossPartitionDelayMs:   5000, // 5 seconds
		CrossPartitionLossRate:  0.5,  // 50% message loss
	}
}

// NetworkPartition represents a network partition state
type NetworkPartition struct {
	ID           int
	Validators   []*SimulatedValidator
	Leader       *SimulatedValidator
	IsIsolated   bool
	BlockHeight  int64
	VotingPower  int64
	CanPropose   bool // Has 2/3+ voting power
}

// PartitionSimulator manages network partition simulation
type PartitionSimulator struct {
	config     *PartitionConfig
	partitions []*NetworkPartition
	validators []*SimulatedValidator
	metrics    *PartitionMetrics

	// rng is a per-simulator deterministic RNG seeded from scenarioSeed().
	// All random decisions (shuffle, healing, message loss) use this instead
	// of the global math/rand or crypto/rand, making runs reproducible when
	// AETHELRED_SCENARIO_SEED is set.
	rng *mrand.Rand

	mu         sync.RWMutex
	isActive   bool
	startBlock int64
	healedAt   int64
}

// PartitionMetrics tracks partition-related metrics
type PartitionMetrics struct {
	mu sync.RWMutex

	// Partition events
	PartitionEvents    int64
	HealingEvents      int64
	TotalPartitionTime int64 // in blocks

	// Block production during partition
	BlocksInPartition  map[int]int64 // partition ID -> blocks produced
	OrphanedBlocks     int64
	ConflictingBlocks  int64

	// Consensus metrics
	ConsensusFailures  int64
	ConsensusRecovered int64
	SplitBrainEvents   int64

	// Safety-preserving halts: partitions that correctly refused to propose
	// because they lacked supermajority. This is desired BFT behavior, not a failure.
	SafetyHalts        int64

	// Message metrics
	CrossPartitionMsgs      int64
	DroppedCrossPartMsgs    int64
	DelayedCrossPartMsgs    int64
}

// NewPartitionSimulator creates a new partition simulator
func NewPartitionSimulator(config *PartitionConfig, validators []*SimulatedValidator) *PartitionSimulator {
	seed := scenarioSeed()
	return &PartitionSimulator{
		config:     config,
		validators: validators,
		partitions: make([]*NetworkPartition, 0),
		rng:        mrand.New(mrand.NewSource(seed)),
		metrics: &PartitionMetrics{
			BlocksInPartition: make(map[int]int64),
		},
	}
}

// CreatePartition creates a network partition
func (ps *PartitionSimulator) CreatePartition(currentBlock int64) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if ps.isActive {
		return fmt.Errorf("partition already active")
	}

	// Validate distribution
	if len(ps.config.PartitionDistribution) != ps.config.NumPartitions {
		return fmt.Errorf("partition distribution mismatch: got %d, expected %d",
			len(ps.config.PartitionDistribution), ps.config.NumPartitions)
	}

	var total float64
	for _, p := range ps.config.PartitionDistribution {
		total += p
	}
	if math.Abs(total-1.0) > 0.001 {
		return fmt.Errorf("partition distribution must sum to 1.0, got %.2f", total)
	}

	// Shuffle validators for deterministic-random assignment
	shuffled := make([]*SimulatedValidator, len(ps.validators))
	copy(shuffled, ps.validators)
	ps.rng.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// Create partitions
	ps.partitions = make([]*NetworkPartition, ps.config.NumPartitions)
	idx := 0

	for i := 0; i < ps.config.NumPartitions; i++ {
		count := int(float64(len(shuffled)) * ps.config.PartitionDistribution[i])
		if i == ps.config.NumPartitions-1 {
			// Last partition gets remaining validators
			count = len(shuffled) - idx
		}

		partition := &NetworkPartition{
			ID:          i,
			Validators:  shuffled[idx : idx+count],
			IsIsolated:  true,
			BlockHeight: currentBlock,
		}

		// Calculate voting power
		for _, v := range partition.Validators {
			partition.VotingPower += v.VotingPower
		}

		// Check if partition can achieve consensus
		totalVotingPower := int64(0)
		for _, v := range ps.validators {
			totalVotingPower += v.VotingPower
		}
		partition.CanPropose = partition.VotingPower > (2*totalVotingPower)/3

		// Assign leader
		if len(partition.Validators) > 0 {
			partition.Leader = partition.Validators[0]
		}

		ps.partitions[i] = partition
		idx += count
	}

	ps.isActive = true
	ps.startBlock = currentBlock
	ps.healedAt = 0

	atomic.AddInt64(&ps.metrics.PartitionEvents, 1)

	return nil
}

// HealPartition heals the network partition
func (ps *PartitionSimulator) HealPartition(currentBlock int64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if !ps.isActive {
		return
	}

	ps.isActive = false
	ps.healedAt = currentBlock

	// Mark all partitions as not isolated
	for _, p := range ps.partitions {
		p.IsIsolated = false
	}

	atomic.AddInt64(&ps.metrics.HealingEvents, 1)
	atomic.AddInt64(&ps.metrics.TotalPartitionTime, currentBlock-ps.startBlock)
}

// CheckHealing checks if partition should heal naturally
func (ps *PartitionSimulator) CheckHealing(currentBlock int64) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if !ps.isActive {
		return false
	}

	// Check duration limit
	if currentBlock-ps.startBlock >= ps.config.PartitionDurationBlocks {
		return true
	}

	// Deterministic healing probability
	return ps.rng.Float64() < ps.config.HealingProbability
}

// IsPartitioned returns whether network is currently partitioned
func (ps *PartitionSimulator) IsPartitioned() bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.isActive
}

// GetPartitionForValidator returns which partition a validator belongs to
func (ps *PartitionSimulator) GetPartitionForValidator(validatorID int) int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.getPartitionForValidatorLocked(validatorID)
}

// getPartitionForValidatorLocked is the lock-free internal implementation.
// Caller MUST hold ps.mu (read or write).
func (ps *PartitionSimulator) getPartitionForValidatorLocked(validatorID int) int {
	if !ps.isActive {
		return -1 // No partition
	}

	for i, p := range ps.partitions {
		for _, v := range p.Validators {
			if v.ID == validatorID {
				return i
			}
		}
	}

	return -1
}

// CanCommunicate checks if two validators can communicate
func (ps *PartitionSimulator) CanCommunicate(validatorA, validatorB int) bool {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if !ps.isActive {
		return true
	}

	partitionA := ps.getPartitionForValidatorLocked(validatorA)
	partitionB := ps.getPartitionForValidatorLocked(validatorB)

	if partitionA == partitionB {
		return true // Same partition
	}

	if !ps.config.PartialConnectivity {
		return false // Complete isolation
	}

	// Check partial connectivity with loss rate
	atomic.AddInt64(&ps.metrics.CrossPartitionMsgs, 1)

	if ps.rng.Float64() < ps.config.CrossPartitionLossRate {
		atomic.AddInt64(&ps.metrics.DroppedCrossPartMsgs, 1)
		return false
	}

	atomic.AddInt64(&ps.metrics.DelayedCrossPartMsgs, 1)
	return true
}

// GetCommunicationDelay returns delay between validators
func (ps *PartitionSimulator) GetCommunicationDelay(validatorA, validatorB int) time.Duration {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if !ps.isActive {
		return 0
	}

	partitionA := ps.getPartitionForValidatorLocked(validatorA)
	partitionB := ps.getPartitionForValidatorLocked(validatorB)

	if partitionA == partitionB {
		return 0 // Same partition, no delay
	}

	if ps.config.PartialConnectivity {
		return time.Duration(ps.config.CrossPartitionDelayMs) * time.Millisecond
	}

	return 0 // Complete isolation, no communication at all
}

// SimulateBlockProduction simulates block production during partition
func (ps *PartitionSimulator) SimulateBlockProduction() []*SimulatedBlock {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if !ps.isActive {
		return nil
	}

	blocks := make([]*SimulatedBlock, 0)

	for _, partition := range ps.partitions {
		if !partition.CanPropose {
			// Partition correctly halts - this is desired BFT safety behavior.
			// A minority partition SHOULD NOT produce blocks to prevent split-brain.
			atomic.AddInt64(&ps.metrics.SafetyHalts, 1)
			continue
		}

		// Partition produces a block
		block := &SimulatedBlock{
			Height:     partition.BlockHeight + 1,
			Timestamp:  time.Now(),
			ProposerID: partition.Leader.ID,
			Finalized:  true,
			Jobs:       make([]*SimulatedJob, 0),
		}

		partition.BlockHeight++
		blocks = append(blocks, block)

		ps.metrics.mu.Lock()
		ps.metrics.BlocksInPartition[partition.ID]++
		ps.metrics.mu.Unlock()
	}

	// Check for conflicting blocks (split-brain)
	if len(blocks) > 1 {
		atomic.AddInt64(&ps.metrics.SplitBrainEvents, 1)
		atomic.AddInt64(&ps.metrics.ConflictingBlocks, int64(len(blocks)))
	}

	return blocks
}

// GetMetrics returns partition metrics
func (ps *PartitionSimulator) GetMetrics() *PartitionMetrics {
	return ps.metrics
}

// ============================================================================
// Eclipse Attack Simulation
// ============================================================================

// EclipseConfig defines eclipse attack parameters
type EclipseConfig struct {
	// Target validator IDs to eclipse
	TargetValidators []int

	// Number of malicious peers to surround target
	MaliciousPeers int

	// Percentage of honest connections to block (0-1)
	ConnectionBlockRate float64

	// Duration of eclipse in blocks
	EclipseDurationBlocks int64

	// Type of eclipse attack
	AttackType EclipseAttackType

	// Whether to feed false data to eclipsed validators
	FeedFalseData bool

	// Delay to add to legitimate messages (milliseconds)
	MessageDelayMs int64
}

// EclipseAttackType defines the type of eclipse attack
type EclipseAttackType string

const (
	// EclipseTotal completely isolates the target
	EclipseTotal EclipseAttackType = "total"

	// EclipsePartial allows some honest connections
	EclipsePartial EclipseAttackType = "partial"

	// EclipseDelayed delays but doesn't block messages
	EclipseDelayed EclipseAttackType = "delayed"

	// EclipsePoisoned feeds false data to the target
	EclipsePoisoned EclipseAttackType = "poisoned"
)

// DefaultEclipseConfig returns default eclipse configuration
func DefaultEclipseConfig() *EclipseConfig {
	return &EclipseConfig{
		TargetValidators:      []int{0}, // Target first validator
		MaliciousPeers:        50,
		ConnectionBlockRate:   0.9, // Block 90% of connections
		EclipseDurationBlocks: 30,
		AttackType:            EclipsePartial,
		FeedFalseData:         false,
		MessageDelayMs:        2000, // 2 seconds
	}
}

// EclipseSimulator manages eclipse attack simulation
type EclipseSimulator struct {
	config     *EclipseConfig
	validators []*SimulatedValidator
	metrics    *EclipseMetrics

	// rng provides deterministic randomness for eclipse decisions.
	rng *mrand.Rand

	mu              sync.RWMutex
	isActive        bool
	startBlock      int64
	eclipsedTargets map[int]bool
}

// EclipseMetrics tracks eclipse attack metrics
type EclipseMetrics struct {
	// Attack events
	EclipseEvents    int64
	EclipseEndEvents int64
	TotalEclipseTime int64 // in blocks

	// Message manipulation
	BlockedMessages   int64
	DelayedMessages   int64
	PoisonedMessages  int64
	AllowedMessages   int64

	// Target validator behavior
	TargetBlocksMissed      int64
	TargetIncorrectVotes    int64
	TargetSlashingEvents    int64

	// Attack effectiveness
	SuccessfulIsolations    int64
	PartialIsolations       int64
	FailedIsolations        int64

	// Network response
	PeersDetectedAttack     int64
	NetworkRecoveryTime     int64 // blocks to recover
}

// NewEclipseSimulator creates a new eclipse simulator
func NewEclipseSimulator(config *EclipseConfig, validators []*SimulatedValidator) *EclipseSimulator {
	seed := scenarioSeed()
	return &EclipseSimulator{
		config:          config,
		validators:      validators,
		rng:             mrand.New(mrand.NewSource(seed + 1)), // offset from partition seed
		metrics:         &EclipseMetrics{},
		eclipsedTargets: make(map[int]bool),
	}
}

// StartEclipse initiates an eclipse attack
func (es *EclipseSimulator) StartEclipse(currentBlock int64) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if es.isActive {
		return fmt.Errorf("eclipse attack already active")
	}

	// Validate targets exist
	for _, targetID := range es.config.TargetValidators {
		found := false
		for _, v := range es.validators {
			if v.ID == targetID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("target validator %d not found", targetID)
		}
	}

	// Mark targets as eclipsed
	for _, targetID := range es.config.TargetValidators {
		es.eclipsedTargets[targetID] = true
	}

	es.isActive = true
	es.startBlock = currentBlock

	atomic.AddInt64(&es.metrics.EclipseEvents, 1)

	return nil
}

// EndEclipse ends the eclipse attack
func (es *EclipseSimulator) EndEclipse(currentBlock int64) {
	es.mu.Lock()
	defer es.mu.Unlock()

	if !es.isActive {
		return
	}

	es.isActive = false
	es.eclipsedTargets = make(map[int]bool)

	atomic.AddInt64(&es.metrics.EclipseEndEvents, 1)
	atomic.AddInt64(&es.metrics.TotalEclipseTime, currentBlock-es.startBlock)
}

// ShouldEndEclipse checks if eclipse should end
func (es *EclipseSimulator) ShouldEndEclipse(currentBlock int64) bool {
	es.mu.RLock()
	defer es.mu.RUnlock()

	if !es.isActive {
		return false
	}

	return currentBlock-es.startBlock >= es.config.EclipseDurationBlocks
}

// IsEclipsed checks if a validator is eclipsed
func (es *EclipseSimulator) IsEclipsed(validatorID int) bool {
	es.mu.RLock()
	defer es.mu.RUnlock()

	return es.eclipsedTargets[validatorID]
}

// FilterMessage decides whether to allow/block/delay a message
func (es *EclipseSimulator) FilterMessage(fromValidator, toValidator int) MessageFilterResult {
	es.mu.RLock()
	defer es.mu.RUnlock()

	// Check if either endpoint is eclipsed
	fromEclipsed := es.eclipsedTargets[fromValidator]
	toEclipsed := es.eclipsedTargets[toValidator]

	if !fromEclipsed && !toEclipsed {
		return MessageFilterResult{Action: MessageAllow}
	}

	// Apply attack type-specific filtering
	switch es.config.AttackType {
	case EclipseTotal:
		atomic.AddInt64(&es.metrics.BlockedMessages, 1)
		return MessageFilterResult{Action: MessageBlock}

	case EclipsePartial:
		if es.rng.Float64() < es.config.ConnectionBlockRate {
			atomic.AddInt64(&es.metrics.BlockedMessages, 1)
			return MessageFilterResult{Action: MessageBlock}
		}
		atomic.AddInt64(&es.metrics.AllowedMessages, 1)
		return MessageFilterResult{Action: MessageAllow}

	case EclipseDelayed:
		atomic.AddInt64(&es.metrics.DelayedMessages, 1)
		return MessageFilterResult{
			Action: MessageDelay,
			Delay:  time.Duration(es.config.MessageDelayMs) * time.Millisecond,
		}

	case EclipsePoisoned:
		if es.config.FeedFalseData {
			atomic.AddInt64(&es.metrics.PoisonedMessages, 1)
			return MessageFilterResult{
				Action:     MessagePoison,
				PoisonData: es.generateFalseData(),
			}
		}
		return MessageFilterResult{Action: MessageAllow}

	default:
		return MessageFilterResult{Action: MessageAllow}
	}
}

// generateFalseData generates false blockchain data (deterministic when seeded).
func (es *EclipseSimulator) generateFalseData() []byte {
	data := make([]byte, 256)
	es.rng.Read(data)
	return data
}

// GetMetrics returns eclipse metrics
func (es *EclipseSimulator) GetMetrics() *EclipseMetrics {
	return es.metrics
}

// MessageFilterAction defines what to do with a message
type MessageFilterAction string

const (
	MessageAllow  MessageFilterAction = "allow"
	MessageBlock  MessageFilterAction = "block"
	MessageDelay  MessageFilterAction = "delay"
	MessagePoison MessageFilterAction = "poison"
)

// MessageFilterResult is the result of filtering a message
type MessageFilterResult struct {
	Action     MessageFilterAction
	Delay      time.Duration
	PoisonData []byte
}

// ============================================================================
// Combined Network Scenario Runner
// ============================================================================

// NetworkScenarioConfig defines a network attack scenario
type NetworkScenarioConfig struct {
	Name        string
	Description string

	// Partition configuration (nil to disable)
	PartitionConfig *PartitionConfig

	// Eclipse configuration (nil to disable)
	EclipseConfig *EclipseConfig

	// Timing
	StartAtBlock      int64
	DurationBlocks    int64

	// Success criteria
	ExpectedConsensusFailures int64
	MaxRecoveryBlocks         int64
}

// NetworkScenarioRunner runs network attack scenarios
type NetworkScenarioRunner struct {
	scenario     *NetworkScenarioConfig
	partition    *PartitionSimulator
	eclipse      *EclipseSimulator
	validators   []*SimulatedValidator
	baseRunner   *Runner

	results      *NetworkScenarioResult
}

// NetworkScenarioResult contains results from a network scenario
type NetworkScenarioResult struct {
	ScenarioName          string
	StartBlock            int64
	EndBlock              int64
	Duration              time.Duration

	// Partition results
	PartitionMetrics      *PartitionMetrics

	// Eclipse results
	EclipseMetrics        *EclipseMetrics

	// Overall results
	ConsensusFailures     int64
	RecoveryBlocks        int64
	SplitBrainEvents      int64
	DataLoss              int64

	// Grading
	AttackResilienceGrade string
	RecoveryGrade         string
	OverallGrade          string
	Recommendations       []string
}

// NewNetworkScenarioRunner creates a new scenario runner
func NewNetworkScenarioRunner(
	scenario *NetworkScenarioConfig,
	validators []*SimulatedValidator,
	baseRunner *Runner,
) *NetworkScenarioRunner {
	runner := &NetworkScenarioRunner{
		scenario:   scenario,
		validators: validators,
		baseRunner: baseRunner,
		results:    &NetworkScenarioResult{ScenarioName: scenario.Name},
	}

	if scenario.PartitionConfig != nil {
		runner.partition = NewPartitionSimulator(scenario.PartitionConfig, validators)
	}

	if scenario.EclipseConfig != nil {
		runner.eclipse = NewEclipseSimulator(scenario.EclipseConfig, validators)
	}

	return runner
}

// Run executes the network scenario
func (nsr *NetworkScenarioRunner) Run(ctx context.Context) (*NetworkScenarioResult, error) {
	nsr.results.StartBlock = nsr.scenario.StartAtBlock
	startTime := time.Now()

	currentBlock := nsr.scenario.StartAtBlock

	// Start attacks
	if nsr.partition != nil {
		if err := nsr.partition.CreatePartition(currentBlock); err != nil {
			return nil, fmt.Errorf("failed to create partition: %w", err)
		}
	}

	if nsr.eclipse != nil {
		if err := nsr.eclipse.StartEclipse(currentBlock); err != nil {
			return nil, fmt.Errorf("failed to start eclipse: %w", err)
		}
	}

	// Run scenario
	for currentBlock < nsr.scenario.StartAtBlock+nsr.scenario.DurationBlocks {
		select {
		case <-ctx.Done():
			return nsr.results, ctx.Err()
		default:
		}

		// Check for partition healing
		if nsr.partition != nil && nsr.partition.CheckHealing(currentBlock) {
			nsr.partition.HealPartition(currentBlock)
		}

		// Check for eclipse end
		if nsr.eclipse != nil && nsr.eclipse.ShouldEndEclipse(currentBlock) {
			nsr.eclipse.EndEclipse(currentBlock)
		}

		// Simulate block production
		if nsr.partition != nil && nsr.partition.IsPartitioned() {
			nsr.partition.SimulateBlockProduction()
		}

		currentBlock++
		time.Sleep(10 * time.Millisecond) // Fast simulation
	}

	// End attacks if still active
	if nsr.partition != nil && nsr.partition.IsPartitioned() {
		nsr.partition.HealPartition(currentBlock)
	}
	if nsr.eclipse != nil && nsr.eclipse.isActive {
		nsr.eclipse.EndEclipse(currentBlock)
	}

	// Collect results
	nsr.results.EndBlock = currentBlock
	nsr.results.Duration = time.Since(startTime)

	if nsr.partition != nil {
		nsr.results.PartitionMetrics = nsr.partition.GetMetrics()
		nsr.results.SplitBrainEvents = nsr.partition.metrics.SplitBrainEvents
		nsr.results.ConsensusFailures = nsr.partition.metrics.ConsensusFailures
	}

	if nsr.eclipse != nil {
		nsr.results.EclipseMetrics = nsr.eclipse.GetMetrics()
	}

	// Calculate grades
	nsr.calculateGrades()

	return nsr.results, nil
}

// calculateGrades determines grades for the scenario results.
//
// IMPORTANT: In BFT consensus, a minority partition halting block production
// is the CORRECT safety behavior, not a failure. Only actual split-brain
// events or unexpected liveness failures are penalized. Safety halts are
// tracked separately and credited as resilient behavior.
func (nsr *NetworkScenarioRunner) calculateGrades() {
	// True consensus failures = split-brain events + actual unexpected failures.
	// Safety halts (minority partitions correctly refusing to propose) are NOT failures.
	trueFailures := nsr.results.ConsensusFailures + nsr.results.SplitBrainEvents

	// Scale thresholds by scenario duration to avoid penalizing longer scenarios.
	durationScale := float64(nsr.scenario.DurationBlocks) / 50.0
	if durationScale < 1.0 {
		durationScale = 1.0
	}

	// Attack resilience grading - based on true failures (split-brain/unexpected).
	if trueFailures == 0 {
		nsr.results.AttackResilienceGrade = "A+"
	} else if trueFailures < int64(5*durationScale) {
		nsr.results.AttackResilienceGrade = "A"
	} else if trueFailures < int64(15*durationScale) {
		nsr.results.AttackResilienceGrade = "B"
	} else if trueFailures < int64(40*durationScale) {
		nsr.results.AttackResilienceGrade = "C"
	} else {
		nsr.results.AttackResilienceGrade = "D"
	}

	// Recovery grading
	if nsr.results.RecoveryBlocks == 0 {
		nsr.results.RecoveryGrade = "A+"
	} else if nsr.results.RecoveryBlocks < 10 {
		nsr.results.RecoveryGrade = "A"
	} else if nsr.results.RecoveryBlocks < 30 {
		nsr.results.RecoveryGrade = "B"
	} else if nsr.results.RecoveryBlocks < 60 {
		nsr.results.RecoveryGrade = "C"
	} else {
		nsr.results.RecoveryGrade = "D"
	}

	// Overall grade - weighted average (resilience 60%, recovery 40%)
	grades := map[string]int{"A+": 5, "A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
	weightedScore := float64(grades[nsr.results.AttackResilienceGrade])*0.6 +
		float64(grades[nsr.results.RecoveryGrade])*0.4

	switch {
	case weightedScore >= 4.5:
		nsr.results.OverallGrade = "A+"
	case weightedScore >= 3.5:
		nsr.results.OverallGrade = "A"
	case weightedScore >= 2.5:
		nsr.results.OverallGrade = "B"
	case weightedScore >= 1.5:
		nsr.results.OverallGrade = "C"
	default:
		nsr.results.OverallGrade = "D"
	}

	// Recommendations
	if nsr.results.SplitBrainEvents > 0 {
		nsr.results.Recommendations = append(nsr.results.Recommendations,
			"Implement stronger partition detection mechanisms")
	}
	if trueFailures > int64(10*durationScale) {
		nsr.results.Recommendations = append(nsr.results.Recommendations,
			"Review validator distribution strategy")
	}
	if nsr.results.RecoveryBlocks > 30 {
		nsr.results.Recommendations = append(nsr.results.Recommendations,
			"Implement faster consensus recovery protocol")
	}
}

// ============================================================================
// Predefined Network Scenarios
// ============================================================================

// GetNetworkScenarios returns predefined network attack scenarios
func GetNetworkScenarios() []NetworkScenarioConfig {
	return []NetworkScenarioConfig{
		{
			Name:        "simple-partition",
			Description: "Simple 50/50 network partition with rapid healing",
			PartitionConfig: &PartitionConfig{
				NumPartitions:           2,
				PartitionDistribution:   []float64{0.5, 0.5},
				PartitionDurationBlocks: 10,
				HealingProbability:      0.15,
				PartialConnectivity:     true,
				BandwidthReduction:      0.3,
				CrossPartitionDelayMs:   2000,
				CrossPartitionLossRate:  0.5,
			},
			StartAtBlock:   10,
			DurationBlocks: 50,
		},
		{
			Name:        "asymmetric-partition",
			Description: "Asymmetric partition (70/30 split) - majority can continue",
			PartitionConfig: &PartitionConfig{
				NumPartitions:           2,
				PartitionDistribution:   []float64{0.7, 0.3},
				PartitionDurationBlocks: 15,
				HealingProbability:      0.1,
				PartialConnectivity:     true,
				BandwidthReduction:      0.2,
				CrossPartitionDelayMs:   1500,
				CrossPartitionLossRate:  0.4,
			},
			StartAtBlock:   10,
			DurationBlocks: 50,
		},
		{
			Name:        "three-way-partition",
			Description: "Three-way partition preventing any majority",
			PartitionConfig: &PartitionConfig{
				NumPartitions:           3,
				PartitionDistribution:   []float64{0.34, 0.33, 0.33},
				PartitionDurationBlocks: 10,
				HealingProbability:      0.15,
				PartialConnectivity:     true,
				CrossPartitionDelayMs:   2000,
				CrossPartitionLossRate:  0.6,
			},
			StartAtBlock:   10,
			DurationBlocks: 35,
		},
		{
			Name:        "single-node-eclipse",
			Description: "Eclipse attack on single validator",
			EclipseConfig: &EclipseConfig{
				TargetValidators:      []int{0},
				MaliciousPeers:        30,
				ConnectionBlockRate:   0.95,
				EclipseDurationBlocks: 40,
				AttackType:            EclipsePartial,
			},
			StartAtBlock:   10,
			DurationBlocks: 60,
		},
		{
			Name:        "multi-node-eclipse",
			Description: "Eclipse attack on 10% of validators",
			EclipseConfig: &EclipseConfig{
				TargetValidators:      []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
				MaliciousPeers:        100,
				ConnectionBlockRate:   0.9,
				EclipseDurationBlocks: 30,
				AttackType:            EclipsePartial,
			},
			StartAtBlock:   10,
			DurationBlocks: 50,
		},
		{
			Name:        "delayed-eclipse",
			Description: "Eclipse attack with message delays only",
			EclipseConfig: &EclipseConfig{
				TargetValidators:      []int{0, 1, 2},
				EclipseDurationBlocks: 50,
				AttackType:            EclipseDelayed,
				MessageDelayMs:        5000,
			},
			StartAtBlock:   10,
			DurationBlocks: 70,
		},
		{
			Name:        "combined-attack",
			Description: "Partition + Eclipse attack simultaneously with partial connectivity",
			PartitionConfig: &PartitionConfig{
				NumPartitions:           2,
				PartitionDistribution:   []float64{0.7, 0.3},
				PartitionDurationBlocks: 12,
				HealingProbability:      0.12,
				PartialConnectivity:     true,
				BandwidthReduction:      0.25,
				CrossPartitionDelayMs:   1500,
				CrossPartitionLossRate:  0.5,
			},
			EclipseConfig: &EclipseConfig{
				TargetValidators:      []int{0, 1, 2},
				ConnectionBlockRate:   0.80,
				EclipseDurationBlocks: 15,
				AttackType:            EclipsePartial,
			},
			StartAtBlock:   10,
			DurationBlocks: 50,
		},
	}
}

// RunNetworkScenario runs a named network scenario
func RunNetworkScenario(name string, validators []*SimulatedValidator) (*NetworkScenarioResult, error) {
	scenarios := GetNetworkScenarios()
	for _, s := range scenarios {
		if s.Name == name {
			runner := NewNetworkScenarioRunner(&s, validators, nil)
			return runner.Run(context.Background())
		}
	}
	return nil, fmt.Errorf("unknown scenario: %s", name)
}
