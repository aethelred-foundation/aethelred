//go:build bridge

package bridge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================================================
// Mock Bridge Infrastructure
//
// These types simulate bridge components without requiring real Ethereum nodes
// or IBC relayers. All tests run entirely in-process with deterministic timing.
// ============================================================================

// DepositStatus represents the lifecycle of a bridge deposit.
type DepositStatus int

const (
	DepositPending DepositStatus = iota
	DepositConfirmed
	DepositMinted
	DepositFailed
)

// BridgeDeposit represents a lock-and-mint deposit event on the source chain.
type BridgeDeposit struct {
	ID          [32]byte
	Sender      [20]byte
	Recipient   [20]byte
	Amount      *big.Int
	TokenAddr   [20]byte
	BlockHeight uint64
	Timestamp   time.Time
	Status      DepositStatus
	Nonce       uint64
}

// CCTPMessage represents a Cross-Chain Transfer Protocol message.
type CCTPMessage struct {
	ID           [32]byte
	SourceDomain uint32
	DestDomain   uint32
	Nonce        uint64
	Sender       [32]byte
	Recipient    [32]byte
	Amount       *big.Int
	MessageBody  []byte
	Attestation  []byte
}

// RelayMessage represents a bridge relay message requiring validator consensus.
type RelayMessage struct {
	ID             [32]byte
	SourceChain    string
	DestChain      string
	Payload        []byte
	Signatures     []ValidatorSignature
	RequiredWeight uint64
	TotalWeight    uint64
	Finalized      bool
}

// ValidatorSignature is a simulated validator signature for relay consensus.
type ValidatorSignature struct {
	ValidatorID [32]byte
	Signature   [64]byte
	Power       uint64
	Timestamp   time.Time
}

// MockBridge simulates the Aethelred bridge for testing.
type MockBridge struct {
	mu              sync.RWMutex
	deposits        map[[32]byte]*BridgeDeposit
	cctpMessages    map[[32]byte]*CCTPMessage
	relayMessages   map[[32]byte]*RelayMessage
	blockTime       time.Duration
	processDelay    time.Duration
	validatorCount  int
	validatorPowers []uint64
	totalPower      uint64

	// Metrics
	depositsProcessed  atomic.Int64
	depositsFailed     atomic.Int64
	cctpProcessed      atomic.Int64
	relayFinalized     atomic.Int64
	totalProcessTimeNs atomic.Int64
}

// NewMockBridge creates a mock bridge with the given parameters.
func NewMockBridge(validatorCount int, blockTime, processDelay time.Duration) *MockBridge {
	powers := make([]uint64, validatorCount)
	var totalPower uint64
	for i := range powers {
		powers[i] = 100 // equal power for simplicity
		totalPower += 100
	}

	return &MockBridge{
		deposits:        make(map[[32]byte]*BridgeDeposit),
		cctpMessages:    make(map[[32]byte]*CCTPMessage),
		relayMessages:   make(map[[32]byte]*RelayMessage),
		blockTime:       blockTime,
		processDelay:    processDelay,
		validatorCount:  validatorCount,
		validatorPowers: powers,
		totalPower:      totalPower,
	}
}

// ProcessDeposit simulates processing a deposit through lock-and-mint.
func (b *MockBridge) ProcessDeposit(ctx context.Context, deposit *BridgeDeposit) error {
	start := time.Now()
	defer func() {
		b.totalProcessTimeNs.Add(time.Since(start).Nanoseconds())
	}()

	// Simulate block confirmation delay.
	select {
	case <-time.After(b.processDelay):
	case <-ctx.Done():
		b.depositsFailed.Add(1)
		return ctx.Err()
	}

	b.mu.Lock()
	deposit.Status = DepositConfirmed
	b.deposits[deposit.ID] = deposit
	b.mu.Unlock()

	// Simulate mint on destination chain.
	select {
	case <-time.After(b.processDelay / 2):
	case <-ctx.Done():
		b.depositsFailed.Add(1)
		return ctx.Err()
	}

	b.mu.Lock()
	deposit.Status = DepositMinted
	b.mu.Unlock()

	b.depositsProcessed.Add(1)
	return nil
}

// ProcessCCTPMessage simulates CCTP message relay.
func (b *MockBridge) ProcessCCTPMessage(ctx context.Context, msg *CCTPMessage) error {
	start := time.Now()
	defer func() {
		b.totalProcessTimeNs.Add(time.Since(start).Nanoseconds())
	}()

	// Simulate attestation verification.
	h := sha256.Sum256(msg.MessageBody)
	if len(msg.Attestation) == 0 {
		msg.Attestation = h[:]
	}

	select {
	case <-time.After(b.processDelay):
	case <-ctx.Done():
		return ctx.Err()
	}

	b.mu.Lock()
	b.cctpMessages[msg.ID] = msg
	b.mu.Unlock()

	b.cctpProcessed.Add(1)
	return nil
}

// FinalizeRelay simulates validator consensus for a relay message.
// Returns true if 67% consensus was reached.
func (b *MockBridge) FinalizeRelay(ctx context.Context, msg *RelayMessage, signingRatio float64) (bool, error) {
	start := time.Now()
	defer func() {
		b.totalProcessTimeNs.Add(time.Since(start).Nanoseconds())
	}()

	signaturesNeeded := int(float64(b.validatorCount) * signingRatio)
	var accumulatedPower uint64

	for i := 0; i < signaturesNeeded; i++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}

		var sig ValidatorSignature
		binary.BigEndian.PutUint64(sig.ValidatorID[:8], uint64(i))
		sig.Power = b.validatorPowers[i]
		sig.Timestamp = time.Now()
		// Simulate signing delay per validator.
		time.Sleep(50 * time.Microsecond)

		msg.Signatures = append(msg.Signatures, sig)
		accumulatedPower += sig.Power
	}

	threshold := (b.totalPower * 2) / 3
	msg.Finalized = accumulatedPower > threshold
	msg.TotalWeight = accumulatedPower
	msg.RequiredWeight = threshold

	b.mu.Lock()
	b.relayMessages[msg.ID] = msg
	b.mu.Unlock()

	if msg.Finalized {
		b.relayFinalized.Add(1)
	}

	return msg.Finalized, nil
}

// makeDeposit creates a test deposit with a unique ID.
func makeDeposit(index int) *BridgeDeposit {
	var id [32]byte
	binary.BigEndian.PutUint64(id[:8], uint64(index))
	_, _ = rand.Read(id[8:])

	var sender, recipient, token [20]byte
	binary.BigEndian.PutUint64(sender[:8], uint64(index))
	binary.BigEndian.PutUint64(recipient[:8], uint64(index+1000))
	copy(token[:], []byte{0x01, 0x02, 0x03})

	return &BridgeDeposit{
		ID:          id,
		Sender:      sender,
		Recipient:   recipient,
		Amount:      big.NewInt(int64(1000000 + index)),
		TokenAddr:   token,
		BlockHeight: uint64(100 + index),
		Timestamp:   time.Now(),
		Status:      DepositPending,
		Nonce:       uint64(index),
	}
}

// makeCCTPMessage creates a test CCTP message with configurable body size.
func makeCCTPMessage(index int, bodySize int) *CCTPMessage {
	var id [32]byte
	binary.BigEndian.PutUint64(id[:8], uint64(index))

	var sender, recipient [32]byte
	binary.BigEndian.PutUint64(sender[:8], uint64(index))
	binary.BigEndian.PutUint64(recipient[:8], uint64(index+5000))

	body := make([]byte, bodySize)
	for i := range body {
		body[i] = byte((index + i) % 256)
	}

	return &CCTPMessage{
		ID:           id,
		SourceDomain: 0, // Ethereum
		DestDomain:   1, // Aethelred
		Nonce:        uint64(index),
		Sender:       sender,
		Recipient:    recipient,
		Amount:       big.NewInt(int64(500000 + index)),
		MessageBody:  body,
	}
}

// makeRelayMessage creates a test relay message with the given payload size.
func makeRelayMessage(index int, payloadSize int) *RelayMessage {
	var id [32]byte
	binary.BigEndian.PutUint64(id[:8], uint64(index))

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((index + i) % 256)
	}

	return &RelayMessage{
		ID:          id,
		SourceChain: "ethereum",
		DestChain:   "aethelred",
		Payload:     payload,
	}
}

// ============================================================================
// Tests
// ============================================================================

// TestBridgeThroughput_ConcurrentDeposits simulates 100 concurrent
// lock-and-mint operations on the Ethereum bridge.
func TestBridgeThroughput_ConcurrentDeposits(t *testing.T) {
	const (
		concurrentDeposits = 100
		processDelay       = 500 * time.Microsecond
		blockTime          = 6 * time.Second
		testTimeout        = 30 * time.Second
	)

	bridge := NewMockBridge(21, blockTime, processDelay)
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var (
		wg        sync.WaitGroup
		errCount  atomic.Int64
		latencies = make([]time.Duration, concurrentDeposits)
	)

	start := time.Now()

	for i := 0; i < concurrentDeposits; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			deposit := makeDeposit(idx)
			iterStart := time.Now()
			if err := bridge.ProcessDeposit(ctx, deposit); err != nil {
				errCount.Add(1)
				return
			}
			latencies[idx] = time.Since(iterStart)
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	processed := bridge.depositsProcessed.Load()
	failed := bridge.depositsFailed.Load()
	successRate := float64(processed) / float64(concurrentDeposits) * 100

	t.Logf("Concurrent deposits: %d", concurrentDeposits)
	t.Logf("Processed: %d, Failed: %d (errors: %d)", processed, failed, errCount.Load())
	t.Logf("Success rate: %.1f%%", successRate)
	t.Logf("Total elapsed: %v", elapsed)
	t.Logf("Throughput: %.1f deposits/sec", float64(processed)/elapsed.Seconds())

	// Calculate P50 and P99 from valid latencies.
	var validLatencies []time.Duration
	for _, lat := range latencies {
		if lat > 0 {
			validLatencies = append(validLatencies, lat)
		}
	}
	if len(validLatencies) > 0 {
		sortDurations(validLatencies)
		p50 := validLatencies[len(validLatencies)/2]
		p99 := validLatencies[int(float64(len(validLatencies))*0.99)]
		t.Logf("P50 latency: %v, P99 latency: %v", p50, p99)
	}

	if successRate < 95 {
		t.Fatalf("success rate %.1f%% below 95%% threshold", successRate)
	}

	if processed < int64(concurrentDeposits*90/100) {
		t.Fatalf("only %d/%d deposits processed", processed, concurrentDeposits)
	}
}

// TestBridgeThroughput_CCTPMessages tests CCTP message relay throughput
// with varying message sizes and concurrent relayers.
func TestBridgeThroughput_CCTPMessages(t *testing.T) {
	testCases := []struct {
		name            string
		messageCount    int
		bodySize        int
		concurrentRelay int
	}{
		{"Small_10_Concurrent4", 10, 256, 4},
		{"Medium_50_Concurrent8", 50, 1024, 8},
		{"Large_100_Concurrent16", 100, 4096, 16},
		{"XLarge_50_Concurrent8", 50, 16384, 8},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bridge := NewMockBridge(21, 6*time.Second, 200*time.Microsecond)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			messages := make([]*CCTPMessage, tc.messageCount)
			for i := range messages {
				messages[i] = makeCCTPMessage(i, tc.bodySize)
			}

			var (
				wg       sync.WaitGroup
				errCount atomic.Int64
			)
			sem := make(chan struct{}, tc.concurrentRelay)

			start := time.Now()

			for _, msg := range messages {
				wg.Add(1)
				sem <- struct{}{}
				go func(m *CCTPMessage) {
					defer func() {
						<-sem
						wg.Done()
					}()
					if err := bridge.ProcessCCTPMessage(ctx, m); err != nil {
						errCount.Add(1)
					}
				}(msg)
			}

			wg.Wait()
			elapsed := time.Since(start)

			processed := bridge.cctpProcessed.Load()
			throughput := float64(processed) / elapsed.Seconds()

			t.Logf("Messages: %d (body=%dB), Concurrency: %d", tc.messageCount, tc.bodySize, tc.concurrentRelay)
			t.Logf("Processed: %d, Errors: %d", processed, errCount.Load())
			t.Logf("Elapsed: %v, Throughput: %.1f msg/sec", elapsed, throughput)

			if errCount.Load() > int64(tc.messageCount/10) {
				t.Fatalf("error rate %d/%d exceeds 10%% threshold", errCount.Load(), tc.messageCount)
			}
		})
	}
}

// TestBridgeRecovery_EthereumCongestion simulates bridge behavior
// when Ethereum block times increase from 12s to 60s (congestion).
func TestBridgeRecovery_EthereumCongestion(t *testing.T) {
	const (
		normalBlockTime    = 12 * time.Millisecond  // scaled down: 12s -> 12ms
		congestedBlockTime = 60 * time.Millisecond  // scaled down: 60s -> 60ms
		depositsPerPhase   = 20
		testTimeout        = 30 * time.Second
	)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Phase 1: Normal operation.
	normalBridge := NewMockBridge(21, normalBlockTime, normalBlockTime/4)
	var normalLatencies []time.Duration
	for i := 0; i < depositsPerPhase; i++ {
		deposit := makeDeposit(i)
		start := time.Now()
		if err := normalBridge.ProcessDeposit(ctx, deposit); err != nil {
			t.Fatalf("normal phase deposit %d failed: %v", i, err)
		}
		normalLatencies = append(normalLatencies, time.Since(start))
	}

	// Phase 2: Congested operation (5x block time).
	congestedBridge := NewMockBridge(21, congestedBlockTime, congestedBlockTime/4)
	var congestedLatencies []time.Duration
	for i := 0; i < depositsPerPhase; i++ {
		deposit := makeDeposit(i + depositsPerPhase)
		start := time.Now()
		if err := congestedBridge.ProcessDeposit(ctx, deposit); err != nil {
			t.Fatalf("congested phase deposit %d failed: %v", i, err)
		}
		congestedLatencies = append(congestedLatencies, time.Since(start))
	}

	// Phase 3: Recovery to normal operation.
	recoveryBridge := NewMockBridge(21, normalBlockTime, normalBlockTime/4)
	var recoveryLatencies []time.Duration
	for i := 0; i < depositsPerPhase; i++ {
		deposit := makeDeposit(i + 2*depositsPerPhase)
		start := time.Now()
		if err := recoveryBridge.ProcessDeposit(ctx, deposit); err != nil {
			t.Fatalf("recovery phase deposit %d failed: %v", i, err)
		}
		recoveryLatencies = append(recoveryLatencies, time.Since(start))
	}

	normalAvg := avgDuration(normalLatencies)
	congestedAvg := avgDuration(congestedLatencies)
	recoveryAvg := avgDuration(recoveryLatencies)

	t.Logf("Normal avg latency:    %v", normalAvg)
	t.Logf("Congested avg latency: %v", congestedAvg)
	t.Logf("Recovery avg latency:  %v", recoveryAvg)

	// Congested should be slower than normal.
	if congestedAvg <= normalAvg {
		t.Errorf("congested latency (%v) should exceed normal latency (%v)", congestedAvg, normalAvg)
	}

	// Recovery latency should return close to normal (within 2x).
	if recoveryAvg > normalAvg*2 {
		t.Errorf("recovery latency (%v) exceeds 2x normal (%v); bridge did not recover", recoveryAvg, normalAvg*2)
	}

	// All deposits must succeed (zero failures across all phases).
	totalProcessed := normalBridge.depositsProcessed.Load() +
		congestedBridge.depositsProcessed.Load() +
		recoveryBridge.depositsProcessed.Load()
	if totalProcessed != int64(3*depositsPerPhase) {
		t.Fatalf("expected %d total processed, got %d", 3*depositsPerPhase, totalProcessed)
	}
}

// TestBridgeRelay_ValidatorConsensus tests 67% validator consensus
// for bridge relay messages under varying validator counts.
func TestBridgeRelay_ValidatorConsensus(t *testing.T) {
	testCases := []struct {
		name           string
		validatorCount int
		signingRatio   float64
		expectFinalize bool
	}{
		{"21_Validators_100pct", 21, 1.0, true},
		{"21_Validators_72pct", 21, 0.72, true},
		{"21_Validators_50pct", 21, 0.50, false},
		{"100_Validators_70pct", 100, 0.70, true},
		{"100_Validators_67pct", 100, 0.67, true},
		{"100_Validators_60pct", 100, 0.60, false},
		{"200_Validators_68pct", 200, 0.68, true},
		{"200_Validators_65pct", 200, 0.65, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bridge := NewMockBridge(tc.validatorCount, 6*time.Second, 100*time.Microsecond)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			msg := makeRelayMessage(0, 512)
			start := time.Now()
			finalized, err := bridge.FinalizeRelay(ctx, msg, tc.signingRatio)
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("FinalizeRelay error: %v", err)
			}

			t.Logf("Validators: %d, Signing: %.0f%%, Finalized: %v, Elapsed: %v",
				tc.validatorCount, tc.signingRatio*100, finalized, elapsed)
			t.Logf("Accumulated power: %d, Required: %d, Total: %d",
				msg.TotalWeight, msg.RequiredWeight, bridge.totalPower)

			if finalized != tc.expectFinalize {
				t.Fatalf("expected finalized=%v, got %v (power=%d, threshold=%d)",
					tc.expectFinalize, finalized, msg.TotalWeight, msg.RequiredWeight)
			}

			// Verify signature count matches expected signing validators.
			expectedSigs := int(float64(tc.validatorCount) * tc.signingRatio)
			if len(msg.Signatures) != expectedSigs {
				t.Fatalf("expected %d signatures, got %d", expectedSigs, len(msg.Signatures))
			}
		})
	}
}

// BenchmarkBridgeRelayLatency measures end-to-end bridge relay latency
// from deposit detection to mint confirmation.
func BenchmarkBridgeRelayLatency(b *testing.B) {
	benchCases := []struct {
		name           string
		validatorCount int
		processDelay   time.Duration
	}{
		{"21v_Fast", 21, 100 * time.Microsecond},
		{"21v_Normal", 21, 500 * time.Microsecond},
		{"100v_Fast", 100, 100 * time.Microsecond},
		{"100v_Normal", 100, 500 * time.Microsecond},
	}

	for _, bc := range benchCases {
		b.Run(fmt.Sprintf("Deposit_%s", bc.name), func(b *testing.B) {
			bridge := NewMockBridge(bc.validatorCount, 6*time.Second, bc.processDelay)
			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				deposit := makeDeposit(i)
				if err := bridge.ProcessDeposit(ctx, deposit); err != nil {
					b.Fatalf("deposit %d failed: %v", i, err)
				}
			}

			b.ReportMetric(float64(bridge.depositsProcessed.Load()), "deposits")
		})

		b.Run(fmt.Sprintf("Relay_%s", bc.name), func(b *testing.B) {
			bridge := NewMockBridge(bc.validatorCount, 6*time.Second, bc.processDelay)
			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				msg := makeRelayMessage(i, 512)
				finalized, err := bridge.FinalizeRelay(ctx, msg, 0.67)
				if err != nil {
					b.Fatalf("relay %d failed: %v", i, err)
				}
				if !finalized {
					b.Fatalf("relay %d not finalized", i)
				}
			}

			b.ReportMetric(float64(bridge.relayFinalized.Load()), "relays")
		})
	}
}

// ============================================================================
// Helpers
// ============================================================================

// sortDurations sorts a slice of durations in ascending order.
func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		key := d[i]
		j := i - 1
		for j >= 0 && d[j] > key {
			d[j+1] = d[j]
			j--
		}
		d[j+1] = key
	}
}

// avgDuration returns the average of a duration slice.
func avgDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	var total time.Duration
	for _, v := range d {
		total += v
	}
	return total / time.Duration(len(d))
}
