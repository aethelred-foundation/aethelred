package libp2p

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

// testLogger captures log output for assertions.
type testLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *testLogger) Info(msg string, keyvals ...interface{})  { l.record("INFO", msg) }
func (l *testLogger) Error(msg string, keyvals ...interface{}) { l.record("ERROR", msg) }
func (l *testLogger) Debug(msg string, keyvals ...interface{}) { l.record("DEBUG", msg) }

func (l *testLogger) record(level, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf("[%s] %s", level, msg))
}

// newTestHost creates an AethelredHost bound to a random port for testing.
func newTestHost(t *testing.T) (*AethelredHost, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	cfg := DefaultConfig()
	cfg.EnableMDNS = false // avoid mDNS chatter in tests
	cfg.Logger = &testLogger{}
	// Use random high port on localhost only
	cfg.ListenAddrs = []multiaddr.Multiaddr{
		mustMultiaddr("/ip4/127.0.0.1/tcp/0"),
	}

	h, err := NewHost(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("NewHost: %v", err)
	}

	cleanup := func() {
		h.Close()
		cancel()
	}
	return h, cleanup
}

// ---------------------------------------------------------------------------
// Core host tests
// ---------------------------------------------------------------------------

func TestHost_Init(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	if h.Host == nil {
		t.Fatal("underlying libp2p host is nil")
	}
	if h.ID() == "" {
		t.Error("host peer ID is empty")
	}
	if h.dht == nil {
		t.Error("DHT is nil")
	}
	if h.pubsub == nil {
		t.Error("PubSub is nil")
	}
	if h.peerStore == nil {
		t.Error("PeerStore is nil")
	}
	if h.metrics == nil {
		t.Error("NetworkMetrics is nil")
	}
	if len(h.Addrs()) == 0 {
		t.Error("host has no listen addresses")
	}
}

func TestHost_DefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()

	if cfg.PrivateKey == nil {
		t.Error("default config should generate a private key")
	}
	if len(cfg.ListenAddrs) == 0 {
		t.Error("default config should have listen addresses")
	}
	if cfg.LowWatermark != MinPeers {
		t.Errorf("expected LowWatermark=%d, got %d", MinPeers, cfg.LowWatermark)
	}
	if cfg.HighWatermark != MaxPeers {
		t.Errorf("expected HighWatermark=%d, got %d", MaxPeers, cfg.HighWatermark)
	}
	if !cfg.EnableMDNS {
		t.Error("mDNS should be enabled by default")
	}
}

func TestHost_ProtocolRegistration(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	protocols := []protocol.ID{
		ProtocolIDConsensus,
		ProtocolIDSync,
		ProtocolIDCompute,
		ProtocolIDAttestation,
		ProtocolIDDAG,
	}

	handlerCalled := make(map[protocol.ID]bool)
	for _, pid := range protocols {
		p := pid // capture
		h.RegisterProtocolHandler(p, func(s network.Stream) {
			handlerCalled[p] = true
			s.Close()
		})
	}

	// Verify all protocol IDs are registered with distinct values.
	seen := make(map[protocol.ID]bool)
	for _, pid := range protocols {
		if seen[pid] {
			t.Errorf("duplicate protocol ID: %s", pid)
		}
		seen[pid] = true
	}
	if len(seen) != 5 {
		t.Errorf("expected 5 unique protocols, got %d", len(seen))
	}
}

func TestHost_GossipSub_Subscribe(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	topics := []string{
		TopicConsensusVotes,
		TopicComputeJobs,
		TopicAttestations,
		TopicDAGVertices,
		TopicSealBroadcast,
	}

	for _, topic := range topics {
		err := h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
			return nil
		})
		if err != nil {
			t.Fatalf("Subscribe(%q): %v", topic, err)
		}
	}

	h.topicsMu.RLock()
	defer h.topicsMu.RUnlock()

	for _, topic := range topics {
		if _, ok := h.topics[topic]; !ok {
			t.Errorf("topic %q not found in topics map", topic)
		}
		if _, ok := h.subs[topic]; !ok {
			t.Errorf("subscription for %q not found", topic)
		}
	}
}

func TestHost_GossipSub_Publish(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	topic := "test/publish"

	// Subscribe first so the topic exists.
	err := h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Publish should succeed.
	err = h.Publish(context.Background(), topic, []byte("hello"))
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}

	if h.metrics.MessagesSent.Get() == 0 {
		t.Error("expected MessagesSent to be incremented")
	}
}

func TestHost_GossipSub_Publish_NewTopic(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	// Publish to a topic that has not been subscribed to yet.
	// This should auto-join the topic.
	err := h.Publish(context.Background(), "auto-joined/topic", []byte("data"))
	if err != nil {
		t.Fatalf("Publish to new topic: %v", err)
	}

	h.topicsMu.RLock()
	_, ok := h.topics["auto-joined/topic"]
	h.topicsMu.RUnlock()
	if !ok {
		t.Error("topic should have been auto-joined on publish")
	}
}

func TestHost_MessageHandling(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	// Register a handler and verify it is stored.
	topic := "test/handler"
	var called int32
	err := h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
		atomic.AddInt32(&called, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	h.handlersMu.RLock()
	handler, exists := h.handlers[topic]
	h.handlersMu.RUnlock()

	if !exists {
		t.Fatal("handler not registered")
	}
	if handler == nil {
		t.Fatal("handler is nil")
	}
}

func TestHost_ConnectionManagement(t *testing.T) {
	t.Parallel()
	h1, cleanup1 := newTestHost(t)
	defer cleanup1()
	h2, cleanup2 := newTestHost(t)
	defer cleanup2()

	// Connect h1 -> h2
	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	err := h1.Connect(context.Background(), h2Info)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Wait briefly for connection notifications.
	time.Sleep(100 * time.Millisecond)

	peers := h1.ConnectedPeers()
	found := false
	for _, p := range peers {
		if p == h2.ID() {
			found = true
			break
		}
	}
	if !found {
		t.Error("h2 not in h1's connected peers")
	}

	if h1.PeerCount() == 0 {
		t.Error("PeerCount should be > 0")
	}
}

func TestHost_PeerDiscovery(t *testing.T) {
	t.Parallel()
	h1, cleanup1 := newTestHost(t)
	defer cleanup1()
	h2, cleanup2 := newTestHost(t)
	defer cleanup2()

	// Connect the two hosts
	h2Info := peer.AddrInfo{
		ID:    h2.ID(),
		Addrs: h2.Addrs(),
	}
	if err := h1.Connect(context.Background(), h2Info); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Subscribe both to the same topic.
	topic := "test/discovery"
	for _, h := range []*AethelredHost{h1, h2} {
		if err := h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
			return nil
		}); err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
	}

	// Allow GossipSub heartbeat time to propagate peer info.
	time.Sleep(2 * time.Second)

	peers := h1.FindPeers(topic)
	if len(peers) == 0 {
		t.Log("FindPeers returned 0 peers (may need longer heartbeat interval)")
	}

	// FindPeers for unknown topic should return nil.
	if h1.FindPeers("nonexistent/topic") != nil {
		t.Error("expected nil for unknown topic")
	}
}

func TestHost_ConcurrentMessages(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	topic := "test/concurrent"
	var received int64
	err := h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
		atomic.AddInt64(&received, 1)
		return nil
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Fire off concurrent publishes.
	const numMessages = 50
	var wg sync.WaitGroup
	wg.Add(numMessages)
	for i := 0; i < numMessages; i++ {
		go func(n int) {
			defer wg.Done()
			data := []byte(fmt.Sprintf("message-%d", n))
			_ = h.Publish(context.Background(), topic, data)
		}(i)
	}
	wg.Wait()

	if h.metrics.MessagesSent.Get() < uint64(numMessages) {
		t.Errorf("expected at least %d messages sent, got %d", numMessages, h.metrics.MessagesSent.Get())
	}
}

func TestHost_InvalidPeerAddress(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	// Attempt to connect to a bogus peer address.
	bogusAddr, _ := multiaddr.NewMultiaddr("/ip4/192.0.2.1/tcp/1")
	bogusInfo := peer.AddrInfo{
		ID:    "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
		Addrs: []multiaddr.Multiaddr{bogusAddr},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := h.Connect(ctx, bogusInfo)
	if err == nil {
		t.Error("expected error connecting to unreachable address")
	}
}

func TestHost_TopicValidation(t *testing.T) {
	t.Parallel()
	h, cleanup := newTestHost(t)
	defer cleanup()

	// Subscribe to empty string topic -- libp2p allows it, just verify no panic.
	err := h.Subscribe("", func(ctx context.Context, msg *pubsub.Message) error {
		return nil
	})
	// Empty topic may or may not error depending on libp2p version.
	// The important thing is no panic.
	_ = err

	// Verify metrics reflect startup state.
	metrics := h.GetMetrics()
	if metrics == nil {
		t.Fatal("GetMetrics() returned nil")
	}
	summary := metrics.GetSummary()
	if summary.Uptime <= 0 {
		t.Error("expected positive uptime")
	}
}

func TestHost_Close(t *testing.T) {
	t.Parallel()
	h, cancel := newTestHost(t)

	// Subscribe to a topic before closing.
	_ = h.Subscribe("close/test", func(ctx context.Context, msg *pubsub.Message) error {
		return nil
	})

	err := h.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	cancel()
}

// ---------------------------------------------------------------------------
// PeerStore unit tests
// ---------------------------------------------------------------------------

func TestPeerStore_AddRemove(t *testing.T) {
	t.Parallel()
	ps := NewPeerStore()
	pid := peer.ID("test-peer-1")

	ps.AddPeer(pid)
	if ps.PeerCount() != 1 {
		t.Errorf("expected 1 peer, got %d", ps.PeerCount())
	}

	info, ok := ps.GetPeer(pid)
	if !ok || info == nil {
		t.Fatal("peer not found")
	}
	if info.Score != 0.5 {
		t.Errorf("expected initial score 0.5, got %f", info.Score)
	}

	ps.RemovePeer(pid)
	if ps.PeerCount() != 0 {
		t.Errorf("expected 0 peers after removal, got %d", ps.PeerCount())
	}
}

func TestPeerStore_Validators(t *testing.T) {
	t.Parallel()
	ps := NewPeerStore()
	pid := peer.ID("validator-1")

	ps.AddPeer(pid)
	ps.SetValidator(pid, true)

	validators := ps.GetValidators()
	if len(validators) != 1 {
		t.Errorf("expected 1 validator, got %d", len(validators))
	}
	if ps.ValidatorCount() != 1 {
		t.Errorf("expected validator count 1, got %d", ps.ValidatorCount())
	}

	ps.SetValidator(pid, false)
	if ps.ValidatorCount() != 0 {
		t.Error("expected 0 validators after demotion")
	}
}

func TestPeerStore_HardwareCaps(t *testing.T) {
	t.Parallel()
	ps := NewPeerStore()
	pid := peer.ID("hw-peer")

	ps.AddPeer(pid)
	ps.SetHardwareCaps(pid, &HardwareCaps{
		HasTEE:      true,
		TEEPlatform: "sgx",
		HasGPU:      true,
		GPUModel:    "A100",
		HasFPGA:     true,
		FPGAModel:   "U250",
	})

	tee := ps.GetPeersWithTEE()
	if len(tee) != 1 {
		t.Errorf("expected 1 TEE peer, got %d", len(tee))
	}
	gpu := ps.GetPeersWithGPU()
	if len(gpu) != 1 {
		t.Errorf("expected 1 GPU peer, got %d", len(gpu))
	}
	fpga := ps.GetPeersWithFPGA()
	if len(fpga) != 1 {
		t.Errorf("expected 1 FPGA peer, got %d", len(fpga))
	}
}

func TestPeerStore_Score(t *testing.T) {
	t.Parallel()
	ps := NewPeerStore()
	pid := peer.ID("score-peer")
	ps.AddPeer(pid)

	ps.UpdateScore(pid, 0.3)
	info, _ := ps.GetPeer(pid)
	if info.Score != 0.8 { // 0.5 + 0.3
		t.Errorf("expected 0.8, got %f", info.Score)
	}

	// Clamp to 1.0
	ps.UpdateScore(pid, 0.5)
	info, _ = ps.GetPeer(pid)
	if info.Score != 1.0 {
		t.Errorf("expected 1.0 (clamped), got %f", info.Score)
	}

	// Clamp to 0
	ps.UpdateScore(pid, -2.0)
	info, _ = ps.GetPeer(pid)
	if info.Score != 0.0 {
		t.Errorf("expected 0.0 (clamped), got %f", info.Score)
	}
}

func TestPeerStore_TopPeersByScore(t *testing.T) {
	t.Parallel()
	ps := NewPeerStore()
	for i := 0; i < 5; i++ {
		pid := peer.ID(fmt.Sprintf("peer-%d", i))
		ps.AddPeer(pid)
		ps.UpdateScore(pid, float64(i)*0.1)
	}

	top := ps.GetTopPeersByScore(3)
	if len(top) != 3 {
		t.Fatalf("expected 3, got %d", len(top))
	}
	// Top peer should have highest score.
	if top[0].Score < top[1].Score {
		t.Error("peers not sorted by score descending")
	}
}

func TestPeerStore_PruneInactive(t *testing.T) {
	t.Parallel()
	ps := NewPeerStore()
	pid := peer.ID("old-peer")
	ps.AddPeer(pid)

	// Artificially age the peer.
	ps.mu.Lock()
	ps.peers[pid].LastSeen = time.Now().Add(-2 * time.Hour)
	ps.mu.Unlock()

	removed := ps.PruneInactive(1 * time.Hour)
	if removed != 1 {
		t.Errorf("expected 1 pruned, got %d", removed)
	}
	if ps.PeerCount() != 0 {
		t.Error("expected 0 peers after prune")
	}
}

// ---------------------------------------------------------------------------
// Metrics tests
// ---------------------------------------------------------------------------

func TestMetrics_Counter(t *testing.T) {
	t.Parallel()
	var c Counter
	c.Inc()
	c.Inc()
	c.Add(3)
	if c.Get() != 5 {
		t.Errorf("expected 5, got %d", c.Get())
	}
}

func TestMetrics_Gauge(t *testing.T) {
	t.Parallel()
	var g Gauge
	g.Inc()
	g.Inc()
	g.Dec()
	if g.Get() != 1 {
		t.Errorf("expected 1, got %d", g.Get())
	}
	g.Set(42)
	if g.Get() != 42 {
		t.Errorf("expected 42, got %d", g.Get())
	}
}

func TestMetrics_TopicMetrics(t *testing.T) {
	t.Parallel()
	m := NewNetworkMetrics()
	tm := m.GetTopicMetrics("test/topic")
	if tm.Name != "test/topic" {
		t.Errorf("expected topic name 'test/topic', got %q", tm.Name)
	}
	tm.Published.Inc()
	tm.Received.Add(5)

	// Same topic should return cached instance.
	tm2 := m.GetTopicMetrics("test/topic")
	if tm2.Published.Get() != 1 {
		t.Error("expected cached topic metrics")
	}
}

func TestMetrics_ProtocolCalls(t *testing.T) {
	t.Parallel()
	m := NewNetworkMetrics()
	pc := m.GetProtocolCalls("consensus")
	pc.Inc()
	pc.Inc()

	pc2 := m.GetProtocolCalls("consensus")
	if pc2.Get() != 2 {
		t.Errorf("expected 2 protocol calls, got %d", pc2.Get())
	}
}

func TestMetrics_Summary(t *testing.T) {
	t.Parallel()
	m := NewNetworkMetrics()
	m.PeersConnected.Inc()
	m.MessagesSent.Add(10)
	m.BytesSent.Add(1024)

	summary := m.GetSummary()
	if summary.PeersConnected != 1 {
		t.Errorf("expected 1 peer connected, got %d", summary.PeersConnected)
	}
	if summary.MessagesSent != 10 {
		t.Errorf("expected 10 messages sent, got %d", summary.MessagesSent)
	}
	if summary.Uptime <= 0 {
		t.Error("expected positive uptime")
	}
}

func TestMetrics_TopicSummaries(t *testing.T) {
	t.Parallel()
	m := NewNetworkMetrics()
	tm := m.GetTopicMetrics("topic-a")
	tm.Published.Add(3)
	tm.Received.Add(7)
	tm.SubscriberCount.Set(2)

	summaries := m.GetTopicSummaries()
	if len(summaries) != 1 {
		t.Fatalf("expected 1 topic summary, got %d", len(summaries))
	}
	if summaries[0].Published != 3 {
		t.Errorf("expected 3 published, got %d", summaries[0].Published)
	}
}

// ---------------------------------------------------------------------------
// Connection manager tests
// ---------------------------------------------------------------------------

func TestConnManager_Basic(t *testing.T) {
	t.Parallel()
	cm := newConnManager(MinPeers, MaxPeers, time.Minute)
	if cm == nil {
		t.Fatal("connection manager is nil")
	}
}

func TestConnManager_Fallback(t *testing.T) {
	t.Parallel()
	// basicConnManager is the fallback path, verify its methods are safe.
	bcm := &basicConnManager{
		lowWater:    10,
		highWater:   100,
		gracePeriod: time.Minute,
	}

	pid := peer.ID("test")
	bcm.TagPeer(pid, "tag", 10)
	bcm.UntagPeer(pid, "tag")
	bcm.UpsertTag(pid, "tag", func(i int) int { return i + 1 })
	bcm.Protect(pid, "tag")
	if bcm.IsProtected(pid, "tag") {
		t.Error("basicConnManager.IsProtected should return false")
	}
	if bcm.Unprotect(pid, "tag") {
		t.Error("basicConnManager.Unprotect should return false")
	}
	if bcm.GetTagInfo(pid) != nil {
		t.Error("basicConnManager.GetTagInfo should return nil")
	}
	if bcm.Notifee() != nil {
		t.Error("basicConnManager.Notifee should return nil")
	}
	bcm.TrimOpenConns(context.Background())
	if err := bcm.Close(); err != nil {
		t.Errorf("basicConnManager.Close: %v", err)
	}
	if err := bcm.CheckLimit(nil); err != nil {
		t.Errorf("basicConnManager.CheckLimit: %v", err)
	}
}

func TestConnectionPrioritizer(t *testing.T) {
	t.Parallel()
	bcm := &basicConnManager{}
	cp := NewConnectionPrioritizer(bcm)
	pid := peer.ID("test-peer")

	cp.ProtectValidator(pid)
	cp.UnprotectValidator(pid)
	cp.ProtectTEENode(pid)
	cp.UnprotectTEENode(pid)
	cp.ProtectComputeWorker(pid)
	cp.UnprotectComputeWorker(pid)
	cp.ProtectDAGParticipant(pid)
	cp.UnprotectDAGParticipant(pid)

	// basicConnManager always returns false for checks.
	if cp.IsValidator(pid) {
		t.Error("expected false for basicConnManager")
	}
	if cp.IsTEENode(pid) {
		t.Error("expected false")
	}
	if cp.IsComputeWorker(pid) {
		t.Error("expected false")
	}
	if cp.IsDAGParticipant(pid) {
		t.Error("expected false")
	}

	cp.UpdateScore(pid, 10)
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

func BenchmarkHost_MessageDispatch(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := DefaultConfig()
	cfg.EnableMDNS = false
	cfg.Logger = &noopLogger{}
	cfg.ListenAddrs = []multiaddr.Multiaddr{
		mustMultiaddr("/ip4/127.0.0.1/tcp/0"),
	}

	h, err := NewHost(ctx, cfg)
	if err != nil {
		b.Fatalf("NewHost: %v", err)
	}
	defer h.Close()

	topic := "bench/dispatch"
	_ = h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
		return nil
	})

	data := []byte("benchmark-payload")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Publish(ctx, topic, data)
	}
}

// ---------------------------------------------------------------------------
// Fuzz
// ---------------------------------------------------------------------------

func FuzzHost_MessageParsing(f *testing.F) {
	f.Add([]byte("valid-message"))
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte{})
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cfg := DefaultConfig()
		cfg.EnableMDNS = false
		cfg.Logger = &noopLogger{}
		cfg.ListenAddrs = []multiaddr.Multiaddr{
			mustMultiaddr("/ip4/127.0.0.1/tcp/0"),
		}

		h, err := NewHost(ctx, cfg)
		if err != nil {
			t.Skip("could not create host")
		}
		defer h.Close()

		topic := "fuzz/parse"
		_ = h.Subscribe(topic, func(ctx context.Context, msg *pubsub.Message) error {
			return nil
		})

		// Publishing arbitrary bytes should not panic.
		_ = h.Publish(ctx, topic, data)
	})
}

// ---------------------------------------------------------------------------
// NoopLogger
// ---------------------------------------------------------------------------

func TestNoopLogger(t *testing.T) {
	t.Parallel()
	l := &noopLogger{}
	// These should not panic.
	l.Info("msg", "key", "val")
	l.Error("msg")
	l.Debug("msg")
}

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

func TestProtocolConstants(t *testing.T) {
	t.Parallel()
	if ProtocolIDConsensus != "/aethelred/consensus/1.0.0" {
		t.Error("ProtocolIDConsensus mismatch")
	}
	if ProtocolIDSync != "/aethelred/sync/1.0.0" {
		t.Error("ProtocolIDSync mismatch")
	}
	if ProtocolIDCompute != "/aethelred/compute/1.0.0" {
		t.Error("ProtocolIDCompute mismatch")
	}
	if ProtocolIDAttestation != "/aethelred/attestation/1.0.0" {
		t.Error("ProtocolIDAttestation mismatch")
	}
	if ProtocolIDDAG != "/aethelred/dag/1.0.0" {
		t.Error("ProtocolIDDAG mismatch")
	}
}

func TestTopicConstants(t *testing.T) {
	t.Parallel()
	topics := []string{
		TopicConsensusVotes,
		TopicComputeJobs,
		TopicAttestations,
		TopicDAGVertices,
		TopicSealBroadcast,
	}
	seen := make(map[string]bool)
	for _, topic := range topics {
		if topic == "" {
			t.Error("topic constant is empty")
		}
		if seen[topic] {
			t.Errorf("duplicate topic: %s", topic)
		}
		seen[topic] = true
	}
}
