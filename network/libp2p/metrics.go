// Package libp2p provides network metrics for Aethelred
package libp2p

import (
	"sync/atomic"
	"time"
)

// Counter is a simple atomic counter for metrics
type Counter struct {
	value uint64
}

// Inc increments the counter
func (c *Counter) Inc() {
	atomic.AddUint64(&c.value, 1)
}

// Add adds a value to the counter
func (c *Counter) Add(delta uint64) {
	atomic.AddUint64(&c.value, delta)
}

// Get returns the current value
func (c *Counter) Get() uint64 {
	return atomic.LoadUint64(&c.value)
}

// Gauge is a simple atomic gauge for metrics
type Gauge struct {
	value int64
}

// Set sets the gauge value
func (g *Gauge) Set(val int64) {
	atomic.StoreInt64(&g.value, val)
}

// Inc increments the gauge
func (g *Gauge) Inc() {
	atomic.AddInt64(&g.value, 1)
}

// Dec decrements the gauge
func (g *Gauge) Dec() {
	atomic.AddInt64(&g.value, -1)
}

// Get returns the current value
func (g *Gauge) Get() int64 {
	return atomic.LoadInt64(&g.value)
}

// NetworkMetrics contains network performance metrics
type NetworkMetrics struct {
	// Peer metrics
	PeersConnected    Counter
	PeersDisconnected Counter
	PeersActive       Gauge

	// Message metrics
	MessagesSent      Counter
	MessagesReceived  Counter
	MessagesDropped   Counter
	MessageLatencyMs  Gauge

	// Topic metrics (by topic)
	TopicMetrics map[string]*TopicMetrics

	// Bandwidth metrics
	BytesSent         Counter
	BytesReceived     Counter

	// Connection metrics
	ConnectionAttempts Counter
	ConnectionFailures Counter

	// DHT metrics
	DHTQueries        Counter
	DHTQueryFailures  Counter

	// Protocol metrics
	ProtocolCalls     map[string]*Counter

	// Validator-specific metrics
	ValidatorPeers    Gauge
	TEEPeers          Gauge
	GPUPeers          Gauge
	FPGAPeers         Gauge

	// Consensus metrics
	ConsensusMessages Counter
	VoteExtensions    Counter
	DAGVertices       Counter

	// Start time for uptime calculation
	StartTime time.Time
}

// TopicMetrics contains metrics for a specific GossipSub topic
type TopicMetrics struct {
	Name             string
	Published        Counter
	Received         Counter
	Rejected         Counter
	Duplicates       Counter
	SubscriberCount  Gauge
}

// NewNetworkMetrics creates a new NetworkMetrics instance
func NewNetworkMetrics() *NetworkMetrics {
	return &NetworkMetrics{
		TopicMetrics:  make(map[string]*TopicMetrics),
		ProtocolCalls: make(map[string]*Counter),
		StartTime:     time.Now(),
	}
}

// GetTopicMetrics returns metrics for a specific topic
func (m *NetworkMetrics) GetTopicMetrics(topic string) *TopicMetrics {
	if tm, exists := m.TopicMetrics[topic]; exists {
		return tm
	}
	tm := &TopicMetrics{Name: topic}
	m.TopicMetrics[topic] = tm
	return tm
}

// GetProtocolCalls returns call count for a protocol
func (m *NetworkMetrics) GetProtocolCalls(protocol string) *Counter {
	if c, exists := m.ProtocolCalls[protocol]; exists {
		return c
	}
	c := &Counter{}
	m.ProtocolCalls[protocol] = c
	return c
}

// Uptime returns the duration since start
func (m *NetworkMetrics) Uptime() time.Duration {
	return time.Since(m.StartTime)
}

// Summary returns a summary of network metrics
type MetricsSummary struct {
	Uptime               time.Duration `json:"uptime"`
	PeersConnected       uint64        `json:"peers_connected"`
	PeersDisconnected    uint64        `json:"peers_disconnected"`
	CurrentPeers         int64         `json:"current_peers"`
	MessagesSent         uint64        `json:"messages_sent"`
	MessagesReceived     uint64        `json:"messages_received"`
	MessagesDropped      uint64        `json:"messages_dropped"`
	BytesSent            uint64        `json:"bytes_sent"`
	BytesReceived        uint64        `json:"bytes_received"`
	ValidatorPeers       int64         `json:"validator_peers"`
	TEEPeers             int64         `json:"tee_peers"`
	GPUPeers             int64         `json:"gpu_peers"`
	FPGAPeers            int64         `json:"fpga_peers"`
	ConsensusMessages    uint64        `json:"consensus_messages"`
	VoteExtensions       uint64        `json:"vote_extensions"`
	DAGVertices          uint64        `json:"dag_vertices"`
}

// GetSummary returns a summary of current metrics
func (m *NetworkMetrics) GetSummary() MetricsSummary {
	return MetricsSummary{
		Uptime:            m.Uptime(),
		PeersConnected:    m.PeersConnected.Get(),
		PeersDisconnected: m.PeersDisconnected.Get(),
		CurrentPeers:      m.PeersActive.Get(),
		MessagesSent:      m.MessagesSent.Get(),
		MessagesReceived:  m.MessagesReceived.Get(),
		MessagesDropped:   m.MessagesDropped.Get(),
		BytesSent:         m.BytesSent.Get(),
		BytesReceived:     m.BytesReceived.Get(),
		ValidatorPeers:    m.ValidatorPeers.Get(),
		TEEPeers:          m.TEEPeers.Get(),
		GPUPeers:          m.GPUPeers.Get(),
		FPGAPeers:         m.FPGAPeers.Get(),
		ConsensusMessages: m.ConsensusMessages.Get(),
		VoteExtensions:    m.VoteExtensions.Get(),
		DAGVertices:       m.DAGVertices.Get(),
	}
}

// TopicSummary returns a summary of topic-specific metrics
type TopicSummary struct {
	Name        string `json:"name"`
	Published   uint64 `json:"published"`
	Received    uint64 `json:"received"`
	Rejected    uint64 `json:"rejected"`
	Duplicates  uint64 `json:"duplicates"`
	Subscribers int64  `json:"subscribers"`
}

// GetTopicSummaries returns summaries for all topics
func (m *NetworkMetrics) GetTopicSummaries() []TopicSummary {
	var summaries []TopicSummary
	for _, tm := range m.TopicMetrics {
		summaries = append(summaries, TopicSummary{
			Name:        tm.Name,
			Published:   tm.Published.Get(),
			Received:    tm.Received.Get(),
			Rejected:    tm.Rejected.Get(),
			Duplicates:  tm.Duplicates.Get(),
			Subscribers: tm.SubscriberCount.Get(),
		})
	}
	return summaries
}
