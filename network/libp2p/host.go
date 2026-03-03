// Package libp2p provides the networking layer for Aethelred L1
// implementing LibP2P with GossipSub pubsub as specified in MTS
package libp2p

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
)

const (
	// Protocol IDs for Aethelred
	ProtocolIDConsensus    = protocol.ID("/aethelred/consensus/1.0.0")
	ProtocolIDSync         = protocol.ID("/aethelred/sync/1.0.0")
	ProtocolIDCompute      = protocol.ID("/aethelred/compute/1.0.0")
	ProtocolIDAttestation  = protocol.ID("/aethelred/attestation/1.0.0")
	ProtocolIDDAG          = protocol.ID("/aethelred/dag/1.0.0")

	// GossipSub topic names
	TopicConsensusVotes    = "aethelred/consensus/votes"
	TopicComputeJobs       = "aethelred/compute/jobs"
	TopicAttestations      = "aethelred/attestations"
	TopicDAGVertices       = "aethelred/dag/vertices"
	TopicSealBroadcast     = "aethelred/seals"

	// Discovery service tag
	MDNSServiceTag = "aethelred-discovery"

	// Connection limits
	MaxPeers        = 100
	MinPeers        = 10
	TargetPeers     = 50
)

// AethelredHost wraps libp2p host with Aethelred-specific functionality
type AethelredHost struct {
	host.Host
	ctx         context.Context
	cancel      context.CancelFunc

	// Kademlia DHT for peer discovery
	dht         *dht.IpfsDHT

	// GossipSub pubsub system
	pubsub      *pubsub.PubSub

	// Subscribed topics
	topics      map[string]*pubsub.Topic
	subs        map[string]*pubsub.Subscription
	topicsMu    sync.RWMutex

	// Message handlers
	handlers    map[string]MessageHandler
	handlersMu  sync.RWMutex

	// Peer management
	peerStore   *PeerStore

	// Metrics
	metrics     *NetworkMetrics

	// Logger
	logger      Logger
}

// Logger interface for network logging
type Logger interface {
	Info(msg string, keyvals ...interface{})
	Error(msg string, keyvals ...interface{})
	Debug(msg string, keyvals ...interface{})
}

// MessageHandler handles incoming pubsub messages
type MessageHandler func(ctx context.Context, msg *pubsub.Message) error

// HostConfig configures the Aethelred network host
type HostConfig struct {
	// Network identity
	PrivateKey    crypto.PrivKey
	ListenAddrs   []multiaddr.Multiaddr

	// Bootstrap peers for initial discovery
	BootstrapPeers []peer.AddrInfo

	// Enable mDNS for local discovery (development)
	EnableMDNS     bool

	// Connection manager settings
	LowWatermark   int
	HighWatermark  int
	GracePeriod    time.Duration

	// GossipSub settings
	GossipSubParams *pubsub.GossipSubParams

	// Logger
	Logger         Logger
}

// DefaultConfig returns a default host configuration
func DefaultConfig() *HostConfig {
	// Generate random private key if not provided
	priv, _, _ := crypto.GenerateEd25519Key(rand.Reader)

	// Default listen addresses
	listenAddrs := []multiaddr.Multiaddr{
		mustMultiaddr("/ip4/0.0.0.0/tcp/26656"),
		mustMultiaddr("/ip4/0.0.0.0/udp/26656/quic-v1"),
	}

	return &HostConfig{
		PrivateKey:     priv,
		ListenAddrs:    listenAddrs,
		BootstrapPeers: []peer.AddrInfo{},
		EnableMDNS:     true,
		LowWatermark:   MinPeers,
		HighWatermark:  MaxPeers,
		GracePeriod:    time.Minute,
		Logger:         &noopLogger{},
	}
}

// NewHost creates a new Aethelred network host
func NewHost(ctx context.Context, cfg *HostConfig) (*AethelredHost, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Build libp2p options
	opts := []libp2p.Option{
		libp2p.Identity(cfg.PrivateKey),
		libp2p.ListenAddrs(cfg.ListenAddrs...),

		// Security: TLS and Noise
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Security(noise.ID, noise.New),

		// Enable NAT traversal
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{}),

		// Connection manager
		libp2p.ConnectionManager(newConnManager(
			cfg.LowWatermark,
			cfg.HighWatermark,
			cfg.GracePeriod,
		)),

		// Enable QUIC transport for better performance
		libp2p.DefaultTransports,
	}

	// Create libp2p host
	h, err := libp2p.New(opts...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	// Create Kademlia DHT
	kadDHT, err := dht.New(ctx, h, dht.Mode(dht.ModeAutoServer))
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	// Create GossipSub with custom parameters
	gsParams := pubsub.DefaultGossipSubParams()
	if cfg.GossipSubParams != nil {
		gsParams = *cfg.GossipSubParams
	}

	// Configure GossipSub for Aethelred's requirements
	gsParams.D = 8                  // Desired outbound degree
	gsParams.Dlo = 6                // Lower bound for outbound degree
	gsParams.Dhi = 12               // Upper bound for outbound degree
	gsParams.Dscore = 6             // Outbound degree for scoring
	gsParams.Dout = 2               // Outbound quota for GossipSub
	gsParams.HeartbeatInterval = 700 * time.Millisecond
	gsParams.SlowHeartbeatWarning = 0.1

	ps, err := pubsub.NewGossipSub(ctx, h,
		pubsub.WithGossipSubParams(gsParams),
		pubsub.WithMessageSignaturePolicy(pubsub.StrictSign),
		pubsub.WithPeerExchange(true),
		pubsub.WithFloodPublish(true),
	)
	if err != nil {
		kadDHT.Close()
		h.Close()
		cancel()
		return nil, fmt.Errorf("failed to create GossipSub: %w", err)
	}

	ah := &AethelredHost{
		Host:      h,
		ctx:       ctx,
		cancel:    cancel,
		dht:       kadDHT,
		pubsub:    ps,
		topics:    make(map[string]*pubsub.Topic),
		subs:      make(map[string]*pubsub.Subscription),
		handlers:  make(map[string]MessageHandler),
		peerStore: NewPeerStore(),
		metrics:   NewNetworkMetrics(),
		logger:    cfg.Logger,
	}

	// Set up connection notifier
	h.Network().Notify(&networkNotifier{host: ah})

	// Bootstrap DHT
	if err := kadDHT.Bootstrap(ctx); err != nil {
		ah.Close()
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// Connect to bootstrap peers
	for _, pinfo := range cfg.BootstrapPeers {
		if err := h.Connect(ctx, pinfo); err != nil {
			cfg.Logger.Error("failed to connect to bootstrap peer", "peer", pinfo.ID, "error", err)
		}
	}

	// Enable mDNS discovery for local networks
	if cfg.EnableMDNS {
		if err := setupMDNS(ah); err != nil {
			cfg.Logger.Error("failed to setup mDNS", "error", err)
		}
	}

	cfg.Logger.Info("Aethelred network host started",
		"peer_id", h.ID().String(),
		"listen_addrs", h.Addrs(),
	)

	return ah, nil
}

// Subscribe subscribes to a GossipSub topic and sets a handler
func (h *AethelredHost) Subscribe(topicName string, handler MessageHandler) error {
	h.topicsMu.Lock()
	defer h.topicsMu.Unlock()

	// Join topic if not already joined
	topic, exists := h.topics[topicName]
	if !exists {
		var err error
		topic, err = h.pubsub.Join(topicName)
		if err != nil {
			return fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}
		h.topics[topicName] = topic
	}

	// Subscribe to topic
	sub, err := topic.Subscribe()
	if err != nil {
		return fmt.Errorf("failed to subscribe to topic %s: %w", topicName, err)
	}
	h.subs[topicName] = sub

	// Set handler
	h.handlersMu.Lock()
	h.handlers[topicName] = handler
	h.handlersMu.Unlock()

	// Start message handling goroutine
	go h.handleMessages(topicName, sub)

	h.logger.Info("subscribed to topic", "topic", topicName)
	return nil
}

// Publish publishes a message to a GossipSub topic
func (h *AethelredHost) Publish(ctx context.Context, topicName string, data []byte) error {
	h.topicsMu.RLock()
	topic, exists := h.topics[topicName]
	h.topicsMu.RUnlock()

	if !exists {
		// Join topic if not subscribed
		h.topicsMu.Lock()
		var err error
		topic, err = h.pubsub.Join(topicName)
		if err != nil {
			h.topicsMu.Unlock()
			return fmt.Errorf("failed to join topic %s: %w", topicName, err)
		}
		h.topics[topicName] = topic
		h.topicsMu.Unlock()
	}

	if err := topic.Publish(ctx, data); err != nil {
		return fmt.Errorf("failed to publish to topic %s: %w", topicName, err)
	}

	h.metrics.MessagesSent.Inc()
	return nil
}

// handleMessages processes incoming messages for a topic
func (h *AethelredHost) handleMessages(topicName string, sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(h.ctx)
		if err != nil {
			if h.ctx.Err() != nil {
				return // Context cancelled
			}
			h.logger.Error("error receiving message", "topic", topicName, "error", err)
			continue
		}

		// Skip messages from self
		if msg.ReceivedFrom == h.ID() {
			continue
		}

		h.metrics.MessagesReceived.Inc()

		// Get handler
		h.handlersMu.RLock()
		handler, exists := h.handlers[topicName]
		h.handlersMu.RUnlock()

		if !exists {
			continue
		}

		// Handle message
		if err := handler(h.ctx, msg); err != nil {
			h.logger.Error("error handling message", "topic", topicName, "error", err)
		}
	}
}

// RegisterProtocolHandler registers a handler for a protocol
func (h *AethelredHost) RegisterProtocolHandler(pid protocol.ID, handler network.StreamHandler) {
	h.SetStreamHandler(pid, handler)
}

// OpenStream opens a stream to a peer for a specific protocol
func (h *AethelredHost) OpenStream(ctx context.Context, pid peer.ID, proto protocol.ID) (network.Stream, error) {
	return h.NewStream(ctx, pid, proto)
}

// FindPeers finds peers that are subscribed to a topic
func (h *AethelredHost) FindPeers(topicName string) []peer.ID {
	h.topicsMu.RLock()
	topic, exists := h.topics[topicName]
	h.topicsMu.RUnlock()

	if !exists {
		return nil
	}

	return topic.ListPeers()
}

// ConnectedPeers returns all connected peers
func (h *AethelredHost) ConnectedPeers() []peer.ID {
	return h.Network().Peers()
}

// PeerCount returns the number of connected peers
func (h *AethelredHost) PeerCount() int {
	return len(h.Network().Peers())
}

// GetMetrics returns network metrics
func (h *AethelredHost) GetMetrics() *NetworkMetrics {
	return h.metrics
}

// Close shuts down the host
func (h *AethelredHost) Close() error {
	h.cancel()

	// Unsubscribe from all topics
	h.topicsMu.Lock()
	for _, sub := range h.subs {
		sub.Cancel()
	}
	for _, topic := range h.topics {
		topic.Close()
	}
	h.topicsMu.Unlock()

	// Close DHT
	if err := h.dht.Close(); err != nil {
		h.logger.Error("error closing DHT", "error", err)
	}

	// Close host
	return h.Host.Close()
}

// networkNotifier handles network events
type networkNotifier struct {
	host *AethelredHost
}

func (n *networkNotifier) Listen(network.Network, multiaddr.Multiaddr)      {}
func (n *networkNotifier) ListenClose(network.Network, multiaddr.Multiaddr) {}

func (n *networkNotifier) Connected(_ network.Network, conn network.Conn) {
	n.host.logger.Debug("peer connected", "peer", conn.RemotePeer())
	n.host.metrics.PeersConnected.Inc()
	n.host.peerStore.AddPeer(conn.RemotePeer())
}

func (n *networkNotifier) Disconnected(_ network.Network, conn network.Conn) {
	n.host.logger.Debug("peer disconnected", "peer", conn.RemotePeer())
	n.host.metrics.PeersDisconnected.Inc()
	n.host.peerStore.RemovePeer(conn.RemotePeer())
}

// mDNS discovery notifee
type mdnsNotifee struct {
	host *AethelredHost
}

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	m.host.logger.Debug("discovered peer via mDNS", "peer", pi.ID)
	if err := m.host.Connect(m.host.ctx, pi); err != nil {
		m.host.logger.Error("failed to connect to mDNS peer", "peer", pi.ID, "error", err)
	}
}

func setupMDNS(h *AethelredHost) error {
	s := mdns.NewMdnsService(h.Host, MDNSServiceTag, &mdnsNotifee{host: h})
	return s.Start()
}

// Helper functions

func mustMultiaddr(s string) multiaddr.Multiaddr {
	addr, err := multiaddr.NewMultiaddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

// noopLogger is a no-op logger implementation
type noopLogger struct{}

func (l *noopLogger) Info(msg string, keyvals ...interface{})  {}
func (l *noopLogger) Error(msg string, keyvals ...interface{}) {}
func (l *noopLogger) Debug(msg string, keyvals ...interface{}) {}
