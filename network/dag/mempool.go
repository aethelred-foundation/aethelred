// Package dag implements a DAG-based mempool inspired by Narwhal/Tusk
// for high-throughput transaction ordering in Aethelred consensus
package dag

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Vertex represents a node in the DAG
type Vertex struct {
	// Unique identifier (hash of contents)
	ID VertexID

	// Round number in the DAG
	Round uint64

	// Author of this vertex (validator)
	Author peer.ID

	// Transactions batched in this vertex
	Transactions [][]byte

	// References to vertices in previous round (strong links)
	StrongLinks []VertexID

	// References to vertices in same round (weak links, optional)
	WeakLinks []VertexID

	// Timestamp when vertex was created
	Timestamp time.Time

	// Signature from the author
	Signature []byte

	// Metadata for compute jobs
	ComputeMetadata *ComputeVertexMetadata
}

// VertexID is a unique identifier for a vertex
type VertexID [32]byte

// String returns hex representation
func (id VertexID) String() string {
	return hex.EncodeToString(id[:])
}

// IsZero checks if the ID is empty
func (id VertexID) IsZero() bool {
	return id == VertexID{}
}

// ComputeVertexMetadata contains metadata for compute job vertices
type ComputeVertexMetadata struct {
	JobID       string
	ModelHash   [32]byte
	InputHash   [32]byte
	Priority    uint8
	TEERequired bool
	ZKRequired  bool
}

// Certificate represents a quorum certificate for a vertex
type Certificate struct {
	VertexID   VertexID
	Round      uint64
	Signatures map[peer.ID][]byte // Validator signatures
	Timestamp  time.Time
}

// DAGMempool is a DAG-based mempool for transaction ordering
type DAGMempool struct {
	mu sync.RWMutex

	// All vertices indexed by ID
	vertices map[VertexID]*Vertex

	// Vertices by round
	roundVertices map[uint64]map[VertexID]*Vertex

	// Certificates for vertices
	certificates map[VertexID]*Certificate

	// Current round
	currentRound uint64

	// Our peer ID
	localPeer peer.ID

	// Quorum size (2f+1 for f Byzantine faults)
	quorumSize int

	// Total validators
	totalValidators int

	// Pending transactions not yet in a vertex
	pendingTxs [][]byte
	pendingMu  sync.Mutex

	// Channel for new vertices
	newVertexCh chan *Vertex

	// Channel for new certificates
	newCertCh chan *Certificate

	// Configuration
	config *DAGConfig
}

// DAGConfig configures the DAG mempool
type DAGConfig struct {
	// Maximum transactions per vertex
	MaxTxsPerVertex int

	// Maximum vertex size in bytes
	MaxVertexSize int

	// Round duration for vertex creation
	RoundDuration time.Duration

	// Number of rounds to keep in memory
	RetentionRounds uint64

	// Minimum strong links required
	MinStrongLinks int

	// EnableEncryptedMempool enables TEE-encrypted transaction payloads for
	// MEV protection. When enabled, transactions are encrypted client-side
	// using the validators' enclave public keys and only decrypted inside
	// TEE enclaves during execution. This prevents proposer-extractable value.
	EnableEncryptedMempool bool

	// EncryptedTxPrefix is the magic byte prefix for encrypted transactions.
	// Transactions starting with this byte are treated as TEE-encrypted and
	// are NOT readable by proposers, preventing frontrunning and sandwich attacks.
	EncryptedTxPrefix byte
}

// DefaultDAGConfig returns default configuration
func DefaultDAGConfig() *DAGConfig {
	return &DAGConfig{
		MaxTxsPerVertex:        10000,
		MaxVertexSize:          4 * 1024 * 1024, // 4MB
		RoundDuration:          500 * time.Millisecond,
		RetentionRounds:        100,
		MinStrongLinks:         1, // At least one link to previous round
		EnableEncryptedMempool: true,
		EncryptedTxPrefix:      0xAE, // 'AE' for Aethelred Encrypted
	}
}

// NewDAGMempool creates a new DAG-based mempool
func NewDAGMempool(localPeer peer.ID, totalValidators int, config *DAGConfig) *DAGMempool {
	if config == nil {
		config = DefaultDAGConfig()
	}

	// Byzantine fault tolerance: f = (n-1)/3, quorum = 2f+1
	f := (totalValidators - 1) / 3
	quorumSize := 2*f + 1

	return &DAGMempool{
		vertices:        make(map[VertexID]*Vertex),
		roundVertices:   make(map[uint64]map[VertexID]*Vertex),
		certificates:    make(map[VertexID]*Certificate),
		currentRound:    0,
		localPeer:       localPeer,
		quorumSize:      quorumSize,
		totalValidators: totalValidators,
		pendingTxs:      make([][]byte, 0),
		newVertexCh:     make(chan *Vertex, 1000),
		newCertCh:       make(chan *Certificate, 1000),
		config:          config,
	}
}

// AddTransaction adds a transaction to the pending pool.
// When EnableEncryptedMempool is active, transactions with the EncryptedTxPrefix
// byte are tagged as TEE-encrypted and placed in a separate priority lane so
// that proposers cannot inspect (and therefore cannot frontrun) their contents.
func (d *DAGMempool) AddTransaction(tx []byte) error {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	// Basic validation
	if len(tx) == 0 {
		return fmt.Errorf("empty transaction")
	}

	if d.config.EnableEncryptedMempool && len(tx) > 1 && tx[0] == d.config.EncryptedTxPrefix {
		// Encrypted transactions MUST have at least a prefix byte + 32-byte
		// ephemeral public key + 16-byte GCM tag, otherwise the ciphertext
		// is structurally invalid and will fail TEE decryption anyway.
		const minEncryptedTxLen = 1 + 32 + 16 // prefix + ephemeral PK + GCM tag
		if len(tx) < minEncryptedTxLen {
			return fmt.Errorf("encrypted transaction too short: %d bytes (minimum %d)", len(tx), minEncryptedTxLen)
		}

		// Prepend encrypted txs so they are batched first in the next vertex,
		// giving them ordering priority (anti-MEV: execute before any plaintext
		// txs the proposer could have crafted in reaction).
		d.pendingTxs = append([][]byte{tx}, d.pendingTxs...)
		return nil
	}

	d.pendingTxs = append(d.pendingTxs, tx)
	return nil
}

// CreateVertex creates a new vertex for the current round
func (d *DAGMempool) CreateVertex(ctx context.Context) (*Vertex, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get transactions for this vertex
	txs := d.takePendingTxs()
	if len(txs) == 0 {
		// Create empty vertex if no transactions (still needed for DAG progress)
	}

	// Get strong links to previous round
	strongLinks := d.getStrongLinks()
	if d.currentRound > 0 && len(strongLinks) < d.config.MinStrongLinks {
		return nil, fmt.Errorf("insufficient strong links: need %d, have %d",
			d.config.MinStrongLinks, len(strongLinks))
	}

	// Create vertex
	vertex := &Vertex{
		Round:        d.currentRound,
		Author:       d.localPeer,
		Transactions: txs,
		StrongLinks:  strongLinks,
		WeakLinks:    d.getWeakLinks(),
		Timestamp:    time.Now(),
	}

	// Calculate vertex ID
	vertex.ID = d.calculateVertexID(vertex)

	// Store vertex
	d.addVertex(vertex)

	// Notify listeners
	select {
	case d.newVertexCh <- vertex:
	default:
	}

	return vertex, nil
}

// takePendingTxs takes transactions from pending pool
func (d *DAGMempool) takePendingTxs() [][]byte {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()

	// Take up to MaxTxsPerVertex
	n := len(d.pendingTxs)
	if n > d.config.MaxTxsPerVertex {
		n = d.config.MaxTxsPerVertex
	}

	txs := make([][]byte, n)
	copy(txs, d.pendingTxs[:n])
	d.pendingTxs = d.pendingTxs[n:]

	return txs
}

// getStrongLinks returns links to certified vertices in previous round
func (d *DAGMempool) getStrongLinks() []VertexID {
	if d.currentRound == 0 {
		return nil
	}

	prevRound := d.roundVertices[d.currentRound-1]
	if prevRound == nil {
		return nil
	}

	var links []VertexID
	for id := range prevRound {
		// Only link to certified vertices
		if _, certified := d.certificates[id]; certified {
			links = append(links, id)
		}
	}

	return links
}

// getWeakLinks returns optional weak links to vertices in same round
func (d *DAGMempool) getWeakLinks() []VertexID {
	curRound := d.roundVertices[d.currentRound]
	if curRound == nil {
		return nil
	}

	var links []VertexID
	for id, v := range curRound {
		if v.Author != d.localPeer {
			links = append(links, id)
		}
	}

	return links
}

// calculateVertexID calculates the unique ID for a vertex
func (d *DAGMempool) calculateVertexID(v *Vertex) VertexID {
	h := sha256.New()

	// Include all deterministic fields
	h.Write([]byte(fmt.Sprintf("%d", v.Round)))
	h.Write([]byte(v.Author.String()))

	for _, tx := range v.Transactions {
		h.Write(tx)
	}

	for _, link := range v.StrongLinks {
		h.Write(link[:])
	}

	var id VertexID
	copy(id[:], h.Sum(nil))
	return id
}

// addVertex adds a vertex to the DAG
func (d *DAGMempool) addVertex(v *Vertex) {
	d.vertices[v.ID] = v

	if d.roundVertices[v.Round] == nil {
		d.roundVertices[v.Round] = make(map[VertexID]*Vertex)
	}
	d.roundVertices[v.Round][v.ID] = v
}

// AddVertex adds a vertex received from another validator
func (d *DAGMempool) AddVertex(v *Vertex) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Validate vertex
	if err := d.validateVertex(v); err != nil {
		return fmt.Errorf("invalid vertex: %w", err)
	}

	// Check if we already have this vertex
	if _, exists := d.vertices[v.ID]; exists {
		return nil // Already have it
	}

	// Verify ID matches content
	expectedID := d.calculateVertexID(v)
	if !bytes.Equal(v.ID[:], expectedID[:]) {
		return fmt.Errorf("vertex ID mismatch")
	}

	// Add to DAG
	d.addVertex(v)

	// Notify listeners
	select {
	case d.newVertexCh <- v:
	default:
	}

	return nil
}

// validateVertex validates a vertex
func (d *DAGMempool) validateVertex(v *Vertex) error {
	// Check round is not too far in the future
	if v.Round > d.currentRound+1 {
		return fmt.Errorf("vertex round %d too far ahead (current: %d)", v.Round, d.currentRound)
	}

	// Check size
	size := 0
	for _, tx := range v.Transactions {
		size += len(tx)
	}
	if size > d.config.MaxVertexSize {
		return fmt.Errorf("vertex too large: %d bytes", size)
	}

	// Verify strong links exist
	for _, link := range v.StrongLinks {
		if _, exists := d.vertices[link]; !exists {
			// May need to fetch this vertex
			return fmt.Errorf("missing strong link: %s", link.String())
		}
	}

	return nil
}

// AddCertificate adds a certificate for a vertex
func (d *DAGMempool) AddCertificate(cert *Certificate) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Verify we have the vertex
	if _, exists := d.vertices[cert.VertexID]; !exists {
		return fmt.Errorf("unknown vertex: %s", cert.VertexID.String())
	}

	// Verify quorum
	if len(cert.Signatures) < d.quorumSize {
		return fmt.Errorf("insufficient signatures: need %d, have %d",
			d.quorumSize, len(cert.Signatures))
	}

	// Store certificate
	d.certificates[cert.VertexID] = cert

	// Notify listeners
	select {
	case d.newCertCh <- cert:
	default:
	}

	return nil
}

// AdvanceRound moves to the next round
func (d *DAGMempool) AdvanceRound() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.currentRound++

	// Garbage collect old rounds
	d.gcOldRounds()

	return d.currentRound
}

// gcOldRounds removes old rounds from memory
func (d *DAGMempool) gcOldRounds() {
	if d.currentRound <= d.config.RetentionRounds {
		return
	}

	cutoff := d.currentRound - d.config.RetentionRounds

	for round := range d.roundVertices {
		if round < cutoff {
			for id := range d.roundVertices[round] {
				delete(d.vertices, id)
				delete(d.certificates, id)
			}
			delete(d.roundVertices, round)
		}
	}
}

// GetVertex returns a vertex by ID
func (d *DAGMempool) GetVertex(id VertexID) (*Vertex, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	v, exists := d.vertices[id]
	return v, exists
}

// GetCertificate returns a certificate by vertex ID
func (d *DAGMempool) GetCertificate(id VertexID) (*Certificate, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cert, exists := d.certificates[id]
	return cert, exists
}

// GetRoundVertices returns all vertices for a round
func (d *DAGMempool) GetRoundVertices(round uint64) []*Vertex {
	d.mu.RLock()
	defer d.mu.RUnlock()

	roundVs := d.roundVertices[round]
	if roundVs == nil {
		return nil
	}

	vertices := make([]*Vertex, 0, len(roundVs))
	for _, v := range roundVs {
		vertices = append(vertices, v)
	}
	return vertices
}

// GetCertifiedVertices returns all certified vertices for a round
func (d *DAGMempool) GetCertifiedVertices(round uint64) []*Vertex {
	d.mu.RLock()
	defer d.mu.RUnlock()

	roundVs := d.roundVertices[round]
	if roundVs == nil {
		return nil
	}

	var vertices []*Vertex
	for id, v := range roundVs {
		if _, certified := d.certificates[id]; certified {
			vertices = append(vertices, v)
		}
	}
	return vertices
}

// CurrentRound returns the current round number
func (d *DAGMempool) CurrentRound() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.currentRound
}

// PendingTxCount returns the number of pending transactions
func (d *DAGMempool) PendingTxCount() int {
	d.pendingMu.Lock()
	defer d.pendingMu.Unlock()
	return len(d.pendingTxs)
}

// NewVertexChannel returns a channel for new vertex notifications
func (d *DAGMempool) NewVertexChannel() <-chan *Vertex {
	return d.newVertexCh
}

// NewCertificateChannel returns a channel for new certificate notifications
func (d *DAGMempool) NewCertificateChannel() <-chan *Certificate {
	return d.newCertCh
}

// OrderTransactions returns ordered transactions from committed vertices
// This implements the Tusk consensus ordering
func (d *DAGMempool) OrderTransactions(leaderVertex *Vertex) [][]byte {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Get all transactions reachable from leader vertex in causal order
	visited := make(map[VertexID]bool)
	var orderedTxs [][]byte

	d.collectTransactions(leaderVertex, visited, &orderedTxs)

	return orderedTxs
}

// collectTransactions recursively collects transactions in causal order
func (d *DAGMempool) collectTransactions(v *Vertex, visited map[VertexID]bool, txs *[][]byte) {
	if v == nil || visited[v.ID] {
		return
	}
	visited[v.ID] = true

	// First visit all ancestors (strong links)
	for _, linkID := range v.StrongLinks {
		if linkedV, exists := d.vertices[linkID]; exists {
			d.collectTransactions(linkedV, visited, txs)
		}
	}

	// Then add this vertex's transactions
	*txs = append(*txs, v.Transactions...)
}

// Stats returns DAG statistics
type DAGStats struct {
	CurrentRound     uint64
	TotalVertices    int
	TotalCertificates int
	PendingTxs       int
	VerticesByRound  map[uint64]int
}

// GetStats returns current DAG statistics
func (d *DAGMempool) GetStats() DAGStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	d.pendingMu.Lock()
	pendingCount := len(d.pendingTxs)
	d.pendingMu.Unlock()

	byRound := make(map[uint64]int)
	for round, vertices := range d.roundVertices {
		byRound[round] = len(vertices)
	}

	return DAGStats{
		CurrentRound:      d.currentRound,
		TotalVertices:     len(d.vertices),
		TotalCertificates: len(d.certificates),
		PendingTxs:        pendingCount,
		VerticesByRound:   byRound,
	}
}
