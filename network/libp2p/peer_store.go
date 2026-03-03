// Package libp2p provides peer management for Aethelred network
package libp2p

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerInfo contains information about a peer
type PeerInfo struct {
	ID            peer.ID
	ConnectedAt   time.Time
	LastSeen      time.Time
	Latency       time.Duration
	BytesSent     uint64
	BytesReceived uint64
	IsValidator   bool
	HardwareCaps  *HardwareCaps
	Score         float64
}

// HardwareCaps represents a peer's hardware capabilities
type HardwareCaps struct {
	HasTEE        bool
	TEEPlatform   string // "sgx", "sev-snp", "nitro", "tdx"
	HasGPU        bool
	GPUModel      string
	HasFPGA       bool
	FPGAModel     string
	MemoryGB      uint64
	ComputeScore  float64
}

// PeerStore manages connected peers
type PeerStore struct {
	mu    sync.RWMutex
	peers map[peer.ID]*PeerInfo

	// Validators are tracked separately for fast lookup
	validators    map[peer.ID]*PeerInfo
	validatorsMu  sync.RWMutex
}

// NewPeerStore creates a new peer store
func NewPeerStore() *PeerStore {
	return &PeerStore{
		peers:      make(map[peer.ID]*PeerInfo),
		validators: make(map[peer.ID]*PeerInfo),
	}
}

// AddPeer adds a peer to the store
func (ps *PeerStore) AddPeer(id peer.ID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if _, exists := ps.peers[id]; !exists {
		ps.peers[id] = &PeerInfo{
			ID:          id,
			ConnectedAt: time.Now(),
			LastSeen:    time.Now(),
			Score:       0.5, // Neutral starting score
		}
	}
}

// RemovePeer removes a peer from the store
func (ps *PeerStore) RemovePeer(id peer.ID) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.peers, id)

	ps.validatorsMu.Lock()
	delete(ps.validators, id)
	ps.validatorsMu.Unlock()
}

// GetPeer returns information about a peer
func (ps *PeerStore) GetPeer(id peer.ID) (*PeerInfo, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	info, exists := ps.peers[id]
	return info, exists
}

// UpdatePeer updates peer information
func (ps *PeerStore) UpdatePeer(id peer.ID, update func(*PeerInfo)) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if info, exists := ps.peers[id]; exists {
		update(info)
		info.LastSeen = time.Now()
	}
}

// SetValidator marks a peer as a validator
func (ps *PeerStore) SetValidator(id peer.ID, isValidator bool) {
	ps.mu.Lock()
	info, exists := ps.peers[id]
	ps.mu.Unlock()

	if !exists {
		return
	}

	info.IsValidator = isValidator

	ps.validatorsMu.Lock()
	if isValidator {
		ps.validators[id] = info
	} else {
		delete(ps.validators, id)
	}
	ps.validatorsMu.Unlock()
}

// SetHardwareCaps sets hardware capabilities for a peer
func (ps *PeerStore) SetHardwareCaps(id peer.ID, caps *HardwareCaps) {
	ps.UpdatePeer(id, func(info *PeerInfo) {
		info.HardwareCaps = caps
	})
}

// GetValidators returns all validator peers
func (ps *PeerStore) GetValidators() []*PeerInfo {
	ps.validatorsMu.RLock()
	defer ps.validatorsMu.RUnlock()

	validators := make([]*PeerInfo, 0, len(ps.validators))
	for _, info := range ps.validators {
		validators = append(validators, info)
	}
	return validators
}

// GetPeersWithTEE returns peers with TEE capability
func (ps *PeerStore) GetPeersWithTEE() []*PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var result []*PeerInfo
	for _, info := range ps.peers {
		if info.HardwareCaps != nil && info.HardwareCaps.HasTEE {
			result = append(result, info)
		}
	}
	return result
}

// GetPeersWithGPU returns peers with GPU capability
func (ps *PeerStore) GetPeersWithGPU() []*PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var result []*PeerInfo
	for _, info := range ps.peers {
		if info.HardwareCaps != nil && info.HardwareCaps.HasGPU {
			result = append(result, info)
		}
	}
	return result
}

// GetPeersWithFPGA returns peers with FPGA capability
func (ps *PeerStore) GetPeersWithFPGA() []*PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	var result []*PeerInfo
	for _, info := range ps.peers {
		if info.HardwareCaps != nil && info.HardwareCaps.HasFPGA {
			result = append(result, info)
		}
	}
	return result
}

// UpdateScore updates the score for a peer
func (ps *PeerStore) UpdateScore(id peer.ID, delta float64) {
	ps.UpdatePeer(id, func(info *PeerInfo) {
		info.Score += delta
		// Clamp score to [0, 1]
		if info.Score < 0 {
			info.Score = 0
		} else if info.Score > 1 {
			info.Score = 1
		}
	})
}

// GetTopPeersByScore returns the top N peers by score
func (ps *PeerStore) GetTopPeersByScore(n int) []*PeerInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	peers := make([]*PeerInfo, 0, len(ps.peers))
	for _, info := range ps.peers {
		peers = append(peers, info)
	}

	// Sort by score (descending)
	for i := 0; i < len(peers)-1; i++ {
		for j := i + 1; j < len(peers); j++ {
			if peers[j].Score > peers[i].Score {
				peers[i], peers[j] = peers[j], peers[i]
			}
		}
	}

	if n > len(peers) {
		n = len(peers)
	}
	return peers[:n]
}

// PeerCount returns the number of peers
func (ps *PeerStore) PeerCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.peers)
}

// ValidatorCount returns the number of validator peers
func (ps *PeerStore) ValidatorCount() int {
	ps.validatorsMu.RLock()
	defer ps.validatorsMu.RUnlock()
	return len(ps.validators)
}

// PruneInactive removes peers not seen within the given duration
func (ps *PeerStore) PruneInactive(maxAge time.Duration) int {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for id, info := range ps.peers {
		if info.LastSeen.Before(cutoff) {
			delete(ps.peers, id)
			removed++
		}
	}

	return removed
}
