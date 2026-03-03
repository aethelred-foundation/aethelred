// Package libp2p provides connection management for Aethelred network
package libp2p

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	connmgrimpl "github.com/libp2p/go-libp2p/p2p/net/connmgr"
)

// Priority tags for connection protection
const (
	TagValidator     = "validator"
	TagTEENode       = "tee-node"
	TagComputeWorker = "compute-worker"
	TagDAGParticipant = "dag-participant"
)

// Priority values (higher = more important)
const (
	PriorityValidator     = 1000
	PriorityTEE           = 500
	PriorityComputeWorker = 300
	PriorityDAG           = 200
	PriorityNormal        = 0
)

// newConnManager creates a connection manager for Aethelred
func newConnManager(lowWater, highWater int, gracePeriod time.Duration) connmgr.ConnManager {
	cm, err := connmgrimpl.NewConnManager(
		lowWater,
		highWater,
		connmgrimpl.WithGracePeriod(gracePeriod),
		connmgrimpl.WithSilencePeriod(time.Minute),
	)
	if err != nil {
		// Fall back to basic manager
		return &basicConnManager{
			lowWater:    lowWater,
			highWater:   highWater,
			gracePeriod: gracePeriod,
		}
	}
	return cm
}

// basicConnManager is a fallback connection manager
type basicConnManager struct {
	lowWater    int
	highWater   int
	gracePeriod time.Duration
}

func (m *basicConnManager) TagPeer(peer.ID, string, int)                       {}
func (m *basicConnManager) UntagPeer(peer.ID, string)                          {}
func (m *basicConnManager) UpsertTag(peer.ID, string, func(int) int)           {}
func (m *basicConnManager) GetTagInfo(peer.ID) *connmgr.TagInfo                { return nil }
func (m *basicConnManager) TrimOpenConns(context.Context)                      {}
func (m *basicConnManager) Notifee() network.Notifiee                          { return nil }
func (m *basicConnManager) Protect(peer.ID, string)                            {}
func (m *basicConnManager) Unprotect(peer.ID, string) bool                     { return false }
func (m *basicConnManager) IsProtected(peer.ID, string) bool                   { return false }
func (m *basicConnManager) Close() error                                       { return nil }
func (m *basicConnManager) CheckLimit(_ connmgr.GetConnLimiter) error          { return nil }

// ConnectionPrioritizer manages connection priorities
type ConnectionPrioritizer struct {
	cm connmgr.ConnManager
}

// NewConnectionPrioritizer creates a new connection prioritizer
func NewConnectionPrioritizer(cm connmgr.ConnManager) *ConnectionPrioritizer {
	return &ConnectionPrioritizer{cm: cm}
}

// ProtectValidator marks a peer as a validator with high priority
func (cp *ConnectionPrioritizer) ProtectValidator(id peer.ID) {
	cp.cm.Protect(id, TagValidator)
	cp.cm.TagPeer(id, TagValidator, PriorityValidator)
}

// UnprotectValidator removes validator protection
func (cp *ConnectionPrioritizer) UnprotectValidator(id peer.ID) {
	cp.cm.Unprotect(id, TagValidator)
	cp.cm.UntagPeer(id, TagValidator)
}

// ProtectTEENode marks a peer as a TEE node
func (cp *ConnectionPrioritizer) ProtectTEENode(id peer.ID) {
	cp.cm.Protect(id, TagTEENode)
	cp.cm.TagPeer(id, TagTEENode, PriorityTEE)
}

// UnprotectTEENode removes TEE node protection
func (cp *ConnectionPrioritizer) UnprotectTEENode(id peer.ID) {
	cp.cm.Unprotect(id, TagTEENode)
	cp.cm.UntagPeer(id, TagTEENode)
}

// ProtectComputeWorker marks a peer as a compute worker
func (cp *ConnectionPrioritizer) ProtectComputeWorker(id peer.ID) {
	cp.cm.Protect(id, TagComputeWorker)
	cp.cm.TagPeer(id, TagComputeWorker, PriorityComputeWorker)
}

// UnprotectComputeWorker removes compute worker protection
func (cp *ConnectionPrioritizer) UnprotectComputeWorker(id peer.ID) {
	cp.cm.Unprotect(id, TagComputeWorker)
	cp.cm.UntagPeer(id, TagComputeWorker)
}

// ProtectDAGParticipant marks a peer as a DAG participant
func (cp *ConnectionPrioritizer) ProtectDAGParticipant(id peer.ID) {
	cp.cm.Protect(id, TagDAGParticipant)
	cp.cm.TagPeer(id, TagDAGParticipant, PriorityDAG)
}

// UnprotectDAGParticipant removes DAG participant protection
func (cp *ConnectionPrioritizer) UnprotectDAGParticipant(id peer.ID) {
	cp.cm.Unprotect(id, TagDAGParticipant)
	cp.cm.UntagPeer(id, TagDAGParticipant)
}

// IsValidator checks if a peer is protected as a validator
func (cp *ConnectionPrioritizer) IsValidator(id peer.ID) bool {
	return cp.cm.IsProtected(id, TagValidator)
}

// IsTEENode checks if a peer is protected as a TEE node
func (cp *ConnectionPrioritizer) IsTEENode(id peer.ID) bool {
	return cp.cm.IsProtected(id, TagTEENode)
}

// IsComputeWorker checks if a peer is protected as a compute worker
func (cp *ConnectionPrioritizer) IsComputeWorker(id peer.ID) bool {
	return cp.cm.IsProtected(id, TagComputeWorker)
}

// IsDAGParticipant checks if a peer is protected as a DAG participant
func (cp *ConnectionPrioritizer) IsDAGParticipant(id peer.ID) bool {
	return cp.cm.IsProtected(id, TagDAGParticipant)
}

// UpdateScore adjusts the peer's connection score
func (cp *ConnectionPrioritizer) UpdateScore(id peer.ID, delta int) {
	cp.cm.UpsertTag(id, "score", func(current int) int {
		return current + delta
	})
}
