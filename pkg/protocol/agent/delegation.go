package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Delegation constants
// ---------------------------------------------------------------------------

// MaxDelegationDepth is the maximum allowed depth for delegation chains.
// This prevents infinite delegation and limits the blast radius of compromised
// agent credentials.
const MaxDelegationDepth = 5

// ---------------------------------------------------------------------------
// Delegation types
// ---------------------------------------------------------------------------

// DelegationScope defines the boundaries of a delegation.
type DelegationScope struct {
	// Actions lists the actions the delegate can perform.
	Actions []string `json:"actions,omitempty"`

	// Resources lists the resources the delegate can access.
	Resources []string `json:"resources,omitempty"`

	// Sectors limits the delegation to specific sectors.
	Sectors []string `json:"sectors,omitempty"`

	// MaxDepth is the maximum re-delegation depth allowed (0 = no re-delegation).
	MaxDepth int `json:"max_depth"`

	// TimeLimit is the maximum duration for this delegation.
	TimeLimit time.Duration `json:"time_limit,omitempty"`
}

// DelegationConstraintType classifies delegation constraints.
type DelegationConstraintType string

const (
	ConstraintMaxAmount  DelegationConstraintType = "max_amount"
	ConstraintMaxCount   DelegationConstraintType = "max_count"
	ConstraintTimeWindow DelegationConstraintType = "time_window"
	ConstraintIPRange    DelegationConstraintType = "ip_range"
	ConstraintCustom     DelegationConstraintType = "custom"
)

// DelegationConstraint is a condition that must hold for the delegation to be valid.
type DelegationConstraint struct {
	Type     DelegationConstraintType `json:"type"`
	Value    string                   `json:"value"`
	Operator string                   `json:"operator"`
}

// ---------------------------------------------------------------------------
// DelegationChain
// ---------------------------------------------------------------------------

// DelegationChain represents a delegation of authority from one agent to another.
type DelegationChain struct {
	// ID is the unique delegation identifier.
	ID string `json:"id"`

	// Delegator is the DID of the agent granting authority.
	Delegator string `json:"delegator"`

	// Delegate is the DID of the agent receiving authority.
	Delegate string `json:"delegate"`

	// Scope defines what the delegate is authorized to do.
	Scope *DelegationScope `json:"scope"`

	// Constraints are additional conditions on the delegation.
	Constraints []DelegationConstraint `json:"constraints,omitempty"`

	// Depth is the current depth in the delegation chain (0 = root).
	Depth int `json:"depth"`

	// ParentID is the ID of the parent delegation (empty for root).
	ParentID string `json:"parent_id,omitempty"`

	// ChildIDs lists any sub-delegations created from this one.
	ChildIDs []string `json:"child_ids,omitempty"`

	// CreatedAt is when the delegation was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the delegation expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Revoked indicates whether the delegation has been revoked.
	Revoked bool `json:"revoked"`

	// RevokedAt is when the delegation was revoked.
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

// IsDelegationValid checks whether a delegation is currently valid
// (not expired, not revoked, and within depth limits).
func IsDelegationValid(d *DelegationChain) bool {
	if d == nil {
		return false
	}
	if d.Revoked {
		return false
	}
	if !d.ExpiresAt.IsZero() && time.Now().After(d.ExpiresAt) {
		return false
	}
	if d.Depth > MaxDelegationDepth {
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// DelegationManager
// ---------------------------------------------------------------------------

// DelegationManager manages the lifecycle of delegation chains.
type DelegationManager struct {
	mu          sync.RWMutex
	delegations map[string]*DelegationChain
}

// NewDelegationManager creates a new DelegationManager.
func NewDelegationManager() *DelegationManager {
	return &DelegationManager{
		delegations: make(map[string]*DelegationChain),
	}
}

// Delegate creates a new delegation from delegator to delegate.
func (dm *DelegationManager) Delegate(_ context.Context, delegator, delegate string, scope *DelegationScope, constraints []DelegationConstraint) (*DelegationChain, error) {
	if delegator == "" || delegate == "" {
		return nil, fmt.Errorf("DelegationManager.Delegate: %w: delegator and delegate DIDs are required", ErrInvalidInput)
	}
	if delegator == delegate {
		return nil, fmt.Errorf("DelegationManager.Delegate: %w: cannot delegate to self", ErrInvalidInput)
	}
	if scope == nil {
		return nil, fmt.Errorf("DelegationManager.Delegate: %w: delegation scope is required", ErrInvalidInput)
	}

	now := time.Now().UTC()
	expiresAt := time.Time{}
	if scope.TimeLimit > 0 {
		expiresAt = now.Add(scope.TimeLimit)
	}

	d := &DelegationChain{
		ID:          uuid.New().String(),
		Delegator:   delegator,
		Delegate:    delegate,
		Scope:       scope,
		Constraints: constraints,
		Depth:       0,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.delegations[d.ID] = d

	return d, nil
}

// SubDelegate creates a sub-delegation from an existing delegation. The depth
// is incremented and the scope is narrowed (cannot exceed parent scope).
func (dm *DelegationManager) SubDelegate(_ context.Context, parentID, delegate string, scope *DelegationScope, constraints []DelegationConstraint) (*DelegationChain, error) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	parent, ok := dm.delegations[parentID]
	if !ok {
		return nil, fmt.Errorf("parent delegation %q not found", parentID)
	}

	if !IsDelegationValid(parent) {
		return nil, fmt.Errorf("parent delegation is not valid")
	}

	newDepth := parent.Depth + 1
	if newDepth > MaxDelegationDepth {
		return nil, fmt.Errorf("DelegationManager.SubDelegate: %w: depth %d exceeds maximum of %d", ErrDelegationDepthExceeded, newDepth, MaxDelegationDepth)
	}

	// Check if parent scope allows re-delegation.
	if parent.Scope.MaxDepth > 0 && newDepth > parent.Scope.MaxDepth {
		return nil, fmt.Errorf("delegation depth %d exceeds parent max_depth of %d", newDepth, parent.Scope.MaxDepth)
	}

	if scope == nil {
		scope = parent.Scope
	}

	now := time.Now().UTC()
	expiresAt := parent.ExpiresAt
	if scope.TimeLimit > 0 {
		candidateExpiry := now.Add(scope.TimeLimit)
		if expiresAt.IsZero() || candidateExpiry.Before(expiresAt) {
			expiresAt = candidateExpiry
		}
	}

	d := &DelegationChain{
		ID:          uuid.New().String(),
		Delegator:   parent.Delegate,
		Delegate:    delegate,
		Scope:       scope,
		Constraints: constraints,
		Depth:       newDepth,
		ParentID:    parentID,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}

	parent.ChildIDs = append(parent.ChildIDs, d.ID)
	dm.delegations[d.ID] = d

	return d, nil
}

// VerifyDelegation checks whether a delegation covers a specific action.
func (dm *DelegationManager) VerifyDelegation(_ context.Context, delegationID, action string) (bool, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	d, ok := dm.delegations[delegationID]
	if !ok {
		return false, fmt.Errorf("delegation %q not found", delegationID)
	}

	if !IsDelegationValid(d) {
		return false, fmt.Errorf("delegation is not valid")
	}

	// Check if action is within scope.
	if len(d.Scope.Actions) > 0 {
		found := false
		for _, a := range d.Scope.Actions {
			if a == action {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	// Verify the entire chain is valid (walk up to root).
	return dm.verifyChainFromLocked(d)
}

// RevokeDelegation revokes a delegation and all its children (cascading revocation).
func (dm *DelegationManager) RevokeDelegation(_ context.Context, delegationID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	return dm.revokeRecursive(delegationID)
}

// GetDelegation returns a delegation by ID.
func (dm *DelegationManager) GetDelegation(_ context.Context, delegationID string) (*DelegationChain, error) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	d, ok := dm.delegations[delegationID]
	if !ok {
		return nil, fmt.Errorf("delegation %q not found", delegationID)
	}
	return d, nil
}

// GetDelegationChain returns the full delegation chain for an agent (as delegate).
func (dm *DelegationManager) GetDelegationChain(_ context.Context, agentDID string) []*DelegationChain {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	var chain []*DelegationChain
	for _, d := range dm.delegations {
		if d.Delegate == agentDID && !d.Revoked {
			chain = append(chain, d)
		}
	}
	return chain
}

// GetDelegationsGranted returns all delegations granted by an agent (as delegator).
func (dm *DelegationManager) GetDelegationsGranted(_ context.Context, agentDID string) []*DelegationChain {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	var delegations []*DelegationChain
	for _, d := range dm.delegations {
		if d.Delegator == agentDID && !d.Revoked {
			delegations = append(delegations, d)
		}
	}
	return delegations
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (dm *DelegationManager) revokeRecursive(id string) error {
	d, ok := dm.delegations[id]
	if !ok {
		return fmt.Errorf("delegation %q not found", id)
	}

	if d.Revoked {
		return nil // Already revoked.
	}

	now := time.Now().UTC()
	d.Revoked = true
	d.RevokedAt = now

	// Cascade to children.
	for _, childID := range d.ChildIDs {
		dm.revokeRecursive(childID) //nolint:errcheck // best-effort cascade
	}

	return nil
}

func (dm *DelegationManager) verifyChainFromLocked(d *DelegationChain) (bool, error) {
	current := d
	visited := make(map[string]bool)

	for current != nil {
		if visited[current.ID] {
			return false, fmt.Errorf("circular delegation detected")
		}
		visited[current.ID] = true

		if !IsDelegationValid(current) {
			return false, nil
		}

		if current.ParentID == "" {
			return true, nil // Reached root, all valid.
		}

		parent, ok := dm.delegations[current.ParentID]
		if !ok {
			return false, fmt.Errorf("parent delegation %q not found in chain", current.ParentID)
		}
		current = parent
	}

	return true, nil
}
