package agent

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Agent registration
// ---------------------------------------------------------------------------

// AgentStatus represents the registration status of an agent.
type AgentStatus int

const (
	AgentActive AgentStatus = iota
	AgentSuspended
	AgentDeregistered
)

// String returns the human-readable label for an AgentStatus.
func (s AgentStatus) String() string {
	switch s {
	case AgentActive:
		return "Active"
	case AgentSuspended:
		return "Suspended"
	case AgentDeregistered:
		return "Deregistered"
	default:
		return "Unknown"
	}
}

// AgentRegistration holds the registry entry for a registered agent.
type AgentRegistration struct {
	// Identity is the agent's verified identity.
	Identity *AgentIdentity `json:"identity"`

	// Status is the current registration status.
	Status AgentStatus `json:"status"`

	// RegisteredAt is when the agent was registered.
	RegisteredAt time.Time `json:"registered_at"`

	// LastSeen is when the agent last communicated.
	LastSeen time.Time `json:"last_seen"`

	// ReputationScore is the agent's current reputation (0.0 to 1.0).
	ReputationScore float64 `json:"reputation_score"`

	// ActionCount tracks the total actions performed by this agent.
	ActionCount int64 `json:"action_count"`

	// SuccessCount tracks successful actions.
	SuccessCount int64 `json:"success_count"`
}

// ---------------------------------------------------------------------------
// AgentRegistry
// ---------------------------------------------------------------------------

// AgentRegistry manages agent registrations and provides discovery services.
type AgentRegistry struct {
	mu     sync.RWMutex
	agents map[string]*AgentRegistration
}

// NewAgentRegistry creates a new AgentRegistry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents: make(map[string]*AgentRegistration),
	}
}

// RegisterAgent registers a new agent with the registry.
func (r *AgentRegistry) RegisterAgent(_ context.Context, identity *AgentIdentity) (*AgentRegistration, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity cannot be nil")
	}

	// Verify identity before registration.
	if err := VerifyIdentity(identity); err != nil {
		return nil, fmt.Errorf("identity verification failed: %w", err)
	}

	agentID := identity.AgentID()

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.agents[agentID]; ok {
		if existing.Status == AgentActive {
			return nil, fmt.Errorf("agent %q is already registered", agentID)
		}
	}

	now := time.Now().UTC()
	reg := &AgentRegistration{
		Identity:        identity,
		Status:          AgentActive,
		RegisteredAt:    now,
		LastSeen:        now,
		ReputationScore: 0.5, // Start with neutral reputation.
	}

	r.agents[agentID] = reg
	return reg, nil
}

// DeregisterAgent marks an agent as deregistered.
func (r *AgentRegistry) DeregisterAgent(_ context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	reg, ok := r.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %q not found", agentID)
	}

	reg.Status = AgentDeregistered
	return nil
}

// SuspendAgent suspends an agent's registration.
func (r *AgentRegistry) SuspendAgent(_ context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	reg, ok := r.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %q not found", agentID)
	}

	reg.Status = AgentSuspended
	return nil
}

// ReactivateAgent reactivates a suspended agent.
func (r *AgentRegistry) ReactivateAgent(_ context.Context, agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	reg, ok := r.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %q not found", agentID)
	}
	if reg.Status != AgentSuspended {
		return fmt.Errorf("agent %q is not suspended (status: %s)", agentID, reg.Status)
	}

	reg.Status = AgentActive
	return nil
}

// LookupAgent returns the registration for a specific agent.
func (r *AgentRegistry) LookupAgent(_ context.Context, agentID string) (*AgentRegistration, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("agent %q not found", agentID)
	}
	return reg, nil
}

// DiscoverAgents finds agents that have a specific capability.
func (r *AgentRegistry) DiscoverAgents(_ context.Context, capabilities []string) []*AgentRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*AgentRegistration
	for _, reg := range r.agents {
		if reg.Status != AgentActive {
			continue
		}
		if matchesCapabilities(reg.Identity, capabilities) {
			result = append(result, reg)
		}
	}
	return result
}

// GetAgentReputation returns the reputation score for an agent.
func (r *AgentRegistry) GetAgentReputation(_ context.Context, agentID string) (float64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reg, ok := r.agents[agentID]
	if !ok {
		return 0, fmt.Errorf("agent %q not found", agentID)
	}
	return reg.ReputationScore, nil
}

// UpdateReputation updates an agent's reputation based on action outcomes.
func (r *AgentRegistry) UpdateReputation(_ context.Context, agentID string, success bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	reg, ok := r.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %q not found", agentID)
	}

	reg.ActionCount++
	if success {
		reg.SuccessCount++
	}
	reg.LastSeen = time.Now().UTC()

	// Compute reputation as a weighted moving average.
	// Reputation = 0.9 * previous + 0.1 * latest outcome.
	outcome := 0.0
	if success {
		outcome = 1.0
	}
	reg.ReputationScore = 0.9*reg.ReputationScore + 0.1*outcome

	// Clamp to [0, 1].
	if reg.ReputationScore < 0 {
		reg.ReputationScore = 0
	}
	if reg.ReputationScore > 1 {
		reg.ReputationScore = 1
	}

	return nil
}

// ListActiveAgents returns all active agent registrations.
func (r *AgentRegistry) ListActiveAgents(_ context.Context) []*AgentRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var active []*AgentRegistration
	for _, reg := range r.agents {
		if reg.Status == AgentActive {
			active = append(active, reg)
		}
	}
	return active
}

// AgentCount returns the total number of registered agents.
func (r *AgentRegistry) AgentCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func matchesCapabilities(identity *AgentIdentity, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, req := range required {
		if !identity.HasCapability(req) {
			return false
		}
	}
	return true
}
