package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Negotiation status
// ---------------------------------------------------------------------------

// NegotiationStatus tracks the lifecycle of a trust negotiation session.
type NegotiationStatus int

const (
	// NegotiationInitiated means the session has been created.
	NegotiationInitiated NegotiationStatus = iota

	// NegotiationCredentialExchange means credentials are being exchanged.
	NegotiationCredentialExchange

	// NegotiationPolicyAlignment means parties are aligning on policy.
	NegotiationPolicyAlignment

	// NegotiationAgreed means both parties have agreed on terms.
	NegotiationAgreed

	// NegotiationFailed means the negotiation failed.
	NegotiationFailed
)

// String returns the human-readable label for a NegotiationStatus.
func (s NegotiationStatus) String() string {
	switch s {
	case NegotiationInitiated:
		return "Initiated"
	case NegotiationCredentialExchange:
		return "CredentialExchange"
	case NegotiationPolicyAlignment:
		return "PolicyAlignment"
	case NegotiationAgreed:
		return "Agreed"
	case NegotiationFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// NegotiationRequirements
// ---------------------------------------------------------------------------

// NegotiationRequirements defines what one party requires from the other.
type NegotiationRequirements struct {
	// RequiredCredentials lists credential types the other party must present.
	RequiredCredentials []CredentialType `json:"required_credentials"`

	// RequiredCapabilities lists capabilities the other party must have.
	RequiredCapabilities []string `json:"required_capabilities"`

	// MinReputationScore is the minimum acceptable reputation score.
	MinReputationScore float64 `json:"min_reputation_score"`
}

// ---------------------------------------------------------------------------
// NegotiationSession
// ---------------------------------------------------------------------------

// NegotiationSession represents an ongoing trust negotiation between two agents.
type NegotiationSession struct {
	// ID is the unique session identifier.
	ID string `json:"id"`

	// Initiator is the DID of the agent that started the negotiation.
	Initiator string `json:"initiator"`

	// Responder is the DID of the other agent.
	Responder string `json:"responder"`

	// Status tracks the current phase.
	Status NegotiationStatus `json:"status"`

	// InitiatorRequirements are what the initiator requires.
	InitiatorRequirements *NegotiationRequirements `json:"initiator_requirements,omitempty"`

	// ResponderRequirements are what the responder requires.
	ResponderRequirements *NegotiationRequirements `json:"responder_requirements,omitempty"`

	// ExchangedCredentials tracks which credentials have been exchanged.
	ExchangedCredentials []*AgentCredential `json:"exchanged_credentials,omitempty"`

	// AgreedPolicy is the policy both parties agreed to operate under.
	AgreedPolicy *AuthorizationPolicy `json:"agreed_policy,omitempty"`

	// ProposedPolicy is a policy proposed during alignment.
	ProposedPolicy *AuthorizationPolicy `json:"proposed_policy,omitempty"`

	// ProposedBy is the DID of who proposed the current policy.
	ProposedBy string `json:"proposed_by,omitempty"`

	// StartedAt is when the negotiation started.
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the negotiation concluded.
	CompletedAt time.Time `json:"completed_at,omitempty"`

	// FailureReason explains why the negotiation failed (if Status is Failed).
	FailureReason string `json:"failure_reason,omitempty"`
}

// ---------------------------------------------------------------------------
// NegotiationManager
// ---------------------------------------------------------------------------

// NegotiationManager manages trust negotiation sessions between agents.
type NegotiationManager struct {
	mu       sync.RWMutex
	sessions map[string]*NegotiationSession
}

// NewNegotiationManager creates a new NegotiationManager.
func NewNegotiationManager() *NegotiationManager {
	return &NegotiationManager{
		sessions: make(map[string]*NegotiationSession),
	}
}

// InitiateNegotiation starts a trust negotiation session.
func (nm *NegotiationManager) InitiateNegotiation(_ context.Context, initiator, responder string, requirements *NegotiationRequirements) (*NegotiationSession, error) {
	if initiator == "" || responder == "" {
		return nil, fmt.Errorf("initiator and responder DIDs are required")
	}
	if initiator == responder {
		return nil, fmt.Errorf("cannot negotiate with self")
	}

	session := &NegotiationSession{
		ID:                    uuid.New().String(),
		Initiator:             initiator,
		Responder:             responder,
		Status:                NegotiationInitiated,
		InitiatorRequirements: requirements,
		StartedAt:             time.Now().UTC(),
	}

	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.sessions[session.ID] = session

	return session, nil
}

// ExchangeCredentials adds credentials to a negotiation session.
func (nm *NegotiationManager) ExchangeCredentials(_ context.Context, sessionID string, credentials []*AgentCredential) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("negotiation session %q not found", sessionID)
	}

	if session.Status == NegotiationAgreed || session.Status == NegotiationFailed {
		return fmt.Errorf("negotiation session is in terminal state: %s", session.Status)
	}

	session.ExchangedCredentials = append(session.ExchangedCredentials, credentials...)
	session.Status = NegotiationCredentialExchange

	return nil
}

// SetResponderRequirements sets the responder's requirements.
func (nm *NegotiationManager) SetResponderRequirements(_ context.Context, sessionID string, requirements *NegotiationRequirements) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("negotiation session %q not found", sessionID)
	}

	session.ResponderRequirements = requirements
	return nil
}

// ProposePolicy proposes an operating policy for the session.
func (nm *NegotiationManager) ProposePolicy(_ context.Context, sessionID string, proposer string, policy *AuthorizationPolicy) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("negotiation session %q not found", sessionID)
	}

	if session.Status == NegotiationAgreed || session.Status == NegotiationFailed {
		return fmt.Errorf("negotiation session is in terminal state: %s", session.Status)
	}

	session.ProposedPolicy = policy
	session.ProposedBy = proposer
	session.Status = NegotiationPolicyAlignment

	return nil
}

// AcceptPolicy accepts the proposed policy, completing the negotiation.
func (nm *NegotiationManager) AcceptPolicy(_ context.Context, sessionID string, accepter string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("negotiation session %q not found", sessionID)
	}

	if session.Status != NegotiationPolicyAlignment {
		return fmt.Errorf("no policy has been proposed (status: %s)", session.Status)
	}

	// The accepter cannot be the same as the proposer.
	if accepter == session.ProposedBy {
		return fmt.Errorf("policy proposer cannot accept their own proposal")
	}

	session.AgreedPolicy = session.ProposedPolicy
	session.Status = NegotiationAgreed
	session.CompletedAt = time.Now().UTC()

	return nil
}

// RejectPolicy rejects the proposed policy.
func (nm *NegotiationManager) RejectPolicy(_ context.Context, sessionID string, reason string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("negotiation session %q not found", sessionID)
	}

	if session.Status != NegotiationPolicyAlignment {
		return fmt.Errorf("no policy to reject (status: %s)", session.Status)
	}

	// Reset to credential exchange phase for counter-proposal.
	session.ProposedPolicy = nil
	session.ProposedBy = ""
	session.Status = NegotiationCredentialExchange

	return nil
}

// FailNegotiation marks a negotiation as failed.
func (nm *NegotiationManager) FailNegotiation(_ context.Context, sessionID, reason string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("negotiation session %q not found", sessionID)
	}

	session.Status = NegotiationFailed
	session.FailureReason = reason
	session.CompletedAt = time.Now().UTC()

	return nil
}

// GetNegotiationStatus returns the current status of a negotiation session.
func (nm *NegotiationManager) GetNegotiationStatus(_ context.Context, sessionID string) (*NegotiationSession, error) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	session, ok := nm.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("negotiation session %q not found", sessionID)
	}

	return session, nil
}

// ListActiveSessions returns all non-terminal negotiation sessions.
func (nm *NegotiationManager) ListActiveSessions(_ context.Context) []*NegotiationSession {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	var active []*NegotiationSession
	for _, s := range nm.sessions {
		if s.Status != NegotiationAgreed && s.Status != NegotiationFailed {
			active = append(active, s)
		}
	}
	return active
}
