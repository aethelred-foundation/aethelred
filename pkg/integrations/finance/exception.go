package finance

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// Exception Handling
// ---------------------------------------------------------------------------

// ExceptionType categorizes financial exceptions.
type ExceptionType string

const (
	ExceptionSanctionsHit    ExceptionType = "sanctions_hit"
	ExceptionLimitBreach     ExceptionType = "limit_breach"
	ExceptionUnauthorized    ExceptionType = "unauthorized"
	ExceptionReconciliation  ExceptionType = "reconciliation_break"
	ExceptionFraudSuspicion  ExceptionType = "fraud_suspicion"
	ExceptionComplianceGap   ExceptionType = "compliance_gap"
	ExceptionSystemError     ExceptionType = "system_error"
)

// EscalationLevel indicates how far up the chain an exception has been escalated.
type EscalationLevel int

const (
	EscalationL1 EscalationLevel = iota + 1
	EscalationL2
	EscalationL3
	EscalationExecutive
)

// String returns the human-readable label.
func (l EscalationLevel) String() string {
	switch l {
	case EscalationL1:
		return "Level 1 - Operations"
	case EscalationL2:
		return "Level 2 - Management"
	case EscalationL3:
		return "Level 3 - Senior Management"
	case EscalationExecutive:
		return "Executive"
	default:
		return "Unknown"
	}
}

// Resolution records how an exception was resolved.
type Resolution struct {
	// ResolvedBy is the person who resolved the exception.
	ResolvedBy string `json:"resolved_by"`

	// Action is the action taken.
	Action string `json:"action"`

	// Justification explains why this resolution was chosen.
	Justification string `json:"justification"`

	// Timestamp is when the resolution was applied.
	Timestamp time.Time `json:"timestamp"`

	// EvidenceSealID links to sealed evidence for the resolution.
	EvidenceSealID string `json:"evidence_seal_id"`
}

// FinancialException represents an exception in financial processing.
type FinancialException struct {
	// ID uniquely identifies this exception.
	ID string `json:"id"`

	// Type categorizes the exception.
	Type ExceptionType `json:"type"`

	// TransactionID links to the related transaction.
	TransactionID string `json:"transaction_id"`

	// Reason describes why the exception was raised.
	Reason string `json:"reason"`

	// DetectedBy identifies who or what detected the exception.
	DetectedBy string `json:"detected_by"`

	// EscalationLevel is the current escalation level.
	EscalationLevel EscalationLevel `json:"escalation_level"`

	// Resolution holds the resolution details (nil if unresolved).
	Resolution *Resolution `json:"resolution,omitempty"`

	// CreatedAt is when the exception was raised.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the exception was last modified.
	UpdatedAt time.Time `json:"updated_at"`

	// SealID links to the sealed exception record.
	SealID string `json:"seal_id"`

	// History tracks all escalation and resolution events.
	History []ExceptionHistoryEntry `json:"history"`
}

// ExceptionHistoryEntry records a change in the exception lifecycle.
type ExceptionHistoryEntry struct {
	// Action describes what happened.
	Action string `json:"action"`

	// Actor is who performed the action.
	Actor string `json:"actor"`

	// Timestamp is when it happened.
	Timestamp time.Time `json:"timestamp"`

	// FromLevel is the previous escalation level.
	FromLevel EscalationLevel `json:"from_level"`

	// ToLevel is the new escalation level.
	ToLevel EscalationLevel `json:"to_level"`

	// Details provides additional context.
	Details string `json:"details"`
}

// EscalationChain defines the rules for exception escalation.
type EscalationChain struct {
	// Levels maps escalation levels to responsible parties.
	Levels map[EscalationLevel]string `json:"levels"`

	// DefaultTimeout is the time before automatic escalation.
	DefaultTimeout time.Duration `json:"default_timeout"`

	// AutoEscalate determines whether exceptions escalate automatically.
	AutoEscalate bool `json:"auto_escalate"`
}

// ExceptionHandler manages financial exceptions.
type ExceptionHandler struct {
	chain      EscalationChain
	mu         sync.RWMutex
	exceptions map[string]*FinancialException
	counter    atomic.Uint64
}

// NewExceptionHandler creates a new exception handler.
func NewExceptionHandler(chain EscalationChain) *ExceptionHandler {
	if chain.Levels == nil {
		chain.Levels = map[EscalationLevel]string{
			EscalationL1:        "Operations Team",
			EscalationL2:        "Compliance Manager",
			EscalationL3:        "Chief Compliance Officer",
			EscalationExecutive: "Board Risk Committee",
		}
	}
	return &ExceptionHandler{
		chain:      chain,
		exceptions: make(map[string]*FinancialException),
	}
}

// RaiseException raises a new financial exception with an audit trail.
func (h *ExceptionHandler) RaiseException(_ context.Context, exception *FinancialException) error {
	if exception == nil {
		return fmt.Errorf("exception is required")
	}
	if exception.Type == "" {
		return fmt.Errorf("exception type is required")
	}
	if exception.Reason == "" {
		return fmt.Errorf("reason is required")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if exception.ID == "" {
		exception.ID = fmt.Sprintf("exc-%d-%d", time.Now().UnixNano(), h.counter.Add(1))
	}
	exception.CreatedAt = time.Now().UTC()
	exception.UpdatedAt = exception.CreatedAt
	if exception.EscalationLevel == 0 {
		exception.EscalationLevel = EscalationL1
	}

	exception.History = append(exception.History, ExceptionHistoryEntry{
		Action:    "raised",
		Actor:     exception.DetectedBy,
		Timestamp: exception.CreatedAt,
		ToLevel:   exception.EscalationLevel,
		Details:   exception.Reason,
	})

	h.exceptions[exception.ID] = exception
	return nil
}

// EscalateException escalates an exception to the next level.
func (h *ExceptionHandler) EscalateException(_ context.Context, exceptionID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return fmt.Errorf("exception not found: %s", exceptionID)
	}

	if exc.Resolution != nil {
		return fmt.Errorf("exception is already resolved")
	}

	prevLevel := exc.EscalationLevel
	nextLevel := prevLevel + 1
	if nextLevel > EscalationExecutive {
		return fmt.Errorf("exception is already at the highest escalation level")
	}

	exc.EscalationLevel = nextLevel
	exc.UpdatedAt = time.Now().UTC()

	exc.History = append(exc.History, ExceptionHistoryEntry{
		Action:    "escalated",
		Actor:     "system",
		Timestamp: exc.UpdatedAt,
		FromLevel: prevLevel,
		ToLevel:   nextLevel,
		Details:   fmt.Sprintf("Escalated from %s to %s", prevLevel, nextLevel),
	})

	return nil
}

// ResolveException resolves an exception with evidence.
func (h *ExceptionHandler) ResolveException(_ context.Context, exceptionID string, resolution Resolution) error {
	if resolution.ResolvedBy == "" {
		return fmt.Errorf("resolved_by is required")
	}
	if resolution.Action == "" {
		return fmt.Errorf("action is required")
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return fmt.Errorf("exception not found: %s", exceptionID)
	}

	if exc.Resolution != nil {
		return fmt.Errorf("exception is already resolved")
	}

	resolution.Timestamp = time.Now().UTC()
	exc.Resolution = &resolution
	exc.UpdatedAt = resolution.Timestamp

	exc.History = append(exc.History, ExceptionHistoryEntry{
		Action:    "resolved",
		Actor:     resolution.ResolvedBy,
		Timestamp: resolution.Timestamp,
		Details:   fmt.Sprintf("Resolved: %s - %s", resolution.Action, resolution.Justification),
	})

	return nil
}

// GetException retrieves an exception by ID.
func (h *ExceptionHandler) GetException(_ context.Context, exceptionID string) (*FinancialException, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return nil, fmt.Errorf("exception not found: %s", exceptionID)
	}
	return exc, nil
}

// ListOpenExceptions returns all unresolved exceptions.
func (h *ExceptionHandler) ListOpenExceptions(_ context.Context) ([]*FinancialException, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var results []*FinancialException
	for _, exc := range h.exceptions {
		if exc.Resolution == nil {
			results = append(results, exc)
		}
	}
	return results, nil
}
