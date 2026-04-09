package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Exception types
// ---------------------------------------------------------------------------

// ExceptionType classifies a policy exception.
type ExceptionType int

const (
	// TemporaryException is a time-bounded exception.
	TemporaryException ExceptionType = iota

	// PermanentException is a standing exception (still audited).
	PermanentException

	// EmergencyException is granted under emergency conditions.
	EmergencyException

	// ScheduledException is a pre-approved exception for a known window.
	ScheduledException
)

// String returns the human-readable label for an ExceptionType.
func (t ExceptionType) String() string {
	switch t {
	case TemporaryException:
		return "Temporary"
	case PermanentException:
		return "Permanent"
	case EmergencyException:
		return "Emergency"
	case ScheduledException:
		return "Scheduled"
	default:
		return "Unknown"
	}
}

// ExceptionStatus tracks the lifecycle of an exception.
type ExceptionStatus int

const (
	ExceptionPending ExceptionStatus = iota
	ExceptionApproved
	ExceptionDenied
	ExceptionActive
	ExceptionExpired
	ExceptionRevoked
)

// String returns the human-readable label for an ExceptionStatus.
func (s ExceptionStatus) String() string {
	switch s {
	case ExceptionPending:
		return "Pending"
	case ExceptionApproved:
		return "Approved"
	case ExceptionDenied:
		return "Denied"
	case ExceptionActive:
		return "Active"
	case ExceptionExpired:
		return "Expired"
	case ExceptionRevoked:
		return "Revoked"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Exception struct
// ---------------------------------------------------------------------------

// Exception represents a policy exception request or grant.
type Exception struct {
	ID          string          `json:"id"`
	Type        ExceptionType   `json:"type"`
	Status      ExceptionStatus `json:"status"`
	Reason      string          `json:"reason"`
	RequestedBy string          `json:"requested_by"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
	Scope       *ExceptionScope `json:"scope"`
	Duration    time.Duration   `json:"duration"`
	StartTime   time.Time       `json:"start_time"`
	ExpiresAt   time.Time       `json:"expires_at"`
	Conditions  []string        `json:"conditions,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	AuditTrail  []ExceptionAuditEntry `json:"audit_trail"`
}

// ExceptionScope defines the boundaries of an exception.
type ExceptionScope struct {
	PolicyIDs []string `json:"policy_ids,omitempty"`
	Actions   []string `json:"actions,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Actors    []string `json:"actors,omitempty"`
}

// ExceptionAuditEntry records a single event in the exception lifecycle.
type ExceptionAuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Hash      string    `json:"hash"`
}

// ---------------------------------------------------------------------------
// Exception request
// ---------------------------------------------------------------------------

// ExceptionRequest is the input for requesting a new policy exception.
type ExceptionRequest struct {
	Type        ExceptionType   `json:"type"`
	Reason      string          `json:"reason"`
	RequestedBy string          `json:"requested_by"`
	Scope       *ExceptionScope `json:"scope"`
	Duration    time.Duration   `json:"duration"`
	Conditions  []string        `json:"conditions,omitempty"`
}

// ---------------------------------------------------------------------------
// Escalation
// ---------------------------------------------------------------------------

// EscalationLevel represents a step in an escalation chain.
type EscalationLevel struct {
	Level     int           `json:"level"`
	Roles     []string      `json:"roles"`
	Timeout   time.Duration `json:"timeout"`
	NotifyAll bool          `json:"notify_all"`
}

// EscalationChain defines a sequence of escalation levels.
type EscalationChain struct {
	Levels       []EscalationLevel `json:"levels"`
	AutoEscalate bool              `json:"auto_escalate"`
}

// DefaultEscalationChain returns a standard three-tier escalation chain.
func DefaultEscalationChain() *EscalationChain {
	return &EscalationChain{
		Levels: []EscalationLevel{
			{Level: 1, Roles: []string{"team_lead"}, Timeout: 2 * time.Hour, NotifyAll: false},
			{Level: 2, Roles: []string{"department_head", "compliance_officer"}, Timeout: 4 * time.Hour, NotifyAll: true},
			{Level: 3, Roles: []string{"ciso", "cto"}, Timeout: 8 * time.Hour, NotifyAll: true},
		},
		AutoEscalate: true,
	}
}

// ---------------------------------------------------------------------------
// ExceptionHandler
// ---------------------------------------------------------------------------

// ExceptionHandler manages the lifecycle of policy exceptions.
type ExceptionHandler struct {
	mu              sync.RWMutex
	exceptions      map[string]*Exception
	escalationChain *EscalationChain
}

// NewExceptionHandler creates a new ExceptionHandler with an optional escalation chain.
func NewExceptionHandler(chain *EscalationChain) *ExceptionHandler {
	if chain == nil {
		chain = DefaultEscalationChain()
	}
	return &ExceptionHandler{
		exceptions:      make(map[string]*Exception),
		escalationChain: chain,
	}
}

// RequestException creates a new exception request. The exception starts in Pending status.
func (h *ExceptionHandler) RequestException(_ context.Context, req *ExceptionRequest) (*Exception, error) {
	if req == nil {
		return nil, fmt.Errorf("exception request cannot be nil")
	}
	if req.Reason == "" {
		return nil, fmt.Errorf("exception reason is required")
	}
	if req.RequestedBy == "" {
		return nil, fmt.Errorf("requestor is required")
	}
	if req.Scope == nil {
		return nil, fmt.Errorf("exception scope is required")
	}
	if req.Type == TemporaryException && req.Duration == 0 {
		return nil, fmt.Errorf("temporary exceptions require a duration")
	}

	now := time.Now().UTC()
	exc := &Exception{
		ID:          uuid.New().String(),
		Type:        req.Type,
		Status:      ExceptionPending,
		Reason:      req.Reason,
		RequestedBy: req.RequestedBy,
		Scope:       req.Scope,
		Duration:    req.Duration,
		Conditions:  req.Conditions,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	auditEntry := ExceptionAuditEntry{
		Timestamp: now,
		Actor:     req.RequestedBy,
		Action:    "exception_requested",
		Details:   fmt.Sprintf("type=%s, reason=%s", req.Type, req.Reason),
	}
	auditEntry.Hash = hashExceptionAudit(auditEntry)
	exc.AuditTrail = append(exc.AuditTrail, auditEntry)

	h.mu.Lock()
	defer h.mu.Unlock()
	h.exceptions[exc.ID] = exc

	return exc, nil
}

// ApproveException approves a pending exception and activates it.
func (h *ExceptionHandler) ApproveException(_ context.Context, exceptionID, approver string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return fmt.Errorf("exception %q not found", exceptionID)
	}
	if exc.Status != ExceptionPending {
		return fmt.Errorf("exception %q is not pending (status: %s)", exceptionID, exc.Status)
	}

	now := time.Now().UTC()
	exc.Status = ExceptionActive
	exc.ApprovedBy = approver
	exc.StartTime = now
	exc.UpdatedAt = now

	if exc.Duration > 0 {
		exc.ExpiresAt = now.Add(exc.Duration)
	}

	auditEntry := ExceptionAuditEntry{
		Timestamp: now,
		Actor:     approver,
		Action:    "exception_approved",
		Details:   fmt.Sprintf("exception_id=%s", exceptionID),
	}
	auditEntry.Hash = hashExceptionAudit(auditEntry)
	exc.AuditTrail = append(exc.AuditTrail, auditEntry)

	return nil
}

// DenyException denies a pending exception.
func (h *ExceptionHandler) DenyException(_ context.Context, exceptionID, denier, reason string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return fmt.Errorf("exception %q not found", exceptionID)
	}
	if exc.Status != ExceptionPending {
		return fmt.Errorf("exception %q is not pending (status: %s)", exceptionID, exc.Status)
	}

	now := time.Now().UTC()
	exc.Status = ExceptionDenied
	exc.UpdatedAt = now

	auditEntry := ExceptionAuditEntry{
		Timestamp: now,
		Actor:     denier,
		Action:    "exception_denied",
		Details:   fmt.Sprintf("exception_id=%s, reason=%s", exceptionID, reason),
	}
	auditEntry.Hash = hashExceptionAudit(auditEntry)
	exc.AuditTrail = append(exc.AuditTrail, auditEntry)

	return nil
}

// RevokeException revokes an active exception.
func (h *ExceptionHandler) RevokeException(_ context.Context, exceptionID, revoker, reason string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return fmt.Errorf("exception %q not found", exceptionID)
	}
	if exc.Status != ExceptionActive {
		return fmt.Errorf("exception %q is not active (status: %s)", exceptionID, exc.Status)
	}

	now := time.Now().UTC()
	exc.Status = ExceptionRevoked
	exc.UpdatedAt = now

	auditEntry := ExceptionAuditEntry{
		Timestamp: now,
		Actor:     revoker,
		Action:    "exception_revoked",
		Details:   fmt.Sprintf("exception_id=%s, reason=%s", exceptionID, reason),
	}
	auditEntry.Hash = hashExceptionAudit(auditEntry)
	exc.AuditTrail = append(exc.AuditTrail, auditEntry)

	return nil
}

// IsExceptionActive checks whether an exception is currently active and not expired.
func (h *ExceptionHandler) IsExceptionActive(_ context.Context, exceptionID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return false
	}

	if exc.Status != ExceptionActive {
		return false
	}

	// Check expiration for temporary/scheduled exceptions.
	if !exc.ExpiresAt.IsZero() && time.Now().After(exc.ExpiresAt) {
		return false
	}

	return true
}

// GetException returns an exception by ID.
func (h *ExceptionHandler) GetException(_ context.Context, exceptionID string) (*Exception, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	exc, ok := h.exceptions[exceptionID]
	if !ok {
		return nil, fmt.Errorf("exception %q not found", exceptionID)
	}
	return exc, nil
}

// Escalate escalates a request to the next level in the escalation chain.
func (h *ExceptionHandler) Escalate(_ context.Context, exceptionID string, level int) (*EscalationLevel, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if _, ok := h.exceptions[exceptionID]; !ok {
		return nil, fmt.Errorf("exception %q not found", exceptionID)
	}

	if level < 0 || level >= len(h.escalationChain.Levels) {
		return nil, fmt.Errorf("escalation level %d out of range (max: %d)",
			level, len(h.escalationChain.Levels)-1)
	}

	return &h.escalationChain.Levels[level], nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func hashExceptionAudit(entry ExceptionAuditEntry) string {
	data, _ := json.Marshal(struct {
		Timestamp string `json:"ts"`
		Actor     string `json:"actor"`
		Action    string `json:"action"`
		Details   string `json:"details"`
	}{
		Timestamp: entry.Timestamp.Format(time.RFC3339Nano),
		Actor:     entry.Actor,
		Action:    entry.Action,
		Details:   entry.Details,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
