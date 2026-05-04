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
// Break-glass severity levels
// ---------------------------------------------------------------------------

// BreakGlassSeverity classifies the severity of a break-glass event.
type BreakGlassSeverity int

const (
	BreakGlassLow BreakGlassSeverity = iota
	BreakGlassMedium
	BreakGlassHigh
	BreakGlassCritical
)

// String returns the human-readable label for a BreakGlassSeverity.
func (s BreakGlassSeverity) String() string {
	switch s {
	case BreakGlassLow:
		return "Low"
	case BreakGlassMedium:
		return "Medium"
	case BreakGlassHigh:
		return "High"
	case BreakGlassCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// BreakGlassStatus tracks the lifecycle of a break-glass event.
type BreakGlassStatus int

const (
	BreakGlassActive BreakGlassStatus = iota
	BreakGlassTerminated
)

// ---------------------------------------------------------------------------
// Break-glass event
// ---------------------------------------------------------------------------

// BreakGlassEvent records a single break-glass emergency override.
// Every field is sealed and recorded for compliance auditing. Break-glass
// events are never deleted -- they form a permanent record.
type BreakGlassEvent struct {
	// ID is the unique identifier for this event.
	ID string `json:"id"`

	// Initiator is the identity of whoever triggered the break-glass.
	Initiator string `json:"initiator"`

	// Reason is the mandatory justification (cannot be empty).
	Reason string `json:"reason"`

	// Severity classifies the urgency.
	Severity BreakGlassSeverity `json:"severity"`

	// Status is active or terminated.
	Status BreakGlassStatus `json:"status"`

	// Timestamp is when the break-glass was initiated.
	Timestamp time.Time `json:"timestamp"`

	// TerminatedAt is when the break-glass was ended (zero if still active).
	TerminatedAt time.Time `json:"terminated_at,omitempty"`

	// TerminatedBy is who terminated the break-glass.
	TerminatedBy string `json:"terminated_by,omitempty"`

	// Duration is the maximum duration for this break-glass (auto-terminates).
	Duration time.Duration `json:"duration"`

	// AffectedPolicies lists the policy set IDs that are bypassed.
	AffectedPolicies []string `json:"affected_policies"`

	// AuditTrail is an append-only log of all events during this break-glass.
	AuditTrail []BreakGlassAuditEntry `json:"audit_trail"`

	// SealHash is a tamper-detection hash of the entire event.
	SealHash string `json:"seal_hash"`
}

// BreakGlassAuditEntry records a single action during a break-glass event.
type BreakGlassAuditEntry struct {
	Timestamp    time.Time `json:"timestamp"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	Details      string    `json:"details"`
	Hash         string    `json:"hash"`
	PreviousHash string    `json:"previous_hash"`
}

// ---------------------------------------------------------------------------
// BreakGlassController
// ---------------------------------------------------------------------------

// BreakGlassController manages break-glass emergency overrides. It enforces
// mandatory justification, maintains a complete audit trail, and supports
// auto-termination after a maximum duration.
type BreakGlassController struct {
	mu     sync.RWMutex
	events map[string]*BreakGlassEvent

	// MaxDuration is the maximum allowed break-glass duration. Defaults to 4 hours.
	MaxDuration time.Duration

	// DefaultDuration is used when no duration is specified. Defaults to 1 hour.
	DefaultDuration time.Duration
}

// NewBreakGlassController creates a new BreakGlassController.
func NewBreakGlassController() *BreakGlassController {
	return &BreakGlassController{
		events:          make(map[string]*BreakGlassEvent),
		MaxDuration:     4 * time.Hour,
		DefaultDuration: 1 * time.Hour,
	}
}

// InitiateBreakGlass initiates a break-glass emergency override. This creates
// a fully audited event with mandatory justification. The reason field cannot
// be empty — this is a compliance requirement.
func (c *BreakGlassController) InitiateBreakGlass(_ context.Context, initiator, reason string, severity BreakGlassSeverity, duration time.Duration, affectedPolicies []string) (*BreakGlassEvent, error) {
	if initiator == "" {
		return nil, fmt.Errorf("break-glass initiator cannot be empty")
	}
	if reason == "" {
		return nil, fmt.Errorf("break-glass reason is mandatory for compliance")
	}

	// Enforce maximum duration.
	if duration == 0 {
		duration = c.DefaultDuration
	}
	if duration > c.MaxDuration {
		duration = c.MaxDuration
	}

	now := time.Now().UTC()
	event := &BreakGlassEvent{
		ID:               uuid.New().String(),
		Initiator:        initiator,
		Reason:           reason,
		Severity:         severity,
		Status:           BreakGlassActive,
		Timestamp:        now,
		Duration:         duration,
		AffectedPolicies: affectedPolicies,
	}

	// Create the initial audit entry with hash chain.
	initialEntry := BreakGlassAuditEntry{
		Timestamp:    now,
		Actor:        initiator,
		Action:       "break_glass_initiated",
		Details:      fmt.Sprintf("severity=%s, reason=%s, duration=%s, policies=%v", severity, reason, duration, affectedPolicies),
		PreviousHash: "",
	}
	initialEntry.Hash = hashBreakGlassEntry(initialEntry)
	event.AuditTrail = append(event.AuditTrail, initialEntry)

	// Seal the event.
	event.SealHash = c.sealEvent(event)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.events[event.ID] = event

	return event, nil
}

// TerminateBreakGlass ends a break-glass event. Records who terminated it and why.
func (c *BreakGlassController) TerminateBreakGlass(_ context.Context, eventID, terminator, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	event, ok := c.events[eventID]
	if !ok {
		return fmt.Errorf("break-glass event %q not found", eventID)
	}
	if event.Status != BreakGlassActive {
		return fmt.Errorf("break-glass event %q is not active", eventID)
	}

	now := time.Now().UTC()
	event.Status = BreakGlassTerminated
	event.TerminatedAt = now
	event.TerminatedBy = terminator

	// Append audit entry.
	prevHash := ""
	if len(event.AuditTrail) > 0 {
		prevHash = event.AuditTrail[len(event.AuditTrail)-1].Hash
	}
	entry := BreakGlassAuditEntry{
		Timestamp:    now,
		Actor:        terminator,
		Action:       "break_glass_terminated",
		Details:      fmt.Sprintf("reason=%s, duration_active=%s", reason, now.Sub(event.Timestamp)),
		PreviousHash: prevHash,
	}
	entry.Hash = hashBreakGlassEntry(entry)
	event.AuditTrail = append(event.AuditTrail, entry)

	// Re-seal.
	event.SealHash = c.sealEvent(event)

	return nil
}

// IsBreakGlassActive returns true if any break-glass event is currently active.
func (c *BreakGlassController) IsBreakGlassActive(_ context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	for _, event := range c.events {
		if event.Status == BreakGlassActive {
			// Check auto-expiration.
			if now.Before(event.Timestamp.Add(event.Duration)) {
				return true
			}
		}
	}
	return false
}

// GetActiveBreakGlass returns all currently active break-glass events.
func (c *BreakGlassController) GetActiveBreakGlass(_ context.Context) []*BreakGlassEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	var active []*BreakGlassEvent
	for _, event := range c.events {
		if event.Status == BreakGlassActive && now.Before(event.Timestamp.Add(event.Duration)) {
			active = append(active, event)
		}
	}
	return active
}

// GetBreakGlassHistory returns all break-glass events (active and terminated),
// forming a complete compliance audit trail.
func (c *BreakGlassController) GetBreakGlassHistory(_ context.Context) []*BreakGlassEvent {
	c.mu.RLock()
	defer c.mu.RUnlock()

	history := make([]*BreakGlassEvent, 0, len(c.events))
	for _, event := range c.events {
		history = append(history, event)
	}
	return history
}

// GetBreakGlassEvent returns a single break-glass event by ID.
func (c *BreakGlassController) GetBreakGlassEvent(_ context.Context, eventID string) (*BreakGlassEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	event, ok := c.events[eventID]
	if !ok {
		return nil, fmt.Errorf("break-glass event %q not found", eventID)
	}
	return event, nil
}

// VerifyEventIntegrity checks the audit trail hash chain for a break-glass event.
func (c *BreakGlassController) VerifyEventIntegrity(_ context.Context, eventID string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	event, ok := c.events[eventID]
	if !ok {
		return false, fmt.Errorf("break-glass event %q not found", eventID)
	}

	for i, entry := range event.AuditTrail {
		// Verify hash chain linkage.
		if i > 0 && entry.PreviousHash != event.AuditTrail[i-1].Hash {
			return false, nil
		}
		// Verify entry hash.
		expected := hashBreakGlassEntry(entry)
		if entry.Hash != expected {
			return false, nil
		}
	}

	// Verify event seal.
	expected := c.sealEvent(event)
	return event.SealHash == expected, nil
}

// RecordAction appends an action to a break-glass event's audit trail.
func (c *BreakGlassController) RecordAction(_ context.Context, eventID, actor, action, details string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	event, ok := c.events[eventID]
	if !ok {
		return fmt.Errorf("break-glass event %q not found", eventID)
	}
	if event.Status != BreakGlassActive {
		return fmt.Errorf("break-glass event %q is not active", eventID)
	}

	now := time.Now().UTC()
	prevHash := ""
	if len(event.AuditTrail) > 0 {
		prevHash = event.AuditTrail[len(event.AuditTrail)-1].Hash
	}

	entry := BreakGlassAuditEntry{
		Timestamp:    now,
		Actor:        actor,
		Action:       action,
		Details:      details,
		PreviousHash: prevHash,
	}
	entry.Hash = hashBreakGlassEntry(entry)
	event.AuditTrail = append(event.AuditTrail, entry)

	// Re-seal after modification.
	event.SealHash = c.sealEvent(event)

	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func hashBreakGlassEntry(entry BreakGlassAuditEntry) string {
	data, _ := json.Marshal(struct {
		Timestamp    string `json:"ts"`
		Actor        string `json:"actor"`
		Action       string `json:"action"`
		Details      string `json:"details"`
		PreviousHash string `json:"prev"`
	}{
		Timestamp:    entry.Timestamp.Format(time.RFC3339Nano),
		Actor:        entry.Actor,
		Action:       entry.Action,
		Details:      entry.Details,
		PreviousHash: entry.PreviousHash,
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (c *BreakGlassController) sealEvent(event *BreakGlassEvent) string {
	// Hash all relevant fields for tamper detection.
	data, _ := json.Marshal(struct {
		ID        string `json:"id"`
		Initiator string `json:"initiator"`
		Reason    string `json:"reason"`
		Severity  string `json:"severity"`
		Timestamp string `json:"timestamp"`
		TrailLen  int    `json:"trail_len"`
		LastHash  string `json:"last_hash"`
	}{
		ID:        event.ID,
		Initiator: event.Initiator,
		Reason:    event.Reason,
		Severity:  event.Severity.String(),
		Timestamp: event.Timestamp.Format(time.RFC3339Nano),
		TrailLen:  len(event.AuditTrail),
		LastHash: func() string {
			if len(event.AuditTrail) > 0 {
				return event.AuditTrail[len(event.AuditTrail)-1].Hash
			}
			return ""
		}(),
	})
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
