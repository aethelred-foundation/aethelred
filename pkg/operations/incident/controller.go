// Package incident provides an incident response controller with kill switch,
// automated rollback, jurisdiction-aware disclosure, and runbook execution.
//
// It is designed for enterprise-grade incident management in regulated
// environments where every action must be audit-trailed and disclosure
// requirements vary by jurisdiction.
package incident

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
// Incident types and enums
// ---------------------------------------------------------------------------

// IncidentType classifies the nature of an incident.
type IncidentType string

const (
	IncidentConsensusHalt     IncidentType = "consensus_halt"
	IncidentBridgePause       IncidentType = "bridge_pause"
	IncidentDataCorruption    IncidentType = "data_corruption"
	IncidentSecurityBreach    IncidentType = "security_breach"
	IncidentSafetyViolation   IncidentType = "safety_violation"
	IncidentComplianceViolation IncidentType = "compliance_violation"
)

// IncidentSeverity classifies the urgency and impact of an incident.
type IncidentSeverity string

const (
	SeverityP0 IncidentSeverity = "P0" // Critical: full system outage or security breach
	SeverityP1 IncidentSeverity = "P1" // High: significant degradation or data issue
	SeverityP2 IncidentSeverity = "P2" // Medium: partial impact, workaround available
	SeverityP3 IncidentSeverity = "P3" // Low: minor issue, no immediate impact
)

// IncidentStatus tracks the lifecycle of an incident.
type IncidentStatus string

const (
	StatusDetected  IncidentStatus = "detected"
	StatusTriaging  IncidentStatus = "triaging"
	StatusMitigating IncidentStatus = "mitigating"
	StatusResolved  IncidentStatus = "resolved"
	StatusPostMortem IncidentStatus = "post_mortem"
)

// ---------------------------------------------------------------------------
// Timeline and audit
// ---------------------------------------------------------------------------

// TimelineEntry records a single event in the incident timeline.
type TimelineEntry struct {
	Timestamp   string `json:"timestamp"`
	Action      string `json:"action"`
	Actor       string `json:"actor"`
	Description string `json:"description"`
	Hash        string `json:"hash"` // SHA-256 for tamper detection
}

// computeHash computes the SHA-256 hash of a timeline entry.
func (te *TimelineEntry) computeHash() string {
	h := sha256.New()
	h.Write([]byte(te.Timestamp))
	h.Write([]byte(te.Action))
	h.Write([]byte(te.Actor))
	h.Write([]byte(te.Description))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Incident
// ---------------------------------------------------------------------------

// Incident represents a platform incident with full audit trail.
type Incident struct {
	ID              string           `json:"id"`
	Type            IncidentType     `json:"type"`
	Severity        IncidentSeverity `json:"severity"`
	Status          IncidentStatus   `json:"status"`
	Title           string           `json:"title"`
	Description     string           `json:"description"`
	DetectedAt      string           `json:"detected_at"`
	ResolvedAt      string           `json:"resolved_at,omitempty"`
	Timeline        []TimelineEntry  `json:"timeline"`
	AffectedSystems []string         `json:"affected_systems"`
	Responders      []string         `json:"responders"`
	RootCause       string           `json:"root_cause,omitempty"`
	Resolution      string           `json:"resolution,omitempty"`
	ContentHash     string           `json:"content_hash"`
}

// computeContentHash computes SHA-256 over the incident's current state.
// validTransitions defines allowed status transitions. A transition from
// Resolved back to Detected is not permitted.
var validTransitions = map[IncidentStatus][]IncidentStatus{
	StatusDetected:   {StatusTriaging, StatusMitigating, StatusResolved},
	StatusTriaging:   {StatusMitigating, StatusResolved},
	StatusMitigating: {StatusResolved},
	StatusResolved:   {StatusPostMortem},
	StatusPostMortem: {},
}

// ValidateTransition checks if a status transition is allowed.
func ValidateTransition(from, to IncidentStatus) error {
	allowed, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("ValidateTransition: %w: unknown status %q", ErrInvalidTransition, from)
	}
	for _, s := range allowed {
		if s == to {
			return nil
		}
	}
	return fmt.Errorf("ValidateTransition: %w: cannot transition from %q to %q", ErrInvalidTransition, from, to)
}

func (inc *Incident) computeContentHash() string {
	type hashable struct {
		ID         string           `json:"id"`
		Type       IncidentType     `json:"type"`
		Severity   IncidentSeverity `json:"severity"`
		Status     IncidentStatus   `json:"status"`
		Title      string           `json:"title"`
		DetectedAt string           `json:"detected_at"`
		Timeline   []TimelineEntry  `json:"timeline"`
	}
	h := hashable{
		ID:         inc.ID,
		Type:       inc.Type,
		Severity:   inc.Severity,
		Status:     inc.Status,
		Title:      inc.Title,
		DetectedAt: inc.DetectedAt,
		Timeline:   inc.Timeline,
	}
	data, err := json.Marshal(h)
	if err != nil {
		// Fallback to hash of ID on marshal failure.
		sum := sha256.Sum256([]byte(inc.ID))
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Validate checks the incident for structural validity.
func (inc *Incident) Validate() error {
	if inc.ID == "" {
		return fmt.Errorf("Incident.Validate: %w: ID is empty", ErrIncidentNotFound)
	}
	if inc.Type == "" {
		return fmt.Errorf("Incident.Validate: %w: type is empty", ErrIncidentNotFound)
	}
	if inc.Severity == "" {
		return fmt.Errorf("Incident.Validate: %w", ErrInvalidSeverity)
	}
	// Validate severity is one of the known values.
	switch inc.Severity {
	case SeverityP0, SeverityP1, SeverityP2, SeverityP3:
		// valid
	default:
		return fmt.Errorf("Incident.Validate: %w: unknown severity %q", ErrInvalidSeverity, inc.Severity)
	}
	if inc.Title == "" {
		return fmt.Errorf("Incident.Validate: %w: title is empty", ErrIncidentNotFound)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Incident update
// ---------------------------------------------------------------------------

// IncidentUpdate describes a change to an incident.
type IncidentUpdate struct {
	Status     IncidentStatus `json:"status,omitempty"`
	Severity   IncidentSeverity `json:"severity,omitempty"`
	Actor      string         `json:"actor"`
	Note       string         `json:"note"`
	Responders []string       `json:"responders,omitempty"`
}

// IncidentResolution describes how an incident was resolved.
type IncidentResolution struct {
	Actor      string `json:"actor"`
	RootCause  string `json:"root_cause"`
	Resolution string `json:"resolution"`
	PreventionPlan string `json:"prevention_plan,omitempty"`
}

// ---------------------------------------------------------------------------
// Incident Controller
// ---------------------------------------------------------------------------

// IncidentController manages the full incident lifecycle with audit trail.
type IncidentController struct {
	mu        sync.RWMutex
	incidents map[string]*Incident
	auditLog  []TimelineEntry
}

// NewIncidentController creates a new controller.
func NewIncidentController() *IncidentController {
	return &IncidentController{
		incidents: make(map[string]*Incident),
		auditLog:  make([]TimelineEntry, 0),
	}
}

// CreateIncident creates a new incident with a full audit trail entry.
func (ic *IncidentController) CreateIncident(_ context.Context, inc *Incident) (*Incident, error) {
	if inc == nil {
		return nil, fmt.Errorf("IncidentController.CreateIncident: %w: incident is nil", ErrIncidentNotFound)
	}

	// Assign defaults.
	if inc.ID == "" {
		inc.ID = uuid.New().String()
	}
	if inc.Status == "" {
		inc.Status = StatusDetected
	}
	if inc.DetectedAt == "" {
		inc.DetectedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if inc.Timeline == nil {
		inc.Timeline = make([]TimelineEntry, 0)
	}

	if err := inc.Validate(); err != nil {
		return nil, err
	}

	// Add creation to timeline.
	entry := TimelineEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Action:      "incident_created",
		Actor:       "system",
		Description: fmt.Sprintf("Incident created: %s (%s/%s)", inc.Title, inc.Type, inc.Severity),
	}
	entry.Hash = entry.computeHash()
	inc.Timeline = append(inc.Timeline, entry)
	inc.ContentHash = inc.computeContentHash()

	ic.mu.Lock()
	ic.incidents[inc.ID] = inc
	ic.auditLog = append(ic.auditLog, entry)
	ic.mu.Unlock()

	return inc, nil
}

// GetIncident returns an incident by ID.
func (ic *IncidentController) GetIncident(_ context.Context, id string) (*Incident, error) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	inc, ok := ic.incidents[id]
	if !ok {
		return nil, fmt.Errorf("IncidentController.GetIncident: %w: %s", ErrIncidentNotFound, id)
	}
	return inc, nil
}

// ListIncidents returns all incidents, optionally filtered by status.
func (ic *IncidentController) ListIncidents(_ context.Context, status IncidentStatus) []*Incident {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	var result []*Incident
	for _, inc := range ic.incidents {
		if status == "" || inc.Status == status {
			result = append(result, inc)
		}
	}
	return result
}

// UpdateIncident updates an incident's status and adds a timeline entry.
func (ic *IncidentController) UpdateIncident(_ context.Context, id string, update IncidentUpdate) (*Incident, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	inc, ok := ic.incidents[id]
	if !ok {
		return nil, fmt.Errorf("IncidentController.UpdateIncident: %w: %s", ErrIncidentNotFound, id)
	}

	// Validate status transition.
	if update.Status != "" {
		if err := ValidateTransition(inc.Status, update.Status); err != nil {
			return nil, fmt.Errorf("IncidentController.UpdateIncident: %w", err)
		}
		inc.Status = update.Status
	}
	if update.Severity != "" {
		inc.Severity = update.Severity
	}
	if len(update.Responders) > 0 {
		inc.Responders = append(inc.Responders, update.Responders...)
	}

	entry := TimelineEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Action:      "incident_updated",
		Actor:       update.Actor,
		Description: update.Note,
	}
	entry.Hash = entry.computeHash()
	inc.Timeline = append(inc.Timeline, entry)
	inc.ContentHash = inc.computeContentHash()

	ic.auditLog = append(ic.auditLog, entry)

	return inc, nil
}

// ResolveIncident resolves an incident with evidence and audit trail.
func (ic *IncidentController) ResolveIncident(_ context.Context, id string, resolution IncidentResolution) (*Incident, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()

	inc, ok := ic.incidents[id]
	if !ok {
		return nil, fmt.Errorf("IncidentController.ResolveIncident: %w: %s", ErrIncidentNotFound, id)
	}

	// Validate transition to resolved status.
	if err := ValidateTransition(inc.Status, StatusResolved); err != nil {
		return nil, fmt.Errorf("IncidentController.ResolveIncident: %w", err)
	}

	inc.Status = StatusResolved
	inc.ResolvedAt = time.Now().UTC().Format(time.RFC3339)
	inc.RootCause = resolution.RootCause
	inc.Resolution = resolution.Resolution

	entry := TimelineEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		Action:      "incident_resolved",
		Actor:       resolution.Actor,
		Description: fmt.Sprintf("Root cause: %s. Resolution: %s", resolution.RootCause, resolution.Resolution),
	}
	entry.Hash = entry.computeHash()
	inc.Timeline = append(inc.Timeline, entry)
	inc.ContentHash = inc.computeContentHash()

	ic.auditLog = append(ic.auditLog, entry)

	return inc, nil
}

// GetAuditLog returns the complete audit log of all incident actions.
func (ic *IncidentController) GetAuditLog() []TimelineEntry {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	result := make([]TimelineEntry, len(ic.auditLog))
	copy(result, ic.auditLog)
	return result
}
