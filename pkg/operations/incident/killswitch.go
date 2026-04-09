package incident

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Kill Switch with Graduated Severity
// ---------------------------------------------------------------------------
//
// The kill switch provides graduated emergency response actions, from
// pausing individual subsystems to full emergency shutdown. Every
// activation and deactivation is fully audit-trailed.
//
// Graduated actions (least to most severe):
//   1. Pause    - Pause specific operations (reversible, minimal impact)
//   2. Isolate  - Isolate affected systems from the network
//   3. Halt     - Halt all processing on affected systems
//   4. EmergencyShutdown - Full emergency shutdown of all systems
// ---------------------------------------------------------------------------

// KillSwitchAction specifies the severity of a kill switch activation.
type KillSwitchAction string

const (
	ActionPause             KillSwitchAction = "pause"
	ActionIsolate           KillSwitchAction = "isolate"
	ActionHalt              KillSwitchAction = "halt"
	ActionEmergencyShutdown KillSwitchAction = "emergency_shutdown"
)

// KillSwitchScope defines the scope of a kill switch activation.
type KillSwitchScope struct {
	Systems  []string `json:"systems"`
	Regions  []string `json:"regions,omitempty"`
	Services []string `json:"services,omitempty"`
}

// Validate checks the scope for completeness.
func (s *KillSwitchScope) Validate() error {
	if len(s.Systems) == 0 && len(s.Regions) == 0 && len(s.Services) == 0 {
		return fmt.Errorf("incident/killswitch: at least one system, region, or service must be specified")
	}
	return nil
}

// KillSwitchRecord represents a single kill switch activation record.
type KillSwitchRecord struct {
	ID           string           `json:"id"`
	Action       KillSwitchAction `json:"action"`
	Reason       string           `json:"reason"`
	Scope        KillSwitchScope  `json:"scope"`
	ActivatedAt  string           `json:"activated_at"`
	ActivatedBy  string           `json:"activated_by"`
	DeactivatedAt string          `json:"deactivated_at,omitempty"`
	DeactivatedBy string          `json:"deactivated_by,omitempty"`
	Active       bool             `json:"active"`
	IncidentID   string           `json:"incident_id,omitempty"`
}

// KillSwitch manages graduated emergency response actions.
type KillSwitch struct {
	mu          sync.RWMutex
	records     map[string]*KillSwitchRecord
	auditTrail  []KillSwitchAuditEntry
	idCounter   uint64
}

// KillSwitchAuditEntry records every kill switch action for compliance.
type KillSwitchAuditEntry struct {
	Timestamp   string           `json:"timestamp"`
	RecordID    string           `json:"record_id"`
	Action      KillSwitchAction `json:"action"`
	Operation   string           `json:"operation"` // "activate" or "deactivate"
	Actor       string           `json:"actor"`
	Reason      string           `json:"reason"`
	Scope       KillSwitchScope  `json:"scope"`
}

// NewKillSwitch creates a new kill switch controller.
func NewKillSwitch() *KillSwitch {
	return &KillSwitch{
		records:    make(map[string]*KillSwitchRecord),
		auditTrail: make([]KillSwitchAuditEntry, 0),
	}
}

// ActivateKillSwitch activates a graduated kill switch action.
func (ks *KillSwitch) ActivateKillSwitch(_ context.Context, action KillSwitchAction, reason string, scope KillSwitchScope) (*KillSwitchRecord, error) {
	if action == "" {
		return nil, fmt.Errorf("incident/killswitch: action is required")
	}
	if reason == "" {
		return nil, fmt.Errorf("incident/killswitch: reason is required")
	}
	if err := scope.Validate(); err != nil {
		return nil, err
	}

	ks.mu.Lock()
	ks.idCounter++
	counter := ks.idCounter
	ks.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := &KillSwitchRecord{
		ID:          fmt.Sprintf("ks-%d-%d", time.Now().UnixNano(), counter),
		Action:      action,
		Reason:      reason,
		Scope:       scope,
		ActivatedAt: now,
		ActivatedBy: "system",
		Active:      true,
	}

	auditEntry := KillSwitchAuditEntry{
		Timestamp: now,
		RecordID:  record.ID,
		Action:    action,
		Operation: "activate",
		Actor:     "system",
		Reason:    reason,
		Scope:     scope,
	}

	ks.mu.Lock()
	ks.records[record.ID] = record
	ks.auditTrail = append(ks.auditTrail, auditEntry)
	ks.mu.Unlock()

	return record, nil
}

// DeactivateKillSwitch deactivates a previously activated kill switch.
func (ks *KillSwitch) DeactivateKillSwitch(_ context.Context, recordID string) (*KillSwitchRecord, error) {
	if recordID == "" {
		return nil, fmt.Errorf("incident/killswitch: record ID is required")
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()

	record, ok := ks.records[recordID]
	if !ok {
		return nil, fmt.Errorf("incident/killswitch: record not found: %s", recordID)
	}

	if !record.Active {
		return nil, fmt.Errorf("incident/killswitch: already deactivated: %s", recordID)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	record.Active = false
	record.DeactivatedAt = now
	record.DeactivatedBy = "system"

	ks.auditTrail = append(ks.auditTrail, KillSwitchAuditEntry{
		Timestamp: now,
		RecordID:  recordID,
		Action:    record.Action,
		Operation: "deactivate",
		Actor:     "system",
		Reason:    "operations restored",
		Scope:     record.Scope,
	})

	return record, nil
}

// GetActiveKillSwitches returns all currently active kill switch records.
func (ks *KillSwitch) GetActiveKillSwitches() []*KillSwitchRecord {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	var active []*KillSwitchRecord
	for _, r := range ks.records {
		if r.Active {
			active = append(active, r)
		}
	}
	return active
}

// GetAuditTrail returns the complete kill switch audit trail.
func (ks *KillSwitch) GetAuditTrail() []KillSwitchAuditEntry {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	result := make([]KillSwitchAuditEntry, len(ks.auditTrail))
	copy(result, ks.auditTrail)
	return result
}

// IsSystemPaused checks if a specific system is affected by any active
// kill switch.
func (ks *KillSwitch) IsSystemPaused(system string) bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	for _, r := range ks.records {
		if !r.Active {
			continue
		}
		for _, s := range r.Scope.Systems {
			if s == system {
				return true
			}
		}
	}
	return false
}
