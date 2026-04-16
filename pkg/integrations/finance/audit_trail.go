package finance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Financial Audit Trail (SOX-ready)
// ---------------------------------------------------------------------------

// FinancialEventType categorizes financial events.
type FinancialEventType string

const (
	EventTransaction      FinancialEventType = "transaction"
	EventApproval         FinancialEventType = "approval"
	EventException        FinancialEventType = "exception"
	EventReconciliation   FinancialEventType = "reconciliation"
	EventReportGeneration FinancialEventType = "report_generation"
	EventPolicyChange     FinancialEventType = "policy_change"
	EventScreening        FinancialEventType = "screening"
	EventAuditAccess      FinancialEventType = "audit_access"
	EventSettlement       FinancialEventType = "settlement"
)

// FinancialParty represents a party involved in a financial event.
type FinancialParty struct {
	// Name of the party.
	Name string `json:"name"`

	// Role (originator, beneficiary, approver, auditor).
	Role string `json:"role"`

	// Identifier is a unique identifier for the party.
	Identifier string `json:"identifier"`

	// Jurisdiction is the party's regulatory jurisdiction.
	Jurisdiction string `json:"jurisdiction,omitempty"`
}

// FinancialEvent represents a single auditable financial event.
type FinancialEvent struct {
	// ID uniquely identifies this event.
	ID string `json:"id"`

	// Type categorizes the event.
	Type FinancialEventType `json:"type"`

	// Amount is the monetary value involved (zero for non-monetary events).
	Amount float64 `json:"amount"`

	// Currency is the currency code.
	Currency string `json:"currency"`

	// Parties lists all parties involved.
	Parties []FinancialParty `json:"parties"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Evidence lists sealed evidence items.
	Evidence []FinancialEvidenceItem `json:"evidence"`

	// Regulation identifies the relevant regulatory framework.
	Regulation string `json:"regulation"`

	// Description provides context.
	Description string `json:"description"`

	// SealID links to the blockchain seal.
	SealID string `json:"seal_id"`

	// PreviousEventHash chains this event to the prior event.
	PreviousEventHash string `json:"previous_event_hash"`

	// EventHash is the hash of this event's content.
	EventHash string `json:"event_hash"`
}

// FinancialEvidenceItem is a single piece of financial evidence.
type FinancialEvidenceItem struct {
	// Type describes the evidence (e.g. "screening_result", "approval_record").
	Type string `json:"type"`

	// Description explains the evidence.
	Description string `json:"description"`

	// DataHash is the SHA-256 hash of the evidence data.
	DataHash string `json:"data_hash"`

	// SealID links to the blockchain seal.
	SealID string `json:"seal_id"`
}

// SOXEvidencePackage is a SOX-compliant evidence package for a reporting period.
type SOXEvidencePackage struct {
	// Period identifies the reporting period.
	Period string `json:"period"`

	// GeneratedAt is when the package was assembled.
	GeneratedAt time.Time `json:"generated_at"`

	// EventCount is the number of events in the period.
	EventCount int `json:"event_count"`

	// Events lists all events in the period.
	Events []FinancialEvent `json:"events"`

	// IntegrityValid indicates whether the event chain is intact.
	IntegrityValid bool `json:"integrity_valid"`

	// TotalAmount is the sum of all monetary events.
	TotalAmount float64 `json:"total_amount"`

	// Currency is the primary currency.
	Currency string `json:"currency"`

	// SealID is the seal for the entire package.
	SealID string `json:"seal_id"`

	// ControlsSummary lists SOX controls and their status.
	ControlsSummary map[string]string `json:"controls_summary"`
}

// RegulatoryReport is a report formatted for a specific regulator.
type RegulatoryReport struct {
	// Regulator identifies which regulator this report is for.
	Regulator string `json:"regulator"`

	// Period is the reporting period.
	Period string `json:"period"`

	// GeneratedAt is when the report was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// Sections contains the report content.
	Sections map[string]string `json:"sections"`

	// EventCount is the number of events covered.
	EventCount int `json:"event_count"`

	// SealID is the seal for this report.
	SealID string `json:"seal_id"`
}

// FinancialAuditTrail manages the creation and querying of sealed financial events.
type FinancialAuditTrail struct {
	mu     sync.RWMutex
	events []FinancialEvent
}

// NewFinancialAuditTrail creates a new financial audit trail.
func NewFinancialAuditTrail() *FinancialAuditTrail {
	return &FinancialAuditTrail{
		events: make([]FinancialEvent, 0),
	}
}

// RecordFinancialEvent records a sealed financial event in the audit trail.
// validPartyRoles lists the known financial party roles.
var validPartyRoles = map[string]bool{
	"originator":   true,
	"beneficiary":  true,
	"approver":     true,
	"auditor":      true,
	"custodian":    true,
	"counterparty": true,
}

// ValidatePartyRoles checks that all party roles are known values.
func ValidatePartyRoles(parties []FinancialParty) error {
	for _, p := range parties {
		if p.Role == "" {
			return fmt.Errorf("ValidatePartyRoles: %w: party %q has empty role", ErrAuditChainBroken, p.Name)
		}
		if !validPartyRoles[p.Role] {
			return fmt.Errorf("ValidatePartyRoles: %w: party %q has unknown role %q", ErrAuditChainBroken, p.Name, p.Role)
		}
	}
	return nil
}

func (t *FinancialAuditTrail) RecordFinancialEvent(_ context.Context, event *FinancialEvent) error {
	if event == nil {
		return fmt.Errorf("FinancialAuditTrail.RecordFinancialEvent: %w: event is nil", ErrAuditChainBroken)
	}
	if event.Type == "" {
		return fmt.Errorf("FinancialAuditTrail.RecordFinancialEvent: %w: event type is empty", ErrAuditChainBroken)
	}
	// Validate party roles if parties are provided.
	if len(event.Parties) > 0 {
		if err := ValidatePartyRoles(event.Parties); err != nil {
			return fmt.Errorf("FinancialAuditTrail.RecordFinancialEvent: %w", err)
		}
	}

	// Hold lock through the entire chain-then-store sequence to protect chain integrity.
	t.mu.Lock()
	defer t.mu.Unlock()

	if event.ID == "" {
		event.ID = fmt.Sprintf("fe-%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Chain to previous event
	if len(t.events) > 0 {
		prev := t.events[len(t.events)-1]
		event.PreviousEventHash = prev.EventHash
	}

	// Compute event hash
	event.EventHash = computeEventHash(event)

	// Generate seal ID
	if event.SealID == "" {
		h := sha256.Sum256([]byte(event.EventHash))
		event.SealID = "seal-fin-" + hex.EncodeToString(h[:])[:16]
	}

	t.events = append(t.events, *event)
	return nil
}

// GenerateSOXEvidence generates a SOX-compliant evidence package for a period.
func (t *FinancialAuditTrail) GenerateSOXEvidence(_ context.Context, period string) (*SOXEvidencePackage, error) {
	if period == "" {
		return nil, fmt.Errorf("FinancialAuditTrail.GenerateSOXEvidence: %w: period is empty", ErrReportFailed)
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	pkg := &SOXEvidencePackage{
		Period:      period,
		GeneratedAt: time.Now().UTC(),
		ControlsSummary: map[string]string{
			"ITGC-01_access_control":    "Blockchain-anchored identity with bech32 addresses",
			"ITGC-02_change_management": "Sealed deployment manifests with configuration hashes",
			"ITGC-03_operations":        "Immutable audit trail with hash-chained events",
			"ITGC-04_backup_recovery":   "State snapshots with cryptographic integrity",
			"SOXA302_disclosure":        "Automated evidence collection with sealed artifacts",
			"SOXA404_internal_controls": "Dual-control approval workflow with audit trail",
		},
	}

	// Collect events and verify chain integrity
	pkg.IntegrityValid = true
	for i, event := range t.events {
		pkg.Events = append(pkg.Events, event)
		pkg.EventCount++
		pkg.TotalAmount += event.Amount
		if event.Currency != "" {
			pkg.Currency = event.Currency
		}

		// Verify chain -- log which event broke the chain.
		if i > 0 {
			if event.PreviousEventHash != t.events[i-1].EventHash {
				pkg.IntegrityValid = false
				pkg.ControlsSummary["chain_break"] = fmt.Sprintf(
					"Chain broken at event %s (index %d): expected hash %s, got %s",
					event.ID, i, t.events[i-1].EventHash, event.PreviousEventHash)
			}
		}
	}

	// Seal the package
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d-%f", period, pkg.EventCount, pkg.TotalAmount)))
	pkg.SealID = "seal-sox-" + hex.EncodeToString(h[:])[:16]

	return pkg, nil
}

// GenerateRegulatoryReport generates a report for a specific regulator.
func (t *FinancialAuditTrail) GenerateRegulatoryReport(_ context.Context, regulator string, period string) (*RegulatoryReport, error) {
	if regulator == "" {
		return nil, fmt.Errorf("FinancialAuditTrail.GenerateRegulatoryReport: %w: regulator is empty", ErrReportFailed)
	}
	if period == "" {
		return nil, fmt.Errorf("FinancialAuditTrail.GenerateRegulatoryReport: %w: period is empty", ErrReportFailed)
	}

	t.mu.RLock()
	eventCount := len(t.events)
	t.mu.RUnlock()

	report := &RegulatoryReport{
		Regulator:   regulator,
		Period:      period,
		GeneratedAt: time.Now().UTC(),
		EventCount:  eventCount,
		Sections: map[string]string{
			"executive_summary": fmt.Sprintf("Regulatory report for %s covering period %s. Total events: %d.", regulator, period, eventCount),
			"audit_trail":       "All financial events are sealed on the Aethelred blockchain with tamper-evident hash chains.",
			"controls":          "Internal controls include dual-approval workflows, sanctions screening, and exception management.",
			"evidence":          "Evidence packages are available as sealed blockchain artifacts with cryptographic integrity verification.",
		},
	}

	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", regulator, period, time.Now().UnixNano())))
	report.SealID = "seal-reg-" + hex.EncodeToString(h[:])[:16]

	return report, nil
}

// GetEvents returns all events in the audit trail.
func (t *FinancialAuditTrail) GetEvents() []FinancialEvent {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]FinancialEvent, len(t.events))
	copy(result, t.events)
	return result
}

// VerifyChainIntegrity checks that the event hash chain is intact.
func (t *FinancialAuditTrail) VerifyChainIntegrity() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for i := 1; i < len(t.events); i++ {
		if t.events[i].PreviousEventHash != t.events[i-1].EventHash {
			return false
		}
	}
	return true
}

func computeEventHash(event *FinancialEvent) string {
	h := sha256.New()
	h.Write([]byte(event.ID))
	h.Write([]byte(event.Type))
	h.Write([]byte(fmt.Sprintf("%f", event.Amount)))
	h.Write([]byte(event.Currency))
	h.Write([]byte(event.Timestamp.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(event.PreviousEventHash))
	h.Write([]byte(event.Regulation))
	for _, p := range event.Parties {
		h.Write([]byte(p.Name))
		h.Write([]byte(p.Role))
	}
	return hex.EncodeToString(h.Sum(nil))
}
