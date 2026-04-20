package securecells

import "time"

// SecureCellFederationIncidentDirectiveExtensionDisputeStatus captures the
// lifecycle of one challenge against a governed directive deadline exception.
type SecureCellFederationIncidentDirectiveExtensionDisputeStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionDisputeStatusPendingResolution SecureCellFederationIncidentDirectiveExtensionDisputeStatus = "pending_resolution"
	SecureCellFederationIncidentDirectiveExtensionDisputeStatusUpheld            SecureCellFederationIncidentDirectiveExtensionDisputeStatus = "upheld"
	SecureCellFederationIncidentDirectiveExtensionDisputeStatusReversed          SecureCellFederationIncidentDirectiveExtensionDisputeStatus = "reversed"
)

// SecureCellFederationIncidentDirectiveExtensionDisputeResolution captures the
// final disposition of a challenged deadline exception.
type SecureCellFederationIncidentDirectiveExtensionDisputeResolution string

const (
	SecureCellFederationIncidentDirectiveExtensionDisputeResolutionUphold  SecureCellFederationIncidentDirectiveExtensionDisputeResolution = "uphold"
	SecureCellFederationIncidentDirectiveExtensionDisputeResolutionReverse SecureCellFederationIncidentDirectiveExtensionDisputeResolution = "reverse"
)

// SecureCellFederationIncidentDirectiveExtensionDispute preserves one
// evidence-bearing challenge and resolution over a directive deadline
// exception.
type SecureCellFederationIncidentDirectiveExtensionDispute struct {
	ID                    string                                                          `json:"id"`
	ResponseID            string                                                          `json:"response_id"`
	DirectiveID           string                                                          `json:"directive_id"`
	ExtensionID           string                                                          `json:"extension_id"`
	OrganizationID        string                                                          `json:"organization_id"`
	SponsorOfRecord       string                                                          `json:"sponsor_of_record,omitempty"`
	IncidentID            string                                                          `json:"incident_id"`
	ChallengingParty      SecureCellFederationIncidentResponseParty                       `json:"challenging_party"`
	RespondingParty       SecureCellFederationIncidentResponseParty                       `json:"responding_party"`
	ChallengedStatus      SecureCellFederationIncidentDirectiveExtensionStatus            `json:"challenged_status"`
	DisputedBy            string                                                          `json:"disputed_by,omitempty"`
	Summary               string                                                          `json:"summary"`
	Description           string                                                          `json:"description,omitempty"`
	EvidenceIDs           []string                                                        `json:"evidence_ids,omitempty"`
	Status                SecureCellFederationIncidentDirectiveExtensionDisputeStatus     `json:"status"`
	RequestReceiptID      string                                                          `json:"request_receipt_id,omitempty"`
	RequestReceiptHash    string                                                          `json:"request_receipt_hash,omitempty"`
	Resolution            SecureCellFederationIncidentDirectiveExtensionDisputeResolution `json:"resolution,omitempty"`
	ResolutionReceiptID   string                                                          `json:"resolution_receipt_id,omitempty"`
	ResolutionReceiptHash string                                                          `json:"resolution_receipt_hash,omitempty"`
	ResolutionSummary     string                                                          `json:"resolution_summary,omitempty"`
	ResolutionDescription string                                                          `json:"resolution_description,omitempty"`
	ResolutionEvidenceIDs []string                                                        `json:"resolution_evidence_ids,omitempty"`
	ResolvedBy            string                                                          `json:"resolved_by,omitempty"`
	ResolvedAt            *time.Time                                                      `json:"resolved_at,omitempty"`
	CreatedAt             time.Time                                                       `json:"created_at"`
	UpdatedAt             time.Time                                                       `json:"updated_at"`
	Metadata              map[string]string                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionDisputeRequest records one
// challenge against an approved or rejected directive deadline exception.
type SecureCellFederationIncidentDirectiveExtensionDisputeRequest struct {
	ActorDID         string                                    `json:"actor_did,omitempty"`
	ChallengingParty SecureCellFederationIncidentResponseParty `json:"challenging_party,omitempty"`
	Summary          string                                    `json:"summary,omitempty"`
	Description      string                                    `json:"description,omitempty"`
	EvidenceIDs      []string                                  `json:"evidence_ids,omitempty"`
	Reason           string                                    `json:"reason,omitempty"`
	Metadata         map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest records
// one final disposition of a challenged directive deadline exception.
type SecureCellFederationIncidentDirectiveExtensionDisputeResolveRequest struct {
	ActorDID              string                                                          `json:"actor_did,omitempty"`
	RespondingParty       SecureCellFederationIncidentResponseParty                       `json:"responding_party,omitempty"`
	Resolution            SecureCellFederationIncidentDirectiveExtensionDisputeResolution `json:"resolution,omitempty"`
	ResolutionSummary     string                                                          `json:"resolution_summary,omitempty"`
	ResolutionDescription string                                                          `json:"resolution_description,omitempty"`
	EvidenceIDs           []string                                                        `json:"evidence_ids,omitempty"`
	Reason                string                                                          `json:"reason,omitempty"`
	Metadata              map[string]string                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionDisputeFilter narrows operator
// queries across directive exception disputes.
type SecureCellFederationIncidentDirectiveExtensionDisputeFilter struct {
	CellID         string                                                      `json:"cell_id,omitempty"`
	OrganizationID string                                                      `json:"organization_id,omitempty"`
	IncidentID     string                                                      `json:"incident_id,omitempty"`
	ResponseID     string                                                      `json:"response_id,omitempty"`
	DirectiveID    string                                                      `json:"directive_id,omitempty"`
	ExtensionID    string                                                      `json:"extension_id,omitempty"`
	DisputeID      string                                                      `json:"dispute_id,omitempty"`
	Status         SecureCellFederationIncidentDirectiveExtensionDisputeStatus `json:"status,omitempty"`
	Since          *time.Time                                                  `json:"since,omitempty"`
	Until          *time.Time                                                  `json:"until,omitempty"`
	Limit          int                                                         `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionDisputeSummary projects one
// governed challenge over a directive deadline exception.
type SecureCellFederationIncidentDirectiveExtensionDisputeSummary struct {
	CellID            string                                                          `json:"cell_id"`
	CellName          string                                                          `json:"cell_name,omitempty"`
	Jurisdiction      string                                                          `json:"jurisdiction,omitempty"`
	CellStatus        SecureCellStatus                                                `json:"cell_status"`
	ResponseID        string                                                          `json:"response_id"`
	OrganizationID    string                                                          `json:"organization_id"`
	SponsorOfRecord   string                                                          `json:"sponsor_of_record,omitempty"`
	IncidentID        string                                                          `json:"incident_id"`
	DirectiveID       string                                                          `json:"directive_id"`
	DirectiveTitle    string                                                          `json:"directive_title"`
	DirectiveStatus   SecureCellFederationIncidentDirectiveStatus                     `json:"directive_status"`
	ExtensionID       string                                                          `json:"extension_id"`
	ExtensionStatus   SecureCellFederationIncidentDirectiveExtensionStatus            `json:"extension_status"`
	DisputeID         string                                                          `json:"dispute_id"`
	ChallengingParty  SecureCellFederationIncidentResponseParty                       `json:"challenging_party"`
	RespondingParty   SecureCellFederationIncidentResponseParty                       `json:"responding_party"`
	ChallengedStatus  SecureCellFederationIncidentDirectiveExtensionStatus            `json:"challenged_status"`
	DisputedBy        string                                                          `json:"disputed_by,omitempty"`
	Summary           string                                                          `json:"summary"`
	Description       string                                                          `json:"description,omitempty"`
	Status            SecureCellFederationIncidentDirectiveExtensionDisputeStatus     `json:"status"`
	Resolution        SecureCellFederationIncidentDirectiveExtensionDisputeResolution `json:"resolution,omitempty"`
	ResolutionSummary string                                                          `json:"resolution_summary,omitempty"`
	ResolvedBy        string                                                          `json:"resolved_by,omitempty"`
	ResolvedAt        *time.Time                                                      `json:"resolved_at,omitempty"`
	CreatedAt         time.Time                                                       `json:"created_at"`
	UpdatedAt         time.Time                                                       `json:"updated_at"`
	Metadata          map[string]string                                               `json:"metadata,omitempty"`
}

// SecureCellOverdueFederationIncidentDirectiveExtensionFilter narrows
// operator views over directive exception reviews or dispute resolutions that
// crossed a governed deadline.
type SecureCellOverdueFederationIncidentDirectiveExtensionFilter struct {
	CellID         string                                               `json:"cell_id,omitempty"`
	OrganizationID string                                               `json:"organization_id,omitempty"`
	IncidentID     string                                               `json:"incident_id,omitempty"`
	ResponseID     string                                               `json:"response_id,omitempty"`
	DirectiveID    string                                               `json:"directive_id,omitempty"`
	ExtensionID    string                                               `json:"extension_id,omitempty"`
	Status         SecureCellFederationIncidentDirectiveExtensionStatus `json:"status,omitempty"`
	Before         *time.Time                                           `json:"before,omitempty"`
	Limit          int                                                  `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentDirectiveExtension projects one
// exception request or dispute whose next governed milestone is overdue.
type SecureCellOverdueFederationIncidentDirectiveExtension struct {
	CellID           string                                               `json:"cell_id"`
	CellName         string                                               `json:"cell_name,omitempty"`
	Jurisdiction     string                                               `json:"jurisdiction,omitempty"`
	CellStatus       SecureCellStatus                                     `json:"cell_status"`
	ResponseID       string                                               `json:"response_id"`
	OrganizationID   string                                               `json:"organization_id"`
	SponsorOfRecord  string                                               `json:"sponsor_of_record,omitempty"`
	IncidentID       string                                               `json:"incident_id"`
	DirectiveID      string                                               `json:"directive_id"`
	DirectiveTitle   string                                               `json:"directive_title"`
	DirectiveStatus  SecureCellFederationIncidentDirectiveStatus          `json:"directive_status"`
	ExtensionID      string                                               `json:"extension_id"`
	ExtensionStatus  SecureCellFederationIncidentDirectiveExtensionStatus `json:"extension_status"`
	RequestingParty  SecureCellFederationIncidentResponseParty            `json:"requesting_party"`
	ReviewingParty   SecureCellFederationIncidentResponseParty            `json:"reviewing_party"`
	PendingDisputeID string                                               `json:"pending_dispute_id,omitempty"`
	AutomationAction string                                               `json:"automation_action"`
	OverdueReason    string                                               `json:"overdue_reason"`
	PendingAction    string                                               `json:"pending_action"`
	TierID           string                                               `json:"tier_id,omitempty"`
	TargetDID        string                                               `json:"target_did,omitempty"`
	DueAt            time.Time                                            `json:"due_at"`
	OverdueSeconds   int64                                                `json:"overdue_seconds"`
	CurrentDueAt     *time.Time                                           `json:"current_due_at,omitempty"`
	ProposedDueAt    *time.Time                                           `json:"proposed_due_at,omitempty"`
	ReviewDueAt      *time.Time                                           `json:"review_due_at,omitempty"`
	ResolutionDueAt  *time.Time                                           `json:"resolution_due_at,omitempty"`
	UpdatedAt        time.Time                                            `json:"updated_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter
// narrows operator queries over automated exception-review actions.
type SecureCellFederationIncidentDirectiveExtensionAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	ExtensionID    string     `json:"extension_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord
// projects one automated escalation or containment action applied because a
// directive exception review breached its governed deadline.
type SecureCellFederationIncidentDirectiveExtensionAutomationActionRecord struct {
	CellID               string                                               `json:"cell_id"`
	CellName             string                                               `json:"cell_name,omitempty"`
	Jurisdiction         string                                               `json:"jurisdiction,omitempty"`
	CellStatus           SecureCellStatus                                     `json:"cell_status"`
	OrganizationID       string                                               `json:"organization_id,omitempty"`
	SponsorOfRecord      string                                               `json:"sponsor_of_record,omitempty"`
	IncidentID           string                                               `json:"incident_id,omitempty"`
	ResponseID           string                                               `json:"response_id,omitempty"`
	DirectiveID          string                                               `json:"directive_id,omitempty"`
	DirectiveTitle       string                                               `json:"directive_title,omitempty"`
	DirectiveStatus      SecureCellFederationIncidentDirectiveStatus          `json:"directive_status,omitempty"`
	ExtensionID          string                                               `json:"extension_id,omitempty"`
	ExtensionStatus      SecureCellFederationIncidentDirectiveExtensionStatus `json:"extension_status,omitempty"`
	PendingDisputeID     string                                               `json:"pending_dispute_id,omitempty"`
	PendingAction        string                                               `json:"pending_action,omitempty"`
	ContractID           string                                               `json:"contract_id,omitempty"`
	ContractStatusBefore SecureCellFederationContractStatus                   `json:"contract_status_before,omitempty"`
	ContractStatusAfter  SecureCellFederationContractStatus                   `json:"contract_status_after,omitempty"`
	Action               string                                               `json:"action"`
	Trigger              string                                               `json:"trigger,omitempty"`
	TierID               string                                               `json:"tier_id,omitempty"`
	TargetDID            string                                               `json:"target_did,omitempty"`
	DueAt                *time.Time                                           `json:"due_at,omitempty"`
	Actor                string                                               `json:"actor"`
	AutomatedActor       string                                               `json:"automated_actor,omitempty"`
	Reason               string                                               `json:"reason,omitempty"`
	TransitionID         string                                               `json:"transition_id"`
	OccurredAt           time.Time                                            `json:"occurred_at"`
	Metadata             map[string]string                                    `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionSweepResult summarizes one
// automated directive-exception governance sweep across the live secure-cell
// fleet.
type SecureCellFederationIncidentDirectiveExtensionSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	ExtensionsScanned  int       `json:"extensions_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	ResponsesEscalated int       `json:"responses_escalated"`
	ContractsSuspended int       `json:"contracts_suspended"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}
