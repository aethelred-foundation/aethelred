package securecells

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationIncidentResponseSource identifies whether a coordinated
// response was opened for a local incident or a counterparty bulletin.
type SecureCellFederationIncidentResponseSource string

const (
	SecureCellFederationIncidentResponseSourceLocalIncident        SecureCellFederationIncidentResponseSource = "local_incident"
	SecureCellFederationIncidentResponseSourceCounterpartyIncident SecureCellFederationIncidentResponseSource = "counterparty_incident"
)

// SecureCellFederationIncidentResponseParty identifies which organization side
// is expected to acknowledge or remediate a live incident response.
type SecureCellFederationIncidentResponseParty string

const (
	SecureCellFederationIncidentResponsePartyLocalOrg        SecureCellFederationIncidentResponseParty = "local_org"
	SecureCellFederationIncidentResponsePartyCounterpartyOrg SecureCellFederationIncidentResponseParty = "counterparty_org"
)

// SecureCellFederationIncidentResponseStatus captures live cross-org command
// posture for a coordinated incident response.
type SecureCellFederationIncidentResponseStatus string

const (
	SecureCellFederationIncidentResponseStatusPendingLocalAck        SecureCellFederationIncidentResponseStatus = "pending_local_ack"
	SecureCellFederationIncidentResponseStatusPendingCounterpartyAck SecureCellFederationIncidentResponseStatus = "pending_counterparty_ack"
	SecureCellFederationIncidentResponseStatusAcknowledged           SecureCellFederationIncidentResponseStatus = "acknowledged"
	SecureCellFederationIncidentResponseStatusEscalated              SecureCellFederationIncidentResponseStatus = "escalated"
	SecureCellFederationIncidentResponseStatusRemediating            SecureCellFederationIncidentResponseStatus = "remediating"
	SecureCellFederationIncidentResponseStatusRemediated             SecureCellFederationIncidentResponseStatus = "remediated"
	SecureCellFederationIncidentResponseStatusClosed                 SecureCellFederationIncidentResponseStatus = "closed"
)

// SecureCellFederationIncidentPlaybookStepType identifies one timed command
// milestone in the bilateral response playbook.
type SecureCellFederationIncidentPlaybookStepType string

const (
	SecureCellFederationIncidentPlaybookStepTypeAcknowledge SecureCellFederationIncidentPlaybookStepType = "acknowledge"
	SecureCellFederationIncidentPlaybookStepTypeRemediate   SecureCellFederationIncidentPlaybookStepType = "remediate"
	SecureCellFederationIncidentPlaybookStepTypeVerify      SecureCellFederationIncidentPlaybookStepType = "verify_remediation"
)

// SecureCellFederationIncidentPlaybookStepStatus captures whether a timed
// bilateral response milestone is pending, overdue, or completed.
type SecureCellFederationIncidentPlaybookStepStatus string

const (
	SecureCellFederationIncidentPlaybookStepStatusPending   SecureCellFederationIncidentPlaybookStepStatus = "pending"
	SecureCellFederationIncidentPlaybookStepStatusOverdue   SecureCellFederationIncidentPlaybookStepStatus = "overdue"
	SecureCellFederationIncidentPlaybookStepStatusCompleted SecureCellFederationIncidentPlaybookStepStatus = "completed"
)

// SecureCellFederationIncidentPlaybookStep stores one timed bilateral
// response milestone.
type SecureCellFederationIncidentPlaybookStep struct {
	StepID                   string                                         `json:"step_id"`
	ResponseID               string                                         `json:"response_id"`
	Type                     SecureCellFederationIncidentPlaybookStepType   `json:"type"`
	ResponsibleParty         SecureCellFederationIncidentResponseParty      `json:"responsible_party"`
	Title                    string                                         `json:"title,omitempty"`
	Description              string                                         `json:"description,omitempty"`
	DueAt                    *time.Time                                     `json:"due_at,omitempty"`
	Status                   SecureCellFederationIncidentPlaybookStepStatus `json:"status"`
	CompletedBy              string                                         `json:"completed_by,omitempty"`
	CompletedAt              *time.Time                                     `json:"completed_at,omitempty"`
	RemediationAttestationID string                                         `json:"remediation_attestation_id,omitempty"`
	Metadata                 map[string]string                              `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentRemediationAttestation captures one evidence-
// bearing remediation statement inside a coordinated bilateral response.
type SecureCellFederationIncidentRemediationAttestation struct {
	ID                string                                    `json:"id"`
	ResponseID        string                                    `json:"response_id"`
	OrganizationID    string                                    `json:"organization_id"`
	SponsorOfRecord   string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID        string                                    `json:"incident_id"`
	AttestingParty    SecureCellFederationIncidentResponseParty `json:"attesting_party"`
	SubmittedBy       string                                    `json:"submitted_by,omitempty"`
	Summary           string                                    `json:"summary"`
	Description       string                                    `json:"description,omitempty"`
	EvidenceIDs       []string                                  `json:"evidence_ids,omitempty"`
	PolicyReceiptID   string                                    `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                    `json:"policy_receipt_hash,omitempty"`
	SealID            string                                    `json:"seal_id,omitempty"`
	TraceLinkID       string                                    `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time                                 `json:"created_at"`
	Metadata          map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentRemediationVerificationDecision captures the
// reviewing party's disposition on one submitted remediation package.
type SecureCellFederationIncidentRemediationVerificationDecision string

const (
	SecureCellFederationIncidentRemediationVerificationDecisionAccepted SecureCellFederationIncidentRemediationVerificationDecision = "accepted"
	SecureCellFederationIncidentRemediationVerificationDecisionRejected SecureCellFederationIncidentRemediationVerificationDecision = "rejected"
)

// SecureCellFederationIncidentRemediationVerification captures the opposite
// party's evidence-bearing verification or rejection of remediation.
type SecureCellFederationIncidentRemediationVerification struct {
	ID                    string                                                      `json:"id"`
	ResponseID            string                                                      `json:"response_id"`
	OrganizationID        string                                                      `json:"organization_id"`
	SponsorOfRecord       string                                                      `json:"sponsor_of_record,omitempty"`
	IncidentID            string                                                      `json:"incident_id"`
	ReviewingParty        SecureCellFederationIncidentResponseParty                   `json:"reviewing_party"`
	Decision              SecureCellFederationIncidentRemediationVerificationDecision `json:"decision"`
	VerifiedAttestationID string                                                      `json:"verified_attestation_id,omitempty"`
	SubmittedBy           string                                                      `json:"submitted_by,omitempty"`
	Summary               string                                                      `json:"summary"`
	Description           string                                                      `json:"description,omitempty"`
	EvidenceIDs           []string                                                    `json:"evidence_ids,omitempty"`
	PolicyReceiptID       string                                                      `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash     string                                                      `json:"policy_receipt_hash,omitempty"`
	SealID                string                                                      `json:"seal_id,omitempty"`
	TraceLinkID           string                                                      `json:"trace_link_id,omitempty"`
	CreatedAt             time.Time                                                   `json:"created_at"`
	Metadata              map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentClosureAttestation captures the non-closing
// party's evidence-bearing acknowledgement that one coordinated response can
// stay closed.
type SecureCellFederationIncidentClosureAttestation struct {
	ID                string                                    `json:"id"`
	ResponseID        string                                    `json:"response_id"`
	OrganizationID    string                                    `json:"organization_id"`
	SponsorOfRecord   string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID        string                                    `json:"incident_id"`
	AttestingParty    SecureCellFederationIncidentResponseParty `json:"attesting_party"`
	SubmittedBy       string                                    `json:"submitted_by,omitempty"`
	Summary           string                                    `json:"summary"`
	Description       string                                    `json:"description,omitempty"`
	EvidenceIDs       []string                                  `json:"evidence_ids,omitempty"`
	PolicyReceiptID   string                                    `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                    `json:"policy_receipt_hash,omitempty"`
	SealID            string                                    `json:"seal_id,omitempty"`
	TraceLinkID       string                                    `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time                                 `json:"created_at"`
	Metadata          map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDisputeRecord captures one party's decision to
// reopen or dispute a coordinated response outcome.
type SecureCellFederationIncidentDisputeRecord struct {
	ID                     string                                     `json:"id"`
	ResponseID             string                                     `json:"response_id"`
	OrganizationID         string                                     `json:"organization_id"`
	SponsorOfRecord        string                                     `json:"sponsor_of_record,omitempty"`
	IncidentID             string                                     `json:"incident_id"`
	DisputingParty         SecureCellFederationIncidentResponseParty  `json:"disputing_party"`
	SubmittedBy            string                                     `json:"submitted_by,omitempty"`
	RelatedVerificationID  string                                     `json:"related_verification_id,omitempty"`
	RelatedClosureID       string                                     `json:"related_closure_id,omitempty"`
	Summary                string                                     `json:"summary"`
	Description            string                                     `json:"description,omitempty"`
	EvidenceIDs            []string                                   `json:"evidence_ids,omitempty"`
	Reopened               bool                                       `json:"reopened"`
	ReopenedResponseStatus SecureCellFederationIncidentResponseStatus `json:"reopened_response_status,omitempty"`
	PolicyReceiptID        string                                     `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                                     `json:"policy_receipt_hash,omitempty"`
	SealID                 string                                     `json:"seal_id,omitempty"`
	TraceLinkID            string                                     `json:"trace_link_id,omitempty"`
	CreatedAt              time.Time                                  `json:"created_at"`
	Metadata               map[string]string                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveStatus captures the lifecycle of one
// cross-organization incident command directive.
type SecureCellFederationIncidentDirectiveStatus string

const (
	SecureCellFederationIncidentDirectiveStatusIssued       SecureCellFederationIncidentDirectiveStatus = "issued"
	SecureCellFederationIncidentDirectiveStatusAcknowledged SecureCellFederationIncidentDirectiveStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveStatusCompleted    SecureCellFederationIncidentDirectiveStatus = "completed"
	SecureCellFederationIncidentDirectiveStatusVerified     SecureCellFederationIncidentDirectiveStatus = "verified"
)

// SecureCellFederationIncidentDirectivePriority captures how urgently one
// bilateral incident directive should be executed.
type SecureCellFederationIncidentDirectivePriority string

const (
	SecureCellFederationIncidentDirectivePriorityLow      SecureCellFederationIncidentDirectivePriority = "low"
	SecureCellFederationIncidentDirectivePriorityMedium   SecureCellFederationIncidentDirectivePriority = "medium"
	SecureCellFederationIncidentDirectivePriorityHigh     SecureCellFederationIncidentDirectivePriority = "high"
	SecureCellFederationIncidentDirectivePriorityCritical SecureCellFederationIncidentDirectivePriority = "critical"
)

// SecureCellFederationIncidentDirectiveVerificationDecision captures the
// reviewing party's disposition on one completed bilateral directive.
type SecureCellFederationIncidentDirectiveVerificationDecision string

const (
	SecureCellFederationIncidentDirectiveVerificationDecisionAccepted SecureCellFederationIncidentDirectiveVerificationDecision = "accepted"
	SecureCellFederationIncidentDirectiveVerificationDecisionRejected SecureCellFederationIncidentDirectiveVerificationDecision = "rejected"
)

// SecureCellFederationIncidentDirectiveExtensionStatus captures the lifecycle
// of one governed deadline exception request for a bilateral directive.
type SecureCellFederationIncidentDirectiveExtensionStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionStatusPendingReview SecureCellFederationIncidentDirectiveExtensionStatus = "pending_review"
	SecureCellFederationIncidentDirectiveExtensionStatusApproved      SecureCellFederationIncidentDirectiveExtensionStatus = "approved"
	SecureCellFederationIncidentDirectiveExtensionStatusRejected      SecureCellFederationIncidentDirectiveExtensionStatus = "rejected"
	SecureCellFederationIncidentDirectiveExtensionStatusDisputed      SecureCellFederationIncidentDirectiveExtensionStatus = "disputed"
)

// SecureCellFederationIncidentDirectiveExtension preserves one evidence-bearing
// deadline exception request and review for a bilateral directive.
type SecureCellFederationIncidentDirectiveExtension struct {
	ID                         string                                                     `json:"id"`
	ResponseID                 string                                                     `json:"response_id"`
	DirectiveID                string                                                     `json:"directive_id"`
	OrganizationID             string                                                     `json:"organization_id"`
	SponsorOfRecord            string                                                     `json:"sponsor_of_record,omitempty"`
	IncidentID                 string                                                     `json:"incident_id"`
	RequestingParty            SecureCellFederationIncidentResponseParty                  `json:"requesting_party"`
	ReviewingParty             SecureCellFederationIncidentResponseParty                  `json:"reviewing_party"`
	RequestedBy                string                                                     `json:"requested_by,omitempty"`
	Summary                    string                                                     `json:"summary"`
	Description                string                                                     `json:"description,omitempty"`
	EvidenceIDs                []string                                                   `json:"evidence_ids,omitempty"`
	CurrentDueAt               *time.Time                                                 `json:"current_due_at,omitempty"`
	ProposedDueAt              *time.Time                                                 `json:"proposed_due_at,omitempty"`
	ReviewApprovalThreshold    int                                                        `json:"review_approval_threshold,omitempty"`
	EligibleReviewerDIDs       []string                                                   `json:"eligible_reviewer_dids,omitempty"`
	ReviewVotes                []SecureCellFederationIncidentDirectiveExtensionReviewVote `json:"review_votes,omitempty"`
	ReviewDelegations          []SecureCellFederationIncidentDirectiveExtensionDelegation `json:"review_delegations,omitempty"`
	DisputeResolutionThreshold int                                                        `json:"dispute_resolution_threshold,omitempty"`
	EligibleResolverDIDs       []string                                                   `json:"eligible_resolver_dids,omitempty"`
	Status                     SecureCellFederationIncidentDirectiveExtensionStatus       `json:"status"`
	RequestReceiptID           string                                                     `json:"request_receipt_id,omitempty"`
	RequestReceiptHash         string                                                     `json:"request_receipt_hash,omitempty"`
	DecisionReceiptID          string                                                     `json:"decision_receipt_id,omitempty"`
	DecisionReceiptHash        string                                                     `json:"decision_receipt_hash,omitempty"`
	DecisionSummary            string                                                     `json:"decision_summary,omitempty"`
	DecisionDescription        string                                                     `json:"decision_description,omitempty"`
	DecisionEvidenceIDs        []string                                                   `json:"decision_evidence_ids,omitempty"`
	ReviewedBy                 string                                                     `json:"reviewed_by,omitempty"`
	ReviewedAt                 *time.Time                                                 `json:"reviewed_at,omitempty"`
	Disputes                   []SecureCellFederationIncidentDirectiveExtensionDispute    `json:"disputes,omitempty"`
	CreatedAt                  time.Time                                                  `json:"created_at"`
	UpdatedAt                  time.Time                                                  `json:"updated_at"`
	Metadata                   map[string]string                                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirective is one evidence-bearing cross-org work
// order tied to a live bilateral incident response.
type SecureCellFederationIncidentDirective struct {
	ID                         string                                                    `json:"id"`
	ResponseID                 string                                                    `json:"response_id"`
	OrganizationID             string                                                    `json:"organization_id"`
	SponsorOfRecord            string                                                    `json:"sponsor_of_record,omitempty"`
	IncidentID                 string                                                    `json:"incident_id"`
	DirectiveType              string                                                    `json:"directive_type,omitempty"`
	Title                      string                                                    `json:"title"`
	Summary                    string                                                    `json:"summary"`
	Description                string                                                    `json:"description,omitempty"`
	Priority                   SecureCellFederationIncidentDirectivePriority             `json:"priority"`
	Status                     SecureCellFederationIncidentDirectiveStatus               `json:"status"`
	IssuingParty               SecureCellFederationIncidentResponseParty                 `json:"issuing_party"`
	AssigneeParty              SecureCellFederationIncidentResponseParty                 `json:"assignee_party"`
	ReviewerParty              SecureCellFederationIncidentResponseParty                 `json:"reviewer_party"`
	AssigneeDID                string                                                    `json:"assignee_did,omitempty"`
	ReviewerDID                string                                                    `json:"reviewer_did,omitempty"`
	RelatedReportIDs           []string                                                  `json:"related_report_ids,omitempty"`
	RelatedAmendmentIDs        []string                                                  `json:"related_amendment_ids,omitempty"`
	EvidenceIDs                []string                                                  `json:"evidence_ids,omitempty"`
	DueAt                      *time.Time                                                `json:"due_at,omitempty"`
	AcknowledgementReceiptID   string                                                    `json:"acknowledgement_receipt_id,omitempty"`
	AcknowledgementReceiptHash string                                                    `json:"acknowledgement_receipt_hash,omitempty"`
	AcknowledgedBy             string                                                    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt             *time.Time                                                `json:"acknowledged_at,omitempty"`
	CompletionReceiptID        string                                                    `json:"completion_receipt_id,omitempty"`
	CompletionReceiptHash      string                                                    `json:"completion_receipt_hash,omitempty"`
	CompletionSummary          string                                                    `json:"completion_summary,omitempty"`
	CompletionDescription      string                                                    `json:"completion_description,omitempty"`
	CompletionEvidenceIDs      []string                                                  `json:"completion_evidence_ids,omitempty"`
	CompletedBy                string                                                    `json:"completed_by,omitempty"`
	CompletedAt                *time.Time                                                `json:"completed_at,omitempty"`
	Extensions                 []SecureCellFederationIncidentDirectiveExtension          `json:"extensions,omitempty"`
	VerificationDecision       SecureCellFederationIncidentDirectiveVerificationDecision `json:"verification_decision,omitempty"`
	VerificationReceiptID      string                                                    `json:"verification_receipt_id,omitempty"`
	VerificationReceiptHash    string                                                    `json:"verification_receipt_hash,omitempty"`
	VerificationSummary        string                                                    `json:"verification_summary,omitempty"`
	VerificationDescription    string                                                    `json:"verification_description,omitempty"`
	VerificationEvidenceIDs    []string                                                  `json:"verification_evidence_ids,omitempty"`
	VerifiedBy                 string                                                    `json:"verified_by,omitempty"`
	VerifiedAt                 *time.Time                                                `json:"verified_at,omitempty"`
	CreatedBy                  string                                                    `json:"created_by,omitempty"`
	CreatedAt                  time.Time                                                 `json:"created_at"`
	UpdatedAt                  time.Time                                                 `json:"updated_at"`
	Metadata                   map[string]string                                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponse is the canonical bilateral command case
// for one local or imported federation incident.
type SecureCellFederationIncidentResponse struct {
	ID                       string                                                `json:"id"`
	OrganizationID           string                                                `json:"organization_id"`
	SponsorOfRecord          string                                                `json:"sponsor_of_record,omitempty"`
	OrganizationName         string                                                `json:"organization_name,omitempty"`
	SourceType               SecureCellFederationIncidentResponseSource            `json:"source_type"`
	SourceSnapshotID         string                                                `json:"source_snapshot_id,omitempty"`
	SourceBulletinID         string                                                `json:"source_bulletin_id,omitempty"`
	IncidentID               string                                                `json:"incident_id"`
	IncidentStatus           SecureCellFederationIncidentStatus                    `json:"incident_status"`
	IncidentSeverity         SecureCellFederationIncidentSeverity                  `json:"incident_severity"`
	IncidentCategory         SecureCellFederationIncidentCategory                  `json:"incident_category"`
	IncidentSummary          string                                                `json:"incident_summary"`
	IncidentDescription      string                                                `json:"incident_description,omitempty"`
	ContractIDs              []string                                              `json:"contract_ids,omitempty"`
	SessionIDs               []string                                              `json:"session_ids,omitempty"`
	ThreadIDs                []string                                              `json:"thread_ids,omitempty"`
	SharedOutputIDs          []string                                              `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs       []string                                              `json:"session_exchange_ids,omitempty"`
	Status                   SecureCellFederationIncidentResponseStatus            `json:"status"`
	RequiredAcknowledgement  SecureCellFederationIncidentResponseParty             `json:"required_acknowledgement"`
	ExpectedRemediationFrom  SecureCellFederationIncidentResponseParty             `json:"expected_remediation_from"`
	VerificationRequiredFrom SecureCellFederationIncidentResponseParty             `json:"verification_required_from"`
	PlaybookTemplate         string                                                `json:"playbook_template,omitempty"`
	EscalationLadder         []SecureCellFederationEscalationTier                  `json:"escalation_ladder,omitempty"`
	EscalatedTierIDs         []string                                              `json:"escalated_tier_ids,omitempty"`
	PlaybookSteps            []SecureCellFederationIncidentPlaybookStep            `json:"playbook_steps,omitempty"`
	IncidentDirectives       []SecureCellFederationIncidentDirective               `json:"incident_directives,omitempty"`
	RemediationAttestations  []SecureCellFederationIncidentRemediationAttestation  `json:"remediation_attestations,omitempty"`
	RemediationVerifications []SecureCellFederationIncidentRemediationVerification `json:"remediation_verifications,omitempty"`
	IncidentReports          []SecureCellFederationIncidentReport                  `json:"incident_reports,omitempty"`
	ClosureAttestations      []SecureCellFederationIncidentClosureAttestation      `json:"closure_attestations,omitempty"`
	Disputes                 []SecureCellFederationIncidentDisputeRecord           `json:"disputes,omitempty"`
	AcknowledgedBy           string                                                `json:"acknowledged_by,omitempty"`
	AcknowledgedAt           *time.Time                                            `json:"acknowledged_at,omitempty"`
	RemediatedBy             string                                                `json:"remediated_by,omitempty"`
	RemediatedAt             *time.Time                                            `json:"remediated_at,omitempty"`
	VerifiedBy               string                                                `json:"verified_by,omitempty"`
	VerifiedAt               *time.Time                                            `json:"verified_at,omitempty"`
	ClosedBy                 string                                                `json:"closed_by,omitempty"`
	ClosedAt                 *time.Time                                            `json:"closed_at,omitempty"`
	LastDisputedBy           string                                                `json:"last_disputed_by,omitempty"`
	LastDisputedAt           *time.Time                                            `json:"last_disputed_at,omitempty"`
	ReopenedBy               string                                                `json:"reopened_by,omitempty"`
	ReopenedAt               *time.Time                                            `json:"reopened_at,omitempty"`
	ReopenReason             string                                                `json:"reopen_reason,omitempty"`
	CreatedAt                time.Time                                             `json:"created_at"`
	UpdatedAt                time.Time                                             `json:"updated_at"`
	Metadata                 map[string]string                                     `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponseAcknowledgeRequest records cross-org or
// local acknowledgement for one coordinated incident response.
type SecureCellFederationIncidentResponseAcknowledgeRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponseEscalateRequest escalates one overdue or
// manually escalated coordinated incident response tier.
type SecureCellFederationIncidentResponseEscalateRequest struct {
	ActorDID string            `json:"actor_did,omitempty"`
	TierID   string            `json:"tier_id,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentRemediationAttestationRequest submits one
// evidence-bearing remediation attestation into a bilateral response.
type SecureCellFederationIncidentRemediationAttestationRequest struct {
	ActorDID       string                                    `json:"actor_did,omitempty"`
	AttestingParty SecureCellFederationIncidentResponseParty `json:"attesting_party,omitempty"`
	Summary        string                                    `json:"summary,omitempty"`
	Description    string                                    `json:"description,omitempty"`
	EvidenceIDs    []string                                  `json:"evidence_ids,omitempty"`
	Reason         string                                    `json:"reason,omitempty"`
	Metadata       map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentRemediationVerificationRequest submits one
// evidence-bearing verification or rejection against remediation.
type SecureCellFederationIncidentRemediationVerificationRequest struct {
	ActorDID              string                                                      `json:"actor_did,omitempty"`
	ReviewingParty        SecureCellFederationIncidentResponseParty                   `json:"reviewing_party,omitempty"`
	Decision              SecureCellFederationIncidentRemediationVerificationDecision `json:"decision,omitempty"`
	VerifiedAttestationID string                                                      `json:"verified_attestation_id,omitempty"`
	Summary               string                                                      `json:"summary,omitempty"`
	Description           string                                                      `json:"description,omitempty"`
	EvidenceIDs           []string                                                    `json:"evidence_ids,omitempty"`
	Reason                string                                                      `json:"reason,omitempty"`
	Metadata              map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentClosureAttestationRequest submits one
// evidence-bearing closure acknowledgement from the non-closing party.
type SecureCellFederationIncidentClosureAttestationRequest struct {
	ActorDID       string                                    `json:"actor_did,omitempty"`
	AttestingParty SecureCellFederationIncidentResponseParty `json:"attesting_party,omitempty"`
	Summary        string                                    `json:"summary,omitempty"`
	Description    string                                    `json:"description,omitempty"`
	EvidenceIDs    []string                                  `json:"evidence_ids,omitempty"`
	Reason         string                                    `json:"reason,omitempty"`
	Metadata       map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponseDisputeRequest disputes one coordinated
// outcome and reopens the bilateral response workflow.
type SecureCellFederationIncidentResponseDisputeRequest struct {
	ActorDID              string                                    `json:"actor_did,omitempty"`
	DisputingParty        SecureCellFederationIncidentResponseParty `json:"disputing_party,omitempty"`
	RelatedVerificationID string                                    `json:"related_verification_id,omitempty"`
	RelatedClosureID      string                                    `json:"related_closure_id,omitempty"`
	Summary               string                                    `json:"summary,omitempty"`
	Description           string                                    `json:"description,omitempty"`
	EvidenceIDs           []string                                  `json:"evidence_ids,omitempty"`
	Reason                string                                    `json:"reason,omitempty"`
	Metadata              map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveCreateRequest issues one new bilateral
// incident command directive into a live response.
type SecureCellFederationIncidentDirectiveCreateRequest struct {
	ActorDID            string                                        `json:"actor_did,omitempty"`
	DirectiveType       string                                        `json:"directive_type,omitempty"`
	Title               string                                        `json:"title,omitempty"`
	Summary             string                                        `json:"summary,omitempty"`
	Description         string                                        `json:"description,omitempty"`
	Priority            SecureCellFederationIncidentDirectivePriority `json:"priority,omitempty"`
	AssigneeParty       SecureCellFederationIncidentResponseParty     `json:"assignee_party,omitempty"`
	ReviewerParty       SecureCellFederationIncidentResponseParty     `json:"reviewer_party,omitempty"`
	AssigneeDID         string                                        `json:"assignee_did,omitempty"`
	ReviewerDID         string                                        `json:"reviewer_did,omitempty"`
	RelatedReportIDs    []string                                      `json:"related_report_ids,omitempty"`
	RelatedAmendmentIDs []string                                      `json:"related_amendment_ids,omitempty"`
	EvidenceIDs         []string                                      `json:"evidence_ids,omitempty"`
	DueAt               *time.Time                                    `json:"due_at,omitempty"`
	Reason              string                                        `json:"reason,omitempty"`
	Metadata            map[string]string                             `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveAcknowledgeRequest records assignee
// acknowledgement for one issued directive.
type SecureCellFederationIncidentDirectiveAcknowledgeRequest struct {
	ActorDID           string                                    `json:"actor_did,omitempty"`
	AcknowledgingParty SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Reason             string                                    `json:"reason,omitempty"`
	Metadata           map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveCompleteRequest records assignee
// completion evidence for one acknowledged directive.
type SecureCellFederationIncidentDirectiveCompleteRequest struct {
	ActorDID              string                                    `json:"actor_did,omitempty"`
	CompletingParty       SecureCellFederationIncidentResponseParty `json:"completing_party,omitempty"`
	CompletionSummary     string                                    `json:"completion_summary,omitempty"`
	CompletionDescription string                                    `json:"completion_description,omitempty"`
	EvidenceIDs           []string                                  `json:"evidence_ids,omitempty"`
	Reason                string                                    `json:"reason,omitempty"`
	Metadata              map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveVerifyRequest records reviewer
// verification or rejection of one completed directive.
type SecureCellFederationIncidentDirectiveVerifyRequest struct {
	ActorDID                string                                                    `json:"actor_did,omitempty"`
	ReviewingParty          SecureCellFederationIncidentResponseParty                 `json:"reviewing_party,omitempty"`
	Decision                SecureCellFederationIncidentDirectiveVerificationDecision `json:"decision,omitempty"`
	VerificationSummary     string                                                    `json:"verification_summary,omitempty"`
	VerificationDescription string                                                    `json:"verification_description,omitempty"`
	EvidenceIDs             []string                                                  `json:"evidence_ids,omitempty"`
	Reason                  string                                                    `json:"reason,omitempty"`
	Metadata                map[string]string                                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionRequest opens one governed
// deadline exception request for a bilateral directive.
type SecureCellFederationIncidentDirectiveExtensionRequest struct {
	ActorDID                   string                                    `json:"actor_did,omitempty"`
	RequestingParty            SecureCellFederationIncidentResponseParty `json:"requesting_party,omitempty"`
	Summary                    string                                    `json:"summary,omitempty"`
	Description                string                                    `json:"description,omitempty"`
	EvidenceIDs                []string                                  `json:"evidence_ids,omitempty"`
	ProposedDueAt              *time.Time                                `json:"proposed_due_at,omitempty"`
	ReviewApprovalThreshold    int                                       `json:"review_approval_threshold,omitempty"`
	EligibleReviewerDIDs       []string                                  `json:"eligible_reviewer_dids,omitempty"`
	DisputeResolutionThreshold int                                       `json:"dispute_resolution_threshold,omitempty"`
	EligibleResolverDIDs       []string                                  `json:"eligible_resolver_dids,omitempty"`
	Reason                     string                                    `json:"reason,omitempty"`
	Metadata                   map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionApproveRequest records one
// reviewer decision that grants a directive deadline exception.
type SecureCellFederationIncidentDirectiveExtensionApproveRequest struct {
	ActorDID            string                                    `json:"actor_did,omitempty"`
	ReviewingParty      SecureCellFederationIncidentResponseParty `json:"reviewing_party,omitempty"`
	DecisionSummary     string                                    `json:"decision_summary,omitempty"`
	DecisionDescription string                                    `json:"decision_description,omitempty"`
	EvidenceIDs         []string                                  `json:"evidence_ids,omitempty"`
	Reason              string                                    `json:"reason,omitempty"`
	Metadata            map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionRejectRequest records one
// reviewer decision that denies a directive deadline exception.
type SecureCellFederationIncidentDirectiveExtensionRejectRequest struct {
	ActorDID            string                                    `json:"actor_did,omitempty"`
	ReviewingParty      SecureCellFederationIncidentResponseParty `json:"reviewing_party,omitempty"`
	DecisionSummary     string                                    `json:"decision_summary,omitempty"`
	DecisionDescription string                                    `json:"decision_description,omitempty"`
	EvidenceIDs         []string                                  `json:"evidence_ids,omitempty"`
	Reason              string                                    `json:"reason,omitempty"`
	Metadata            map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponseFilter narrows operator queries across
// coordinated bilateral incident responses.
type SecureCellFederationIncidentResponseFilter struct {
	CellID         string                                     `json:"cell_id,omitempty"`
	OrganizationID string                                     `json:"organization_id,omitempty"`
	IncidentID     string                                     `json:"incident_id,omitempty"`
	ResponseID     string                                     `json:"response_id,omitempty"`
	ContractID     string                                     `json:"contract_id,omitempty"`
	Status         SecureCellFederationIncidentResponseStatus `json:"status,omitempty"`
	SourceType     SecureCellFederationIncidentResponseSource `json:"source_type,omitempty"`
	Limit          int                                        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentResponseSummary is the operator-facing projection
// of one bilateral incident response case.
type SecureCellFederationIncidentResponseSummary struct {
	CellID                   string                                                      `json:"cell_id"`
	CellName                 string                                                      `json:"cell_name,omitempty"`
	CellStatus               SecureCellStatus                                            `json:"cell_status"`
	Jurisdiction             string                                                      `json:"jurisdiction,omitempty"`
	ResponseID               string                                                      `json:"response_id"`
	OrganizationID           string                                                      `json:"organization_id"`
	SponsorOfRecord          string                                                      `json:"sponsor_of_record,omitempty"`
	OrganizationName         string                                                      `json:"organization_name,omitempty"`
	SourceType               SecureCellFederationIncidentResponseSource                  `json:"source_type"`
	SourceSnapshotID         string                                                      `json:"source_snapshot_id,omitempty"`
	SourceBulletinID         string                                                      `json:"source_bulletin_id,omitempty"`
	IncidentID               string                                                      `json:"incident_id"`
	IncidentStatus           SecureCellFederationIncidentStatus                          `json:"incident_status"`
	IncidentSeverity         SecureCellFederationIncidentSeverity                        `json:"incident_severity"`
	IncidentCategory         SecureCellFederationIncidentCategory                        `json:"incident_category"`
	IncidentSummary          string                                                      `json:"incident_summary"`
	IncidentDescription      string                                                      `json:"incident_description,omitempty"`
	Status                   SecureCellFederationIncidentResponseStatus                  `json:"status"`
	RequiredAcknowledgement  SecureCellFederationIncidentResponseParty                   `json:"required_acknowledgement"`
	ExpectedRemediationFrom  SecureCellFederationIncidentResponseParty                   `json:"expected_remediation_from"`
	VerificationRequiredFrom SecureCellFederationIncidentResponseParty                   `json:"verification_required_from"`
	PlaybookTemplate         string                                                      `json:"playbook_template,omitempty"`
	ContractIDs              []string                                                    `json:"contract_ids,omitempty"`
	SessionIDs               []string                                                    `json:"session_ids,omitempty"`
	ThreadIDs                []string                                                    `json:"thread_ids,omitempty"`
	SharedOutputIDs          []string                                                    `json:"shared_output_ids,omitempty"`
	SessionExchangeIDs       []string                                                    `json:"session_exchange_ids,omitempty"`
	ContractCount            int                                                         `json:"contract_count"`
	SessionCount             int                                                         `json:"session_count"`
	ThreadCount              int                                                         `json:"thread_count"`
	SharedOutputCount        int                                                         `json:"shared_output_count"`
	SessionExchangeCount     int                                                         `json:"session_exchange_count"`
	AckDueAt                 *time.Time                                                  `json:"ack_due_at,omitempty"`
	AckStatus                SecureCellFederationIncidentPlaybookStepStatus              `json:"ack_status,omitempty"`
	RemediationDueAt         *time.Time                                                  `json:"remediation_due_at,omitempty"`
	RemediationStatus        SecureCellFederationIncidentPlaybookStepStatus              `json:"remediation_status,omitempty"`
	VerificationDueAt        *time.Time                                                  `json:"verification_due_at,omitempty"`
	VerificationStatus       SecureCellFederationIncidentPlaybookStepStatus              `json:"verification_status,omitempty"`
	EscalationTierCount      int                                                         `json:"escalation_tier_count"`
	EscalatedTierCount       int                                                         `json:"escalated_tier_count"`
	NextEscalationTierID     string                                                      `json:"next_escalation_tier_id,omitempty"`
	NextEscalationTargetDID  string                                                      `json:"next_escalation_target_did,omitempty"`
	RemediationCount         int                                                         `json:"remediation_count"`
	VerificationCount        int                                                         `json:"verification_count"`
	ReportCount              int                                                         `json:"report_count"`
	PendingReportCount       int                                                         `json:"pending_report_count"`
	AcknowledgedReportCount  int                                                         `json:"acknowledged_report_count"`
	OverdueReportCount       int                                                         `json:"overdue_report_count"`
	NextReportDueAt          *time.Time                                                  `json:"next_report_due_at,omitempty"`
	DirectiveCount           int                                                         `json:"directive_count"`
	PendingDirectiveCount    int                                                         `json:"pending_directive_count"`
	OverdueDirectiveCount    int                                                         `json:"overdue_directive_count"`
	NextDirectiveDueAt       *time.Time                                                  `json:"next_directive_due_at,omitempty"`
	ClosureAttestationCount  int                                                         `json:"closure_attestation_count"`
	DisputeCount             int                                                         `json:"dispute_count"`
	LastVerificationDecision SecureCellFederationIncidentRemediationVerificationDecision `json:"last_verification_decision,omitempty"`
	AcknowledgedBy           string                                                      `json:"acknowledged_by,omitempty"`
	AcknowledgedAt           *time.Time                                                  `json:"acknowledged_at,omitempty"`
	RemediatedBy             string                                                      `json:"remediated_by,omitempty"`
	RemediatedAt             *time.Time                                                  `json:"remediated_at,omitempty"`
	VerifiedBy               string                                                      `json:"verified_by,omitempty"`
	VerifiedAt               *time.Time                                                  `json:"verified_at,omitempty"`
	ClosedBy                 string                                                      `json:"closed_by,omitempty"`
	ClosedAt                 *time.Time                                                  `json:"closed_at,omitempty"`
	LastDisputedBy           string                                                      `json:"last_disputed_by,omitempty"`
	LastDisputedAt           *time.Time                                                  `json:"last_disputed_at,omitempty"`
	ReopenedBy               string                                                      `json:"reopened_by,omitempty"`
	ReopenedAt               *time.Time                                                  `json:"reopened_at,omitempty"`
	ClosureReady             bool                                                        `json:"closure_ready"`
	CreatedAt                time.Time                                                   `json:"created_at"`
	UpdatedAt                time.Time                                                   `json:"updated_at"`
}

// SecureCellOverdueFederationIncidentResponseFilter narrows operator queries
// over timed bilateral response cases that crossed their next playbook or
// escalation milestone.
type SecureCellOverdueFederationIncidentResponseFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Before         *time.Time `json:"before,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentResponse projects one timed bilateral
// incident response that crossed its next acknowledgement or remediation
// automation milestone.
type SecureCellOverdueFederationIncidentResponse struct {
	CellID            string                                         `json:"cell_id"`
	CellName          string                                         `json:"cell_name,omitempty"`
	Jurisdiction      string                                         `json:"jurisdiction,omitempty"`
	CellStatus        SecureCellStatus                               `json:"cell_status"`
	ResponseID        string                                         `json:"response_id"`
	OrganizationID    string                                         `json:"organization_id"`
	SponsorOfRecord   string                                         `json:"sponsor_of_record,omitempty"`
	IncidentID        string                                         `json:"incident_id"`
	IncidentSeverity  SecureCellFederationIncidentSeverity           `json:"incident_severity"`
	IncidentCategory  SecureCellFederationIncidentCategory           `json:"incident_category"`
	IncidentSummary   string                                         `json:"incident_summary"`
	ResponseStatus    SecureCellFederationIncidentResponseStatus     `json:"response_status"`
	SourceType        SecureCellFederationIncidentResponseSource     `json:"source_type"`
	PlaybookTemplate  string                                         `json:"playbook_template,omitempty"`
	OverdueStepType   SecureCellFederationIncidentPlaybookStepType   `json:"overdue_step_type"`
	OverdueStepStatus SecureCellFederationIncidentPlaybookStepStatus `json:"overdue_step_status"`
	AutomationAction  string                                         `json:"automation_action"`
	OverdueReason     string                                         `json:"overdue_reason"`
	TierID            string                                         `json:"tier_id,omitempty"`
	TargetDID         string                                         `json:"target_did,omitempty"`
	DueAt             time.Time                                      `json:"due_at"`
	OverdueSeconds    int64                                          `json:"overdue_seconds"`
	AcknowledgedAt    *time.Time                                     `json:"acknowledged_at,omitempty"`
	RemediatedAt      *time.Time                                     `json:"remediated_at,omitempty"`
	VerifiedAt        *time.Time                                     `json:"verified_at,omitempty"`
	ClosedAt          *time.Time                                     `json:"closed_at,omitempty"`
	UpdatedAt         time.Time                                      `json:"updated_at"`
}

// SecureCellFederationIncidentResponseActionFilter narrows operator queries
// across response acknowledgements, escalations, and remediation attestations.
type SecureCellFederationIncidentResponseActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentResponseActionRecord projects one evidence-
// bearing command action inside the bilateral response fabric.
type SecureCellFederationIncidentResponseActionRecord struct {
	CellID               string                                     `json:"cell_id"`
	CellName             string                                     `json:"cell_name,omitempty"`
	Jurisdiction         string                                     `json:"jurisdiction,omitempty"`
	CellStatus           SecureCellStatus                           `json:"cell_status"`
	OrganizationID       string                                     `json:"organization_id,omitempty"`
	SponsorOfRecord      string                                     `json:"sponsor_of_record,omitempty"`
	IncidentID           string                                     `json:"incident_id,omitempty"`
	ResponseID           string                                     `json:"response_id,omitempty"`
	ContractIDs          []string                                   `json:"contract_ids,omitempty"`
	SourceType           SecureCellFederationIncidentResponseSource `json:"source_type,omitempty"`
	ResponseStatusBefore SecureCellFederationIncidentResponseStatus `json:"response_status_before,omitempty"`
	ResponseStatusAfter  SecureCellFederationIncidentResponseStatus `json:"response_status_after,omitempty"`
	Action               string                                     `json:"action"`
	Trigger              string                                     `json:"trigger,omitempty"`
	TierID               string                                     `json:"tier_id,omitempty"`
	TargetDID            string                                     `json:"target_did,omitempty"`
	Actor                string                                     `json:"actor"`
	AutomatedActor       string                                     `json:"automated_actor,omitempty"`
	Reason               string                                     `json:"reason,omitempty"`
	TransitionID         string                                     `json:"transition_id"`
	OccurredAt           time.Time                                  `json:"occurred_at"`
	Metadata             map[string]string                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveFilter narrows operator queries across
// bilateral directive work orders.
type SecureCellFederationIncidentDirectiveFilter struct {
	CellID         string                                        `json:"cell_id,omitempty"`
	OrganizationID string                                        `json:"organization_id,omitempty"`
	IncidentID     string                                        `json:"incident_id,omitempty"`
	ResponseID     string                                        `json:"response_id,omitempty"`
	DirectiveID    string                                        `json:"directive_id,omitempty"`
	AssigneeParty  SecureCellFederationIncidentResponseParty     `json:"assignee_party,omitempty"`
	ReviewerParty  SecureCellFederationIncidentResponseParty     `json:"reviewer_party,omitempty"`
	Status         SecureCellFederationIncidentDirectiveStatus   `json:"status,omitempty"`
	Priority       SecureCellFederationIncidentDirectivePriority `json:"priority,omitempty"`
	Since          *time.Time                                    `json:"since,omitempty"`
	Until          *time.Time                                    `json:"until,omitempty"`
	Limit          int                                           `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveSummary projects one bilateral incident
// directive for operator and auditor use.
type SecureCellFederationIncidentDirectiveSummary struct {
	CellID                     string                                                    `json:"cell_id"`
	CellName                   string                                                    `json:"cell_name,omitempty"`
	Jurisdiction               string                                                    `json:"jurisdiction,omitempty"`
	CellStatus                 SecureCellStatus                                          `json:"cell_status"`
	ResponseID                 string                                                    `json:"response_id"`
	OrganizationID             string                                                    `json:"organization_id"`
	SponsorOfRecord            string                                                    `json:"sponsor_of_record,omitempty"`
	IncidentID                 string                                                    `json:"incident_id"`
	DirectiveID                string                                                    `json:"directive_id"`
	DirectiveType              string                                                    `json:"directive_type,omitempty"`
	Title                      string                                                    `json:"title"`
	Summary                    string                                                    `json:"summary"`
	Description                string                                                    `json:"description,omitempty"`
	Priority                   SecureCellFederationIncidentDirectivePriority             `json:"priority"`
	Status                     SecureCellFederationIncidentDirectiveStatus               `json:"status"`
	IssuingParty               SecureCellFederationIncidentResponseParty                 `json:"issuing_party"`
	AssigneeParty              SecureCellFederationIncidentResponseParty                 `json:"assignee_party"`
	ReviewerParty              SecureCellFederationIncidentResponseParty                 `json:"reviewer_party"`
	AssigneeDID                string                                                    `json:"assignee_did,omitempty"`
	ReviewerDID                string                                                    `json:"reviewer_did,omitempty"`
	RelatedReportIDs           []string                                                  `json:"related_report_ids,omitempty"`
	RelatedAmendmentIDs        []string                                                  `json:"related_amendment_ids,omitempty"`
	EvidenceIDs                []string                                                  `json:"evidence_ids,omitempty"`
	DueAt                      *time.Time                                                `json:"due_at,omitempty"`
	Overdue                    bool                                                      `json:"overdue"`
	ExtensionCount             int                                                       `json:"extension_count"`
	PendingExtensionCount      int                                                       `json:"pending_extension_count"`
	LastExtensionID            string                                                    `json:"last_extension_id,omitempty"`
	LastExtensionStatus        SecureCellFederationIncidentDirectiveExtensionStatus      `json:"last_extension_status,omitempty"`
	LastExtensionProposedDueAt *time.Time                                                `json:"last_extension_proposed_due_at,omitempty"`
	AcknowledgedBy             string                                                    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt             *time.Time                                                `json:"acknowledged_at,omitempty"`
	CompletedBy                string                                                    `json:"completed_by,omitempty"`
	CompletedAt                *time.Time                                                `json:"completed_at,omitempty"`
	VerificationDecision       SecureCellFederationIncidentDirectiveVerificationDecision `json:"verification_decision,omitempty"`
	VerifiedBy                 string                                                    `json:"verified_by,omitempty"`
	VerifiedAt                 *time.Time                                                `json:"verified_at,omitempty"`
	CreatedBy                  string                                                    `json:"created_by,omitempty"`
	CreatedAt                  time.Time                                                 `json:"created_at"`
	UpdatedAt                  time.Time                                                 `json:"updated_at"`
	Metadata                   map[string]string                                         `json:"metadata,omitempty"`
}

// SecureCellOverdueFederationIncidentDirectiveFilter narrows operator views
// over directive work orders that crossed their deadline.
type SecureCellOverdueFederationIncidentDirectiveFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	Before         *time.Time `json:"before,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentDirective projects one directive that is
// still awaiting completion or verification after its due time.
type SecureCellOverdueFederationIncidentDirective struct {
	CellID                        string                                        `json:"cell_id"`
	CellName                      string                                        `json:"cell_name,omitempty"`
	Jurisdiction                  string                                        `json:"jurisdiction,omitempty"`
	CellStatus                    SecureCellStatus                              `json:"cell_status"`
	ResponseID                    string                                        `json:"response_id"`
	OrganizationID                string                                        `json:"organization_id"`
	SponsorOfRecord               string                                        `json:"sponsor_of_record,omitempty"`
	IncidentID                    string                                        `json:"incident_id"`
	DirectiveID                   string                                        `json:"directive_id"`
	Title                         string                                        `json:"title"`
	Priority                      SecureCellFederationIncidentDirectivePriority `json:"priority"`
	Status                        SecureCellFederationIncidentDirectiveStatus   `json:"status"`
	AssigneeParty                 SecureCellFederationIncidentResponseParty     `json:"assignee_party"`
	ReviewerParty                 SecureCellFederationIncidentResponseParty     `json:"reviewer_party"`
	PendingAction                 string                                        `json:"pending_action"`
	PendingExtensionID            string                                        `json:"pending_extension_id,omitempty"`
	PendingExtensionProposedDueAt *time.Time                                    `json:"pending_extension_proposed_due_at,omitempty"`
	DueAt                         time.Time                                     `json:"due_at"`
	OverdueSeconds                int64                                         `json:"overdue_seconds"`
	UpdatedAt                     time.Time                                     `json:"updated_at"`
}

// SecureCellFederationIncidentDirectiveExtensionFilter narrows operator
// queries across directive deadline exception records.
type SecureCellFederationIncidentDirectiveExtensionFilter struct {
	CellID         string                                               `json:"cell_id,omitempty"`
	OrganizationID string                                               `json:"organization_id,omitempty"`
	IncidentID     string                                               `json:"incident_id,omitempty"`
	ResponseID     string                                               `json:"response_id,omitempty"`
	DirectiveID    string                                               `json:"directive_id,omitempty"`
	ExtensionID    string                                               `json:"extension_id,omitempty"`
	Status         SecureCellFederationIncidentDirectiveExtensionStatus `json:"status,omitempty"`
	Since          *time.Time                                           `json:"since,omitempty"`
	Until          *time.Time                                           `json:"until,omitempty"`
	Limit          int                                                  `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionSummary projects one governed
// deadline exception record for operator and auditor use.
type SecureCellFederationIncidentDirectiveExtensionSummary struct {
	CellID                     string                                                      `json:"cell_id"`
	CellName                   string                                                      `json:"cell_name,omitempty"`
	Jurisdiction               string                                                      `json:"jurisdiction,omitempty"`
	CellStatus                 SecureCellStatus                                            `json:"cell_status"`
	ResponseID                 string                                                      `json:"response_id"`
	OrganizationID             string                                                      `json:"organization_id"`
	SponsorOfRecord            string                                                      `json:"sponsor_of_record,omitempty"`
	IncidentID                 string                                                      `json:"incident_id"`
	DirectiveID                string                                                      `json:"directive_id"`
	DirectiveTitle             string                                                      `json:"directive_title"`
	DirectiveStatus            SecureCellFederationIncidentDirectiveStatus                 `json:"directive_status"`
	ExtensionID                string                                                      `json:"extension_id"`
	RequestingParty            SecureCellFederationIncidentResponseParty                   `json:"requesting_party"`
	ReviewingParty             SecureCellFederationIncidentResponseParty                   `json:"reviewing_party"`
	RequestedBy                string                                                      `json:"requested_by,omitempty"`
	Summary                    string                                                      `json:"summary"`
	Description                string                                                      `json:"description,omitempty"`
	CurrentDueAt               *time.Time                                                  `json:"current_due_at,omitempty"`
	ProposedDueAt              *time.Time                                                  `json:"proposed_due_at,omitempty"`
	Status                     SecureCellFederationIncidentDirectiveExtensionStatus        `json:"status"`
	ReviewApprovalThreshold    int                                                         `json:"review_approval_threshold"`
	EligibleReviewerCount      int                                                         `json:"eligible_reviewer_count"`
	ReviewDelegationCount      int                                                         `json:"review_delegation_count"`
	ApproveVoteCount           int                                                         `json:"approve_vote_count"`
	RejectVoteCount            int                                                         `json:"reject_vote_count"`
	ReviewThresholdSatisfied   bool                                                        `json:"review_threshold_satisfied"`
	DisputeResolutionThreshold int                                                         `json:"dispute_resolution_threshold"`
	EligibleResolverCount      int                                                         `json:"eligible_resolver_count"`
	DisputeCount               int                                                         `json:"dispute_count"`
	PendingDisputeCount        int                                                         `json:"pending_dispute_count"`
	LastDisputeID              string                                                      `json:"last_dispute_id,omitempty"`
	LastDisputeStatus          SecureCellFederationIncidentDirectiveExtensionDisputeStatus `json:"last_dispute_status,omitempty"`
	DecisionSummary            string                                                      `json:"decision_summary,omitempty"`
	ReviewedBy                 string                                                      `json:"reviewed_by,omitempty"`
	ReviewedAt                 *time.Time                                                  `json:"reviewed_at,omitempty"`
	CreatedAt                  time.Time                                                   `json:"created_at"`
	UpdatedAt                  time.Time                                                   `json:"updated_at"`
	Metadata                   map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveActionFilter narrows operator queries
// across directive issuance, acknowledgement, completion, and verification.
type SecureCellFederationIncidentDirectiveActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveActionRecord projects one evidence-
// bearing directive lifecycle transition.
type SecureCellFederationIncidentDirectiveActionRecord struct {
	CellID          string                                      `json:"cell_id"`
	CellName        string                                      `json:"cell_name,omitempty"`
	Jurisdiction    string                                      `json:"jurisdiction,omitempty"`
	CellStatus      SecureCellStatus                            `json:"cell_status"`
	OrganizationID  string                                      `json:"organization_id,omitempty"`
	SponsorOfRecord string                                      `json:"sponsor_of_record,omitempty"`
	IncidentID      string                                      `json:"incident_id,omitempty"`
	ResponseID      string                                      `json:"response_id,omitempty"`
	DirectiveID     string                                      `json:"directive_id,omitempty"`
	StatusBefore    SecureCellFederationIncidentDirectiveStatus `json:"status_before,omitempty"`
	StatusAfter     SecureCellFederationIncidentDirectiveStatus `json:"status_after,omitempty"`
	Action          string                                      `json:"action"`
	Actor           string                                      `json:"actor"`
	Reason          string                                      `json:"reason,omitempty"`
	TransitionID    string                                      `json:"transition_id"`
	OccurredAt      time.Time                                   `json:"occurred_at"`
	Metadata        map[string]string                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveAutomationActionFilter narrows
// operator queries across automated directive supervision actions.
type SecureCellFederationIncidentDirectiveAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveAutomationActionRecord projects one
// automated escalation or containment action applied because a directive
// missed its governed deadline.
type SecureCellFederationIncidentDirectiveAutomationActionRecord struct {
	CellID               string                                        `json:"cell_id"`
	CellName             string                                        `json:"cell_name,omitempty"`
	Jurisdiction         string                                        `json:"jurisdiction,omitempty"`
	CellStatus           SecureCellStatus                              `json:"cell_status"`
	OrganizationID       string                                        `json:"organization_id,omitempty"`
	SponsorOfRecord      string                                        `json:"sponsor_of_record,omitempty"`
	IncidentID           string                                        `json:"incident_id,omitempty"`
	ResponseID           string                                        `json:"response_id,omitempty"`
	DirectiveID          string                                        `json:"directive_id,omitempty"`
	DirectiveTitle       string                                        `json:"directive_title,omitempty"`
	DirectivePriority    SecureCellFederationIncidentDirectivePriority `json:"directive_priority,omitempty"`
	DirectiveStatus      SecureCellFederationIncidentDirectiveStatus   `json:"directive_status,omitempty"`
	PendingAction        string                                        `json:"pending_action,omitempty"`
	ContractID           string                                        `json:"contract_id,omitempty"`
	ContractStatusBefore SecureCellFederationContractStatus            `json:"contract_status_before,omitempty"`
	ContractStatusAfter  SecureCellFederationContractStatus            `json:"contract_status_after,omitempty"`
	Action               string                                        `json:"action"`
	Trigger              string                                        `json:"trigger,omitempty"`
	TierID               string                                        `json:"tier_id,omitempty"`
	TargetDID            string                                        `json:"target_did,omitempty"`
	DueAt                *time.Time                                    `json:"due_at,omitempty"`
	Actor                string                                        `json:"actor"`
	AutomatedActor       string                                        `json:"automated_actor,omitempty"`
	Reason               string                                        `json:"reason,omitempty"`
	TransitionID         string                                        `json:"transition_id"`
	OccurredAt           time.Time                                     `json:"occurred_at"`
	Metadata             map[string]string                             `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveSweepResult summarizes one automated
// directive-supervision pass across the secure-cell fleet.
type SecureCellFederationIncidentDirectiveSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	DirectivesScanned  int       `json:"directives_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	ResponsesEscalated int       `json:"responses_escalated"`
	ContractsSuspended int       `json:"contracts_suspended"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}

// SecureCellFederationIncidentRemediationFilter narrows operator queries
// across submitted remediation attestations.
type SecureCellFederationIncidentRemediationFilter struct {
	CellID         string                                    `json:"cell_id,omitempty"`
	OrganizationID string                                    `json:"organization_id,omitempty"`
	IncidentID     string                                    `json:"incident_id,omitempty"`
	ResponseID     string                                    `json:"response_id,omitempty"`
	AttestingParty SecureCellFederationIncidentResponseParty `json:"attesting_party,omitempty"`
	Since          *time.Time                                `json:"since,omitempty"`
	Until          *time.Time                                `json:"until,omitempty"`
	Limit          int                                       `json:"limit,omitempty"`
}

// SecureCellFederationIncidentRemediationSummary projects one evidence-
// bearing remediation attestation for operator export and audit use.
type SecureCellFederationIncidentRemediationSummary struct {
	CellID            string                                    `json:"cell_id"`
	CellName          string                                    `json:"cell_name,omitempty"`
	Jurisdiction      string                                    `json:"jurisdiction,omitempty"`
	CellStatus        SecureCellStatus                          `json:"cell_status"`
	ResponseID        string                                    `json:"response_id"`
	OrganizationID    string                                    `json:"organization_id"`
	SponsorOfRecord   string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID        string                                    `json:"incident_id"`
	AttestationID     string                                    `json:"attestation_id"`
	AttestingParty    SecureCellFederationIncidentResponseParty `json:"attesting_party"`
	SubmittedBy       string                                    `json:"submitted_by,omitempty"`
	Summary           string                                    `json:"summary"`
	Description       string                                    `json:"description,omitempty"`
	EvidenceIDs       []string                                  `json:"evidence_ids,omitempty"`
	PolicyReceiptID   string                                    `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                    `json:"policy_receipt_hash,omitempty"`
	SealID            string                                    `json:"seal_id,omitempty"`
	TraceLinkID       string                                    `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time                                 `json:"created_at"`
	Metadata          map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentVerificationFilter narrows operator queries over
// remediation verifications recorded for bilateral incident responses.
type SecureCellFederationIncidentVerificationFilter struct {
	CellID         string                                                      `json:"cell_id,omitempty"`
	OrganizationID string                                                      `json:"organization_id,omitempty"`
	IncidentID     string                                                      `json:"incident_id,omitempty"`
	ResponseID     string                                                      `json:"response_id,omitempty"`
	ReviewingParty SecureCellFederationIncidentResponseParty                   `json:"reviewing_party,omitempty"`
	Decision       SecureCellFederationIncidentRemediationVerificationDecision `json:"decision,omitempty"`
	Since          *time.Time                                                  `json:"since,omitempty"`
	Until          *time.Time                                                  `json:"until,omitempty"`
	Limit          int                                                         `json:"limit,omitempty"`
}

// SecureCellFederationIncidentVerificationSummary projects one remediation
// verification decision for operator export and audit use.
type SecureCellFederationIncidentVerificationSummary struct {
	CellID                string                                                      `json:"cell_id"`
	CellName              string                                                      `json:"cell_name,omitempty"`
	Jurisdiction          string                                                      `json:"jurisdiction,omitempty"`
	CellStatus            SecureCellStatus                                            `json:"cell_status"`
	ResponseID            string                                                      `json:"response_id"`
	OrganizationID        string                                                      `json:"organization_id"`
	SponsorOfRecord       string                                                      `json:"sponsor_of_record,omitempty"`
	IncidentID            string                                                      `json:"incident_id"`
	VerificationID        string                                                      `json:"verification_id"`
	ReviewingParty        SecureCellFederationIncidentResponseParty                   `json:"reviewing_party"`
	Decision              SecureCellFederationIncidentRemediationVerificationDecision `json:"decision"`
	VerifiedAttestationID string                                                      `json:"verified_attestation_id,omitempty"`
	SubmittedBy           string                                                      `json:"submitted_by,omitempty"`
	Summary               string                                                      `json:"summary"`
	Description           string                                                      `json:"description,omitempty"`
	EvidenceIDs           []string                                                    `json:"evidence_ids,omitempty"`
	PolicyReceiptID       string                                                      `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash     string                                                      `json:"policy_receipt_hash,omitempty"`
	SealID                string                                                      `json:"seal_id,omitempty"`
	TraceLinkID           string                                                      `json:"trace_link_id,omitempty"`
	CreatedAt             time.Time                                                   `json:"created_at"`
	Metadata              map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentClosureAttestationFilter narrows operator
// queries over bilateral closure attestations.
type SecureCellFederationIncidentClosureAttestationFilter struct {
	CellID         string                                    `json:"cell_id,omitempty"`
	OrganizationID string                                    `json:"organization_id,omitempty"`
	IncidentID     string                                    `json:"incident_id,omitempty"`
	ResponseID     string                                    `json:"response_id,omitempty"`
	AttestingParty SecureCellFederationIncidentResponseParty `json:"attesting_party,omitempty"`
	Since          *time.Time                                `json:"since,omitempty"`
	Until          *time.Time                                `json:"until,omitempty"`
	Limit          int                                       `json:"limit,omitempty"`
}

// SecureCellFederationIncidentClosureAttestationSummary projects one closure
// attestation for operator export and audit use.
type SecureCellFederationIncidentClosureAttestationSummary struct {
	CellID            string                                    `json:"cell_id"`
	CellName          string                                    `json:"cell_name,omitempty"`
	Jurisdiction      string                                    `json:"jurisdiction,omitempty"`
	CellStatus        SecureCellStatus                          `json:"cell_status"`
	ResponseID        string                                    `json:"response_id"`
	OrganizationID    string                                    `json:"organization_id"`
	SponsorOfRecord   string                                    `json:"sponsor_of_record,omitempty"`
	IncidentID        string                                    `json:"incident_id"`
	AttestationID     string                                    `json:"attestation_id"`
	AttestingParty    SecureCellFederationIncidentResponseParty `json:"attesting_party"`
	SubmittedBy       string                                    `json:"submitted_by,omitempty"`
	Summary           string                                    `json:"summary"`
	Description       string                                    `json:"description,omitempty"`
	EvidenceIDs       []string                                  `json:"evidence_ids,omitempty"`
	PolicyReceiptID   string                                    `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                    `json:"policy_receipt_hash,omitempty"`
	SealID            string                                    `json:"seal_id,omitempty"`
	TraceLinkID       string                                    `json:"trace_link_id,omitempty"`
	CreatedAt         time.Time                                 `json:"created_at"`
	Metadata          map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDisputeFilter narrows operator queries across
// response disputes and reopen events.
type SecureCellFederationIncidentDisputeFilter struct {
	CellID         string                                    `json:"cell_id,omitempty"`
	OrganizationID string                                    `json:"organization_id,omitempty"`
	IncidentID     string                                    `json:"incident_id,omitempty"`
	ResponseID     string                                    `json:"response_id,omitempty"`
	DisputingParty SecureCellFederationIncidentResponseParty `json:"disputing_party,omitempty"`
	Since          *time.Time                                `json:"since,omitempty"`
	Until          *time.Time                                `json:"until,omitempty"`
	Limit          int                                       `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDisputeSummary projects one bilateral dispute
// or reopen event for operator export and audit use.
type SecureCellFederationIncidentDisputeSummary struct {
	CellID                 string                                     `json:"cell_id"`
	CellName               string                                     `json:"cell_name,omitempty"`
	Jurisdiction           string                                     `json:"jurisdiction,omitempty"`
	CellStatus             SecureCellStatus                           `json:"cell_status"`
	ResponseID             string                                     `json:"response_id"`
	OrganizationID         string                                     `json:"organization_id"`
	SponsorOfRecord        string                                     `json:"sponsor_of_record,omitempty"`
	IncidentID             string                                     `json:"incident_id"`
	DisputeID              string                                     `json:"dispute_id"`
	DisputingParty         SecureCellFederationIncidentResponseParty  `json:"disputing_party"`
	SubmittedBy            string                                     `json:"submitted_by,omitempty"`
	RelatedVerificationID  string                                     `json:"related_verification_id,omitempty"`
	RelatedClosureID       string                                     `json:"related_closure_id,omitempty"`
	Summary                string                                     `json:"summary"`
	Description            string                                     `json:"description,omitempty"`
	EvidenceIDs            []string                                   `json:"evidence_ids,omitempty"`
	Reopened               bool                                       `json:"reopened"`
	ReopenedResponseStatus SecureCellFederationIncidentResponseStatus `json:"reopened_response_status,omitempty"`
	PolicyReceiptID        string                                     `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash      string                                     `json:"policy_receipt_hash,omitempty"`
	SealID                 string                                     `json:"seal_id,omitempty"`
	TraceLinkID            string                                     `json:"trace_link_id,omitempty"`
	CreatedAt              time.Time                                  `json:"created_at"`
	Metadata               map[string]string                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentResponseSweepResult summarizes one automated
// bilateral response escalation pass across live secure cells.
type SecureCellFederationIncidentResponseSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	ResponsesScanned   int       `json:"responses_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	ResponsesEscalated int       `json:"responses_escalated"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}

func (s *Service) AcknowledgeFederationIncidentResponse(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentResponseAcknowledgeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if secureCellFederationIncidentResponseClosed(*response) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q is %s", ErrFederationIncidentResponseImmutable, responseID, response.Status)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, response.RequiredAcknowledgement) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: actor %q is not permitted to acknowledge response %q", ErrPolicyDenied, actorDID, responseID)
	}
	if response.AcknowledgedAt != nil && !response.AcknowledgedAt.IsZero() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q is already acknowledged", ErrFederationIncidentResponseImmutable, responseID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_response", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":       response.ID,
		"federation_organization_id":            response.OrganizationID,
		"federation_sponsor_of_record":          response.SponsorOfRecord,
		"federation_incident_id":                response.IncidentID,
		"federation_incident_response_source":   string(response.SourceType),
		"federation_incident_response_status":   string(response.Status),
		"federation_incident_response_ack_from": string(response.RequiredAcknowledgement),
		"transition_reason":                     strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	statusBefore := response.Status
	run.result.FederationIncidentResponses[idx].AcknowledgedBy = actorDID
	run.result.FederationIncidentResponses[idx].AcknowledgedAt = cloneTimePtr(&now)
	secureCellCompleteFederationIncidentPlaybookStep(&run.result.FederationIncidentResponses[idx], SecureCellFederationIncidentPlaybookStepTypeAcknowledge, actorDID, now, "")
	if secureCellFederationIncidentResponseHasExpectedRemediation(run.result.FederationIncidentResponses[idx]) {
		run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusRemediated
		run.result.FederationIncidentResponses[idx].RemediatedBy = firstNonEmpty(run.result.FederationIncidentResponses[idx].RemediatedBy, actorDID)
		if run.result.FederationIncidentResponses[idx].RemediatedAt == nil {
			run.result.FederationIncidentResponses[idx].RemediatedAt = cloneTimePtr(&now)
		}
	} else {
		run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusAcknowledged
	}
	run.result.FederationIncidentResponses[idx].UpdatedAt = now
	run.result.FederationIncidentResponses[idx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[idx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_response_acknowledged", response.ID),
		Action:           "secure_cell.federation_incident_response_acknowledged",
		Actor:            actorDID,
		TargetType:       "federation_incident_response",
		TargetDID:        response.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":            response.ID,
			"federation_incident_response_status_before": string(statusBefore),
			"federation_incident_response_status_after":  string(run.result.FederationIncidentResponses[idx].Status),
			"federation_incident_response_source":        string(response.SourceType),
			"federation_organization_id":                 response.OrganizationID,
			"federation_sponsor_of_record":               response.SponsorOfRecord,
			"federation_incident_id":                     response.IncidentID,
			"federation_incident_status":                 string(response.IncidentStatus),
			"federation_incident_severity":               string(response.IncidentSeverity),
			"federation_incident_category":               string(response.IncidentCategory),
			"federation_incident_response_action":        "acknowledge",
			"federation_incident_response_ack_from":      string(response.RequiredAcknowledgement),
			"federation_contract_ids":                    strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) EscalateFederationIncidentResponse(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentResponseEscalateRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if secureCellFederationIncidentResponseClosed(*response) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q is %s", ErrFederationIncidentResponseImmutable, responseID, response.Status)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: actor %q is not permitted to escalate response %q", ErrPolicyDenied, actorDID, responseID)
	}
	now := time.Now().UTC()
	tier, stepType, overdueReason, err := secureCellResolveFederationIncidentResponseEscalation(*response, now, strings.TrimSpace(req.TierID))
	if err != nil {
		return nil, err
	}
	receipt, err := s.evaluateStage(ctx, run.request, "escalate_federation_incident_response", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":           response.ID,
		"federation_organization_id":                response.OrganizationID,
		"federation_sponsor_of_record":              response.SponsorOfRecord,
		"federation_incident_id":                    response.IncidentID,
		"federation_incident_response_source":       string(response.SourceType),
		"federation_incident_response_status":       string(response.Status),
		"federation_incident_response_tier_id":      tier.TierID,
		"federation_incident_response_target_did":   tier.TargetDID,
		"federation_incident_response_overdue_step": string(stepType),
		"transition_reason":                         firstNonEmpty(strings.TrimSpace(req.Reason), overdueReason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w", ErrPolicyDenied)
	}

	statusBefore := response.Status
	run.result.FederationIncidentResponses[idx].EscalatedTierIDs = append(run.result.FederationIncidentResponses[idx].EscalatedTierIDs, strings.TrimSpace(tier.TierID))
	run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusEscalated
	run.result.FederationIncidentResponses[idx].UpdatedAt = now
	run.result.FederationIncidentResponses[idx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[idx].Metadata, req.Metadata)
	secureCellMarkFederationIncidentPlaybookStepOverdue(&run.result.FederationIncidentResponses[idx], stepType, now)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_response_escalated", response.ID),
		Action:           "secure_cell.federation_incident_response_escalated",
		Actor:            actorDID,
		TargetType:       "federation_incident_response",
		TargetDID:        response.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), overdueReason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":            response.ID,
			"federation_incident_response_status_before": string(statusBefore),
			"federation_incident_response_status_after":  string(run.result.FederationIncidentResponses[idx].Status),
			"federation_incident_response_source":        string(response.SourceType),
			"federation_organization_id":                 response.OrganizationID,
			"federation_sponsor_of_record":               response.SponsorOfRecord,
			"federation_incident_id":                     response.IncidentID,
			"federation_incident_status":                 string(response.IncidentStatus),
			"federation_incident_severity":               string(response.IncidentSeverity),
			"federation_incident_category":               string(response.IncidentCategory),
			"federation_incident_response_action":        "escalate",
			"federation_incident_response_tier_id":       strings.TrimSpace(tier.TierID),
			"federation_incident_response_target_did":    strings.TrimSpace(tier.TargetDID),
			"federation_incident_response_overdue_step":  string(stepType),
			"federation_contract_ids":                    strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AttestFederationIncidentRemediation(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentRemediationAttestationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if secureCellFederationIncidentResponseClosed(*response) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q is %s", ErrFederationIncidentResponseImmutable, responseID, response.Status)
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-response: remediation summary is required")
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.AttestingParty)
	if party == "" {
		party = response.ExpectedRemediationFrom
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: actor %q is not permitted to attest remediation for response %q", ErrPolicyDenied, actorDID, responseID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "attest_federation_incident_remediation", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":          response.ID,
		"federation_organization_id":               response.OrganizationID,
		"federation_sponsor_of_record":             response.SponsorOfRecord,
		"federation_incident_id":                   response.IncidentID,
		"federation_incident_response_source":      string(response.SourceType),
		"federation_incident_response_status":      string(response.Status),
		"federation_incident_remediation_party":    string(party),
		"federation_incident_remediation_evidence": strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason":                        firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	statusBefore := response.Status
	attestation := SecureCellFederationIncidentRemediationAttestation{
		ID:                secureCellFederationIncidentRemediationAttestationID(*response, actorDID, now, len(run.result.FederationIncidentResponses[idx].RemediationAttestations)),
		ResponseID:        response.ID,
		OrganizationID:    response.OrganizationID,
		SponsorOfRecord:   response.SponsorOfRecord,
		IncidentID:        response.IncidentID,
		AttestingParty:    party,
		SubmittedBy:       actorDID,
		Summary:           strings.TrimSpace(req.Summary),
		Description:       strings.TrimSpace(req.Description),
		EvidenceIDs:       append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	run.result.FederationIncidentResponses[idx].RemediationAttestations = append(run.result.FederationIncidentResponses[idx].RemediationAttestations, attestation)
	run.result.FederationIncidentResponses[idx].UpdatedAt = now
	run.result.FederationIncidentResponses[idx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[idx].Metadata, req.Metadata)
	if party == run.result.FederationIncidentResponses[idx].ExpectedRemediationFrom {
		secureCellCompleteFederationIncidentPlaybookStep(&run.result.FederationIncidentResponses[idx], SecureCellFederationIncidentPlaybookStepTypeRemediate, actorDID, now, attestation.ID)
		run.result.FederationIncidentResponses[idx].RemediatedBy = actorDID
		run.result.FederationIncidentResponses[idx].RemediatedAt = cloneTimePtr(&now)
		run.result.FederationIncidentResponses[idx].VerifiedBy = ""
		run.result.FederationIncidentResponses[idx].VerifiedAt = nil
		run.result.FederationIncidentResponses[idx].ClosedBy = ""
		run.result.FederationIncidentResponses[idx].ClosedAt = nil
		secureCellResetFederationIncidentPlaybookStep(&run.result.FederationIncidentResponses[idx], SecureCellFederationIncidentPlaybookStepTypeVerify, now, secureCellFederationIncidentResponseVerifyDeadline(run.result.FederationIncidentResponses[idx], now), false)
		if run.result.FederationIncidentResponses[idx].AcknowledgedAt != nil && !run.result.FederationIncidentResponses[idx].AcknowledgedAt.IsZero() {
			run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusRemediated
		} else {
			run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusRemediating
		}
	}
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_response_remediation_attested", response.ID),
		Action:           "secure_cell.federation_incident_response_remediation_attested",
		Actor:            actorDID,
		TargetType:       "federation_incident_response",
		TargetDID:        response.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":             response.ID,
			"federation_incident_response_status_before":  string(statusBefore),
			"federation_incident_response_status_after":   string(run.result.FederationIncidentResponses[idx].Status),
			"federation_incident_response_source":         string(response.SourceType),
			"federation_organization_id":                  response.OrganizationID,
			"federation_sponsor_of_record":                response.SponsorOfRecord,
			"federation_incident_id":                      response.IncidentID,
			"federation_incident_status":                  string(response.IncidentStatus),
			"federation_incident_severity":                string(response.IncidentSeverity),
			"federation_incident_category":                string(response.IncidentCategory),
			"federation_incident_response_action":         "attest_remediation",
			"federation_incident_remediation_attestation": attestation.ID,
			"federation_incident_remediation_party":       string(attestation.AttestingParty),
			"federation_incident_remediation_evidence":    strings.Join(attestation.EvidenceIDs, ","),
			"federation_contract_ids":                     strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) VerifyFederationIncidentRemediation(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentRemediationVerificationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if secureCellFederationIncidentResponseClosed(*response) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q is %s", ErrFederationIncidentResponseImmutable, responseID, response.Status)
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-response: remediation verification summary is required")
	}
	decision := secureCellNormalizedFederationIncidentRemediationVerificationDecision(req.Decision)
	if decision == "" {
		decision = SecureCellFederationIncidentRemediationVerificationDecisionAccepted
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.ReviewingParty)
	if party == "" {
		party = response.VerificationRequiredFrom
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: actor %q is not permitted to verify remediation for response %q", ErrPolicyDenied, actorDID, responseID)
	}
	verifiedAttestationID := strings.TrimSpace(req.VerifiedAttestationID)
	if verifiedAttestationID == "" {
		verifiedAttestationID = secureCellLatestFederationIncidentRemediationAttestationID(*response, response.ExpectedRemediationFrom)
	}
	if verifiedAttestationID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q has no remediation attestation to verify", ErrFederationIncidentResponseImmutable, responseID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "verify_federation_incident_remediation", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":             response.ID,
		"federation_organization_id":                  response.OrganizationID,
		"federation_sponsor_of_record":                response.SponsorOfRecord,
		"federation_incident_id":                      response.IncidentID,
		"federation_incident_response_source":         string(response.SourceType),
		"federation_incident_response_status":         string(response.Status),
		"federation_incident_verification_party":      string(party),
		"federation_incident_verification_decision":   string(decision),
		"federation_incident_verified_attestation_id": verifiedAttestationID,
		"federation_incident_verification_evidence":   strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason":                           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	statusBefore := response.Status
	verification := SecureCellFederationIncidentRemediationVerification{
		ID:                    secureCellFederationIncidentRemediationVerificationID(*response, actorDID, now, len(run.result.FederationIncidentResponses[idx].RemediationVerifications)),
		ResponseID:            response.ID,
		OrganizationID:        response.OrganizationID,
		SponsorOfRecord:       response.SponsorOfRecord,
		IncidentID:            response.IncidentID,
		ReviewingParty:        party,
		Decision:              decision,
		VerifiedAttestationID: verifiedAttestationID,
		SubmittedBy:           actorDID,
		Summary:               strings.TrimSpace(req.Summary),
		Description:           strings.TrimSpace(req.Description),
		EvidenceIDs:           append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		PolicyReceiptID:       receipt.ID,
		PolicyReceiptHash:     receipt.ContentHash,
		CreatedAt:             now,
		Metadata:              cloneStringMap(req.Metadata),
	}
	run.result.FederationIncidentResponses[idx].RemediationVerifications = append(run.result.FederationIncidentResponses[idx].RemediationVerifications, verification)
	run.result.FederationIncidentResponses[idx].UpdatedAt = now
	run.result.FederationIncidentResponses[idx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[idx].Metadata, req.Metadata)
	switch decision {
	case SecureCellFederationIncidentRemediationVerificationDecisionAccepted:
		secureCellCompleteFederationIncidentPlaybookStep(&run.result.FederationIncidentResponses[idx], SecureCellFederationIncidentPlaybookStepTypeVerify, actorDID, now, verification.ID)
		run.result.FederationIncidentResponses[idx].VerifiedBy = actorDID
		run.result.FederationIncidentResponses[idx].VerifiedAt = cloneTimePtr(&now)
		if run.result.FederationIncidentResponses[idx].IncidentStatus == SecureCellFederationIncidentStatusResolved && run.result.FederationIncidentResponses[idx].AcknowledgedAt != nil && run.result.FederationIncidentResponses[idx].RemediatedAt != nil {
			run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusClosed
			run.result.FederationIncidentResponses[idx].ClosedBy = actorDID
			run.result.FederationIncidentResponses[idx].ClosedAt = cloneTimePtr(&now)
		} else {
			run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusRemediated
		}
	case SecureCellFederationIncidentRemediationVerificationDecisionRejected:
		dispute := secureCellReopenFederationIncidentResponse(&run.result.FederationIncidentResponses[idx], SecureCellFederationIncidentResponseDisputeRequest{
			ActorDID:              actorDID,
			DisputingParty:        party,
			RelatedVerificationID: verification.ID,
			Summary:               firstNonEmpty(strings.TrimSpace(req.Summary), "Remediation verification rejected"),
			Description:           strings.TrimSpace(req.Description),
			EvidenceIDs:           append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
			Reason:                firstNonEmpty(strings.TrimSpace(req.Reason), "verification rejected"),
			Metadata:              mergeStringMaps(req.Metadata, map[string]string{"reopened_from_verification_decision": string(verification.Decision)}),
		}, receipt, now)
		verification.Metadata = mergeStringMaps(verification.Metadata, map[string]string{"reopened_dispute_id": dispute.ID})
		run.result.FederationIncidentResponses[idx].RemediationVerifications[len(run.result.FederationIncidentResponses[idx].RemediationVerifications)-1] = verification
	}
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_remediation_verified", response.ID),
		Action:           "secure_cell.federation_incident_remediation_verified",
		Actor:            actorDID,
		TargetType:       "federation_incident_response",
		TargetDID:        response.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":             response.ID,
			"federation_incident_response_status_before":  string(statusBefore),
			"federation_incident_response_status_after":   string(run.result.FederationIncidentResponses[idx].Status),
			"federation_incident_response_source":         string(response.SourceType),
			"federation_organization_id":                  response.OrganizationID,
			"federation_sponsor_of_record":                response.SponsorOfRecord,
			"federation_incident_id":                      response.IncidentID,
			"federation_incident_status":                  string(response.IncidentStatus),
			"federation_incident_severity":                string(response.IncidentSeverity),
			"federation_incident_category":                string(response.IncidentCategory),
			"federation_incident_response_action":         "verify_remediation",
			"federation_incident_verification_id":         verification.ID,
			"federation_incident_verification_party":      string(verification.ReviewingParty),
			"federation_incident_verification_decision":   string(verification.Decision),
			"federation_incident_verified_attestation_id": verification.VerifiedAttestationID,
			"federation_incident_verification_evidence":   strings.Join(verification.EvidenceIDs, ","),
			"federation_contract_ids":                     strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AttestFederationIncidentClosure(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentClosureAttestationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-response: closure attestation summary is required")
	}
	if response.Status != SecureCellFederationIncidentResponseStatusClosed && !secureCellFederationIncidentResponseClosureReady(*response) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: response %q is not ready for closure attestation", ErrFederationIncidentResponseImmutable, responseID)
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.AttestingParty)
	if party == "" {
		party = secureCellFederationIncidentResponseClosureParty(*response)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: actor %q is not permitted to attest closure for response %q", ErrPolicyDenied, actorDID, responseID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "attest_federation_incident_closure", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":             response.ID,
		"federation_organization_id":                  response.OrganizationID,
		"federation_sponsor_of_record":                response.SponsorOfRecord,
		"federation_incident_id":                      response.IncidentID,
		"federation_incident_response_source":         string(response.SourceType),
		"federation_incident_response_status":         string(response.Status),
		"federation_incident_closure_attesting_party": string(party),
		"federation_incident_closure_evidence":        strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason":                           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	if run.result.FederationIncidentResponses[idx].Status != SecureCellFederationIncidentResponseStatusClosed {
		run.result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusClosed
		if strings.TrimSpace(run.result.FederationIncidentResponses[idx].ClosedBy) == "" {
			run.result.FederationIncidentResponses[idx].ClosedBy = strings.TrimSpace(actorDID)
		}
		if run.result.FederationIncidentResponses[idx].ClosedAt == nil {
			run.result.FederationIncidentResponses[idx].ClosedAt = cloneTimePtr(&now)
		}
	}
	attestation := SecureCellFederationIncidentClosureAttestation{
		ID:                secureCellFederationIncidentClosureAttestationID(*response, actorDID, now, len(run.result.FederationIncidentResponses[idx].ClosureAttestations)),
		ResponseID:        response.ID,
		OrganizationID:    response.OrganizationID,
		SponsorOfRecord:   response.SponsorOfRecord,
		IncidentID:        response.IncidentID,
		AttestingParty:    party,
		SubmittedBy:       actorDID,
		Summary:           strings.TrimSpace(req.Summary),
		Description:       strings.TrimSpace(req.Description),
		EvidenceIDs:       append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		PolicyReceiptID:   receipt.ID,
		PolicyReceiptHash: receipt.ContentHash,
		CreatedAt:         now,
		Metadata:          cloneStringMap(req.Metadata),
	}
	run.result.FederationIncidentResponses[idx].ClosureAttestations = append(run.result.FederationIncidentResponses[idx].ClosureAttestations, attestation)
	run.result.FederationIncidentResponses[idx].UpdatedAt = now
	run.result.FederationIncidentResponses[idx].Metadata = mergeStringMaps(run.result.FederationIncidentResponses[idx].Metadata, req.Metadata)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_closure_attested", response.ID),
		Action:           "secure_cell.federation_incident_closure_attested",
		Actor:            actorDID,
		TargetType:       "federation_incident_response",
		TargetDID:        response.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":            response.ID,
			"federation_incident_response_status_before": string(response.Status),
			"federation_incident_response_status_after":  string(run.result.FederationIncidentResponses[idx].Status),
			"federation_incident_response_source":        string(response.SourceType),
			"federation_organization_id":                 response.OrganizationID,
			"federation_sponsor_of_record":               response.SponsorOfRecord,
			"federation_incident_id":                     response.IncidentID,
			"federation_incident_status":                 string(response.IncidentStatus),
			"federation_incident_severity":               string(response.IncidentSeverity),
			"federation_incident_category":               string(response.IncidentCategory),
			"federation_incident_response_action":        "attest_closure",
			"federation_incident_closure_attestation_id": attestation.ID,
			"federation_incident_closure_party":          string(attestation.AttestingParty),
			"federation_incident_closure_evidence":       strings.Join(attestation.EvidenceIDs, ","),
			"federation_contract_ids":                    strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) DisputeFederationIncidentResponse(ctx context.Context, cellID string, responseID string, req SecureCellFederationIncidentResponseDisputeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	idx, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	if strings.TrimSpace(req.Summary) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-response: dispute summary is required")
	}
	party := secureCellNormalizedFederationIncidentResponseParty(req.DisputingParty)
	if party == "" {
		party = secureCellFederationIncidentResponseClosureParty(*response)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, party) {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: actor %q is not permitted to dispute response %q", ErrPolicyDenied, actorDID, responseID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "dispute_federation_incident_response", lastReceiptHash(run.result), map[string]string{
		"federation_incident_response_id":             response.ID,
		"federation_organization_id":                  response.OrganizationID,
		"federation_sponsor_of_record":                response.SponsorOfRecord,
		"federation_incident_id":                      response.IncidentID,
		"federation_incident_response_source":         string(response.SourceType),
		"federation_incident_response_status":         string(response.Status),
		"federation_incident_disputing_party":         string(party),
		"federation_incident_related_verification_id": strings.TrimSpace(req.RelatedVerificationID),
		"federation_incident_related_closure_id":      strings.TrimSpace(req.RelatedClosureID),
		"federation_incident_dispute_evidence":        strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason":                           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w", ErrPolicyDenied)
	}

	now := time.Now().UTC()
	statusBefore := response.Status
	dispute := secureCellReopenFederationIncidentResponse(&run.result.FederationIncidentResponses[idx], req, receipt, now)
	run.result.UpdatedAt = now

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_response_disputed", response.ID),
		Action:           "secure_cell.federation_incident_response_disputed",
		Actor:            actorDID,
		TargetType:       "federation_incident_response",
		TargetDID:        response.ID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary)),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_incident_response_id":            response.ID,
			"federation_incident_response_status_before": string(statusBefore),
			"federation_incident_response_status_after":  string(run.result.FederationIncidentResponses[idx].Status),
			"federation_incident_response_source":        string(response.SourceType),
			"federation_organization_id":                 response.OrganizationID,
			"federation_sponsor_of_record":               response.SponsorOfRecord,
			"federation_incident_id":                     response.IncidentID,
			"federation_incident_status":                 string(response.IncidentStatus),
			"federation_incident_severity":               string(response.IncidentSeverity),
			"federation_incident_category":               string(response.IncidentCategory),
			"federation_incident_response_action":        "dispute",
			"federation_incident_dispute_id":             dispute.ID,
			"federation_incident_disputing_party":        string(dispute.DisputingParty),
			"federation_incident_dispute_evidence":       strings.Join(dispute.EvidenceIDs, ","),
			"federation_contract_ids":                    strings.Join(response.ContractIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) GetFederationIncidentResponse(_ context.Context, cellID string, responseID string) (*SecureCellFederationIncidentResponse, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	_, response := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, responseID)
	if response == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: %w: %q", ErrFederationIncidentResponseNotFound, responseID)
	}
	cloned, err := cloneResult(&SecureCellResult{FederationIncidentResponses: []SecureCellFederationIncidentResponse{*response}})
	if err != nil {
		return nil, err
	}
	if cloned == nil || len(cloned.FederationIncidentResponses) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-response: failed to clone response %q", responseID)
	}
	return &cloned.FederationIncidentResponses[0], nil
}

func (s *Service) ListFederationIncidentResponses(_ context.Context, filter SecureCellFederationIncidentResponseFilter) ([]SecureCellFederationIncidentResponseSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentResponseSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			summary := secureCellFederationIncidentResponseSummaryFromRun(run, response)
			if !matchesSecureCellFederationIncidentResponseFilter(summary, filter) {
				continue
			}
			items = append(items, summary)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListOverdueFederationIncidentResponses(_ context.Context, filter SecureCellOverdueFederationIncidentResponseFilter) ([]SecureCellOverdueFederationIncidentResponse, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentResponse, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			summary := secureCellFederationIncidentResponseSummaryFromRun(run, response)
			if filter.OrganizationID != "" && !strings.EqualFold(summary.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(summary.IncidentID, strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(summary.ResponseID, strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			if filter.ContractID != "" && !secureCellStringSliceContains(summary.ContractIDs, strings.TrimSpace(filter.ContractID)) {
				continue
			}
			stepType, action, reason, tierID, targetDID, dueAt, ok := secureCellFederationIncidentResponseOverdueAction(response, at)
			if !ok {
				continue
			}
			items = append(items, SecureCellOverdueFederationIncidentResponse{
				CellID:            summary.CellID,
				CellName:          summary.CellName,
				Jurisdiction:      summary.Jurisdiction,
				CellStatus:        summary.CellStatus,
				ResponseID:        summary.ResponseID,
				OrganizationID:    summary.OrganizationID,
				SponsorOfRecord:   summary.SponsorOfRecord,
				IncidentID:        summary.IncidentID,
				IncidentSeverity:  summary.IncidentSeverity,
				IncidentCategory:  summary.IncidentCategory,
				IncidentSummary:   summary.IncidentSummary,
				ResponseStatus:    summary.Status,
				SourceType:        summary.SourceType,
				PlaybookTemplate:  summary.PlaybookTemplate,
				OverdueStepType:   stepType,
				OverdueStepStatus: secureCellFederationIncidentResponseStepStatus(response, stepType),
				AutomationAction:  action,
				OverdueReason:     reason,
				TierID:            tierID,
				TargetDID:         targetDID,
				DueAt:             dueAt.UTC(),
				OverdueSeconds:    int64(at.Sub(dueAt.UTC()).Seconds()),
				AcknowledgedAt:    summary.AcknowledgedAt,
				RemediatedAt:      summary.RemediatedAt,
				VerifiedAt:        summary.VerifiedAt,
				ClosedAt:          summary.ClosedAt,
				UpdatedAt:         summary.UpdatedAt,
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentResponseActions(_ context.Context, filter SecureCellFederationIncidentResponseActionFilter) ([]SecureCellFederationIncidentResponseActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentResponseActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentResponseActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentResponseActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].TransitionID > items[j].TransitionID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentRemediations(_ context.Context, filter SecureCellFederationIncidentRemediationFilter) ([]SecureCellFederationIncidentRemediationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentRemediationSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, attestation := range response.RemediationAttestations {
				if filter.AttestingParty != "" && attestation.AttestingParty != filter.AttestingParty {
					continue
				}
				if filter.Since != nil && attestation.CreatedAt.Before(filter.Since.UTC()) {
					continue
				}
				if filter.Until != nil && attestation.CreatedAt.After(filter.Until.UTC()) {
					continue
				}
				items = append(items, secureCellFederationIncidentRemediationSummaryFromRun(run, response, attestation))
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].AttestationID > items[j].AttestationID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentVerifications(_ context.Context, filter SecureCellFederationIncidentVerificationFilter) ([]SecureCellFederationIncidentVerificationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentVerificationSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, verification := range response.RemediationVerifications {
				if filter.ReviewingParty != "" && verification.ReviewingParty != filter.ReviewingParty {
					continue
				}
				if filter.Decision != "" && verification.Decision != filter.Decision {
					continue
				}
				if filter.Since != nil && verification.CreatedAt.Before(filter.Since.UTC()) {
					continue
				}
				if filter.Until != nil && verification.CreatedAt.After(filter.Until.UTC()) {
					continue
				}
				items = append(items, secureCellFederationIncidentVerificationSummaryFromRun(run, response, verification))
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].VerificationID > items[j].VerificationID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentClosureAttestations(_ context.Context, filter SecureCellFederationIncidentClosureAttestationFilter) ([]SecureCellFederationIncidentClosureAttestationSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentClosureAttestationSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, attestation := range response.ClosureAttestations {
				if filter.AttestingParty != "" && attestation.AttestingParty != filter.AttestingParty {
					continue
				}
				if filter.Since != nil && attestation.CreatedAt.Before(filter.Since.UTC()) {
					continue
				}
				if filter.Until != nil && attestation.CreatedAt.After(filter.Until.UTC()) {
					continue
				}
				items = append(items, secureCellFederationIncidentClosureAttestationSummaryFromRun(run, response, attestation))
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].AttestationID > items[j].AttestationID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentDisputes(_ context.Context, filter SecureCellFederationIncidentDisputeFilter) ([]SecureCellFederationIncidentDisputeSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDisputeSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, response := range run.result.FederationIncidentResponses {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(response.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(response.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(response.ID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			for _, dispute := range response.Disputes {
				if filter.DisputingParty != "" && dispute.DisputingParty != filter.DisputingParty {
					continue
				}
				if filter.Since != nil && dispute.CreatedAt.Before(filter.Since.UTC()) {
					continue
				}
				if filter.Until != nil && dispute.CreatedAt.After(filter.Until.UTC()) {
					continue
				}
				items = append(items, secureCellFederationIncidentDisputeSummaryFromRun(run, response, dispute))
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].DisputeID > items[j].DisputeID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) SweepFederationIncidentResponses(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentResponseSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-response: service is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	s.mu.RLock()
	cellIDs := make([]string, 0, len(s.runs))
	for cellID := range s.runs {
		cellIDs = append(cellIDs, cellID)
	}
	s.mu.RUnlock()
	sort.Strings(cellIDs)

	report := &SecureCellFederationIncidentResponseSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	mutatedCells := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		report.ResponsesScanned += len(run.result.FederationIncidentResponses)
		for _, response := range run.result.FederationIncidentResponses {
			stepType, action, reason, tierID, _, _, ok := secureCellFederationIncidentResponseOverdueAction(response, at)
			if !ok || action == "" {
				continue
			}
			metadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_incident_response_mode":         "automated",
				"federation_incident_response_trigger":      "playbook_overdue",
				"federation_incident_response_action":       action,
				"federation_incident_response_overdue_step": string(stepType),
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				metadata["automated_actor"] = automatedActor
			}
			result, err := s.EscalateFederationIncidentResponse(ctx, cellID, response.ID, SecureCellFederationIncidentResponseEscalateRequest{
				ActorDID: run.request.OwnerIdentity.AgentID(),
				TierID:   tierID,
				Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), reason),
				Metadata: metadata,
			})
			if err != nil {
				return nil, err
			}
			if result != nil {
				report.ResponsesEscalated++
				mutatedCells[cellID] = struct{}{}
			}
		}
	}
	report.CellsMutated = len(mutatedCells)
	if len(mutatedCells) > 0 {
		report.CellIDs = make([]string, 0, len(mutatedCells))
		for cellID := range mutatedCells {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
	}
	return report, nil
}

func secureCellUpsertFederationIncidentResponseForLocalIncident(run *secureCellRun, incident SecureCellFederationIncident) string {
	if run == nil || run.result == nil {
		return ""
	}
	response := secureCellNewFederationIncidentResponse(run, incident.OrganizationID, incident.SponsorOfRecord, incident.OrganizationName, SecureCellFederationIncidentResponseSourceLocalIncident, "", "", secureCellFederationIncidentSummaryFromRun(run, incident))
	if idx, existing := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, response.ID); existing != nil {
		run.result.FederationIncidentResponses[idx] = secureCellMergeFederationIncidentResponse(run.result.FederationIncidentResponses[idx], response)
		return run.result.FederationIncidentResponses[idx].ID
	}
	run.result.FederationIncidentResponses = append(run.result.FederationIncidentResponses, response)
	return response.ID
}

func secureCellUpsertFederationIncidentResponsesForCounterpartySnapshot(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentSnapshot) []string {
	if run == nil || run.result == nil {
		return nil
	}
	responseIDs := make([]string, 0, len(snapshot.Bulletin.Incidents))
	for _, incident := range snapshot.Bulletin.Incidents {
		summary := incident
		if summary.Status == "" {
			summary.Status = SecureCellFederationIncidentStatusOpen
		}
		if summary.Status != SecureCellFederationIncidentStatusOpen && summary.Status != SecureCellFederationIncidentStatusResolved {
			continue
		}
		response := secureCellNewFederationIncidentResponse(run, snapshot.OrganizationID, summary.SponsorOfRecord, summary.OrganizationName, SecureCellFederationIncidentResponseSourceCounterpartyIncident, snapshot.SnapshotID, snapshot.Bulletin.ID, summary)
		if idx, existing := findSecureCellFederationIncidentResponse(run.result.FederationIncidentResponses, response.ID); existing != nil {
			merged := secureCellMergeFederationIncidentResponse(run.result.FederationIncidentResponses[idx], response)
			if summary.Status == SecureCellFederationIncidentStatusResolved && secureCellFederationIncidentResponseClosureReady(merged) {
				merged.Status = SecureCellFederationIncidentResponseStatusClosed
			}
			run.result.FederationIncidentResponses[idx] = merged
			responseIDs = append(responseIDs, merged.ID)
			continue
		}
		run.result.FederationIncidentResponses = append(run.result.FederationIncidentResponses, response)
		responseIDs = append(responseIDs, response.ID)
	}
	return uniqueTrimmedStrings(responseIDs)
}

func secureCellUpdateFederationIncidentResponseStatusForResolution(result *SecureCellResult, incidentID string, resolvedAt time.Time, resolvedBy string) {
	if result == nil {
		return
	}
	incidentID = strings.TrimSpace(incidentID)
	for idx := range result.FederationIncidentResponses {
		if strings.TrimSpace(result.FederationIncidentResponses[idx].IncidentID) != incidentID {
			continue
		}
		result.FederationIncidentResponses[idx].IncidentStatus = SecureCellFederationIncidentStatusResolved
		if secureCellFederationIncidentResponseClosureReady(result.FederationIncidentResponses[idx]) {
			result.FederationIncidentResponses[idx].Status = SecureCellFederationIncidentResponseStatusClosed
			if strings.TrimSpace(result.FederationIncidentResponses[idx].ClosedBy) == "" {
				result.FederationIncidentResponses[idx].ClosedBy = strings.TrimSpace(resolvedBy)
			}
			if result.FederationIncidentResponses[idx].ClosedAt == nil {
				result.FederationIncidentResponses[idx].ClosedAt = cloneTimePtr(&resolvedAt)
			}
		}
		if strings.TrimSpace(result.FederationIncidentResponses[idx].RemediatedBy) == "" {
			result.FederationIncidentResponses[idx].RemediatedBy = strings.TrimSpace(resolvedBy)
		}
		if result.FederationIncidentResponses[idx].RemediatedAt == nil {
			result.FederationIncidentResponses[idx].RemediatedAt = cloneTimePtr(&resolvedAt)
		}
		result.FederationIncidentResponses[idx].UpdatedAt = resolvedAt.UTC()
	}
}

func secureCellNewFederationIncidentResponse(run *secureCellRun, organizationID string, sponsorOfRecord string, organizationName string, sourceType SecureCellFederationIncidentResponseSource, snapshotID string, bulletinID string, incident SecureCellFederationIncidentSummary) SecureCellFederationIncidentResponse {
	now := time.Now().UTC()
	if !incident.ReportedAt.IsZero() {
		now = incident.ReportedAt.UTC()
	}
	responseID := secureCellFederationIncidentResponseID(run, organizationID, sourceType, incident.IncidentID)
	requiredAck := secureCellFederationIncidentResponsePartyForSource(sourceType)
	verificationParty := secureCellFederationIncidentResponseOppositeParty(requiredAck)
	template, steps, ladder := secureCellFederationIncidentResponsePlaybook(run, responseID, organizationID, requiredAck, verificationParty, incident, now)
	status := SecureCellFederationIncidentResponseStatusPendingCounterpartyAck
	if requiredAck == SecureCellFederationIncidentResponsePartyLocalOrg {
		status = SecureCellFederationIncidentResponseStatusPendingLocalAck
	}
	return SecureCellFederationIncidentResponse{
		ID:                       responseID,
		OrganizationID:           strings.TrimSpace(organizationID),
		SponsorOfRecord:          strings.TrimSpace(sponsorOfRecord),
		OrganizationName:         strings.TrimSpace(organizationName),
		SourceType:               sourceType,
		SourceSnapshotID:         strings.TrimSpace(snapshotID),
		SourceBulletinID:         strings.TrimSpace(bulletinID),
		IncidentID:               strings.TrimSpace(incident.IncidentID),
		IncidentStatus:           incident.Status,
		IncidentSeverity:         incident.Severity,
		IncidentCategory:         incident.Category,
		IncidentSummary:          strings.TrimSpace(incident.Summary),
		IncidentDescription:      strings.TrimSpace(incident.Description),
		ContractIDs:              append([]string(nil), uniqueTrimmedStrings(incident.ContractIDs)...),
		SessionIDs:               append([]string(nil), uniqueTrimmedStrings(incident.SessionIDs)...),
		ThreadIDs:                append([]string(nil), uniqueTrimmedStrings(incident.ThreadIDs)...),
		SharedOutputIDs:          append([]string(nil), uniqueTrimmedStrings(incident.SharedOutputIDs)...),
		SessionExchangeIDs:       append([]string(nil), uniqueTrimmedStrings(incident.SessionExchangeIDs)...),
		Status:                   status,
		RequiredAcknowledgement:  requiredAck,
		ExpectedRemediationFrom:  requiredAck,
		VerificationRequiredFrom: verificationParty,
		PlaybookTemplate:         template,
		EscalationLadder:         ladder,
		PlaybookSteps:            steps,
		CreatedAt:                now,
		UpdatedAt:                now,
	}
}

func secureCellMergeFederationIncidentResponse(existing SecureCellFederationIncidentResponse, incoming SecureCellFederationIncidentResponse) SecureCellFederationIncidentResponse {
	merged := existing
	merged.OrganizationID = firstNonEmpty(strings.TrimSpace(merged.OrganizationID), strings.TrimSpace(incoming.OrganizationID))
	merged.SponsorOfRecord = firstNonEmpty(strings.TrimSpace(incoming.SponsorOfRecord), strings.TrimSpace(merged.SponsorOfRecord))
	merged.OrganizationName = firstNonEmpty(strings.TrimSpace(incoming.OrganizationName), strings.TrimSpace(merged.OrganizationName))
	merged.SourceType = incoming.SourceType
	merged.SourceSnapshotID = firstNonEmpty(strings.TrimSpace(incoming.SourceSnapshotID), strings.TrimSpace(merged.SourceSnapshotID))
	merged.SourceBulletinID = firstNonEmpty(strings.TrimSpace(incoming.SourceBulletinID), strings.TrimSpace(merged.SourceBulletinID))
	merged.IncidentStatus = incoming.IncidentStatus
	merged.IncidentSeverity = incoming.IncidentSeverity
	merged.IncidentCategory = incoming.IncidentCategory
	merged.IncidentSummary = firstNonEmpty(strings.TrimSpace(incoming.IncidentSummary), strings.TrimSpace(merged.IncidentSummary))
	merged.IncidentDescription = firstNonEmpty(strings.TrimSpace(incoming.IncidentDescription), strings.TrimSpace(merged.IncidentDescription))
	merged.ContractIDs = uniqueTrimmedStrings(append(append([]string(nil), merged.ContractIDs...), incoming.ContractIDs...))
	merged.SessionIDs = uniqueTrimmedStrings(append(append([]string(nil), merged.SessionIDs...), incoming.SessionIDs...))
	merged.ThreadIDs = uniqueTrimmedStrings(append(append([]string(nil), merged.ThreadIDs...), incoming.ThreadIDs...))
	merged.SharedOutputIDs = uniqueTrimmedStrings(append(append([]string(nil), merged.SharedOutputIDs...), incoming.SharedOutputIDs...))
	merged.SessionExchangeIDs = uniqueTrimmedStrings(append(append([]string(nil), merged.SessionExchangeIDs...), incoming.SessionExchangeIDs...))
	merged.VerificationRequiredFrom = firstNonEmptyFederationIncidentResponseParty(incoming.VerificationRequiredFrom, merged.VerificationRequiredFrom)
	if len(merged.PlaybookSteps) == 0 {
		merged.PlaybookTemplate = incoming.PlaybookTemplate
		merged.PlaybookSteps = incoming.PlaybookSteps
	}
	if len(merged.EscalationLadder) == 0 {
		merged.EscalationLadder = incoming.EscalationLadder
	}
	merged.Metadata = mergeStringMaps(merged.Metadata, incoming.Metadata)
	if incoming.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = incoming.UpdatedAt.UTC()
	}
	return merged
}

func secureCellFederationIncidentResponseID(run *secureCellRun, organizationID string, sourceType SecureCellFederationIncidentResponseSource, incidentID string) string {
	cell := ""
	if run != nil && run.result != nil {
		cell = strings.TrimSpace(run.result.CellID)
	}
	seed := fmt.Sprintf("%s|%s|%s|%s", cell, strings.TrimSpace(organizationID), strings.TrimSpace(string(sourceType)), strings.TrimSpace(incidentID))
	return fmt.Sprintf("%s-federation-incident-response-%x", cell, sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentRemediationAttestationID(response SecureCellFederationIncidentResponse, actorDID string, at time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|%s", strings.TrimSpace(response.ID), strings.TrimSpace(actorDID), at.UTC().Format(time.RFC3339Nano), ordinal+1, strings.TrimSpace(response.IncidentID))
	return fmt.Sprintf("%s-remediation-%x", strings.TrimSpace(response.ID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentRemediationVerificationID(response SecureCellFederationIncidentResponse, actorDID string, at time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|%s", strings.TrimSpace(response.ID), strings.TrimSpace(actorDID), at.UTC().Format(time.RFC3339Nano), ordinal+1, strings.TrimSpace(response.IncidentID))
	return fmt.Sprintf("%s-verification-%x", strings.TrimSpace(response.ID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentClosureAttestationID(response SecureCellFederationIncidentResponse, actorDID string, at time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|closure|%s", strings.TrimSpace(response.ID), strings.TrimSpace(actorDID), at.UTC().Format(time.RFC3339Nano), ordinal+1, strings.TrimSpace(response.IncidentID))
	return fmt.Sprintf("%s-closure-%x", strings.TrimSpace(response.ID), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDisputeID(response SecureCellFederationIncidentResponse, actorDID string, at time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d|dispute|%s", strings.TrimSpace(response.ID), strings.TrimSpace(actorDID), at.UTC().Format(time.RFC3339Nano), ordinal+1, strings.TrimSpace(response.IncidentID))
	return fmt.Sprintf("%s-dispute-%x", strings.TrimSpace(response.ID), sha256.Sum256([]byte(seed)))
}

func findSecureCellFederationIncidentResponse(items []SecureCellFederationIncidentResponse, responseID string) (int, *SecureCellFederationIncidentResponse) {
	responseID = strings.TrimSpace(responseID)
	if responseID == "" {
		return -1, nil
	}
	for idx := range items {
		if strings.TrimSpace(items[idx].ID) == responseID {
			return idx, &items[idx]
		}
	}
	return -1, nil
}

func secureCellFederationIncidentResponsePartyForSource(source SecureCellFederationIncidentResponseSource) SecureCellFederationIncidentResponseParty {
	switch source {
	case SecureCellFederationIncidentResponseSourceCounterpartyIncident:
		return SecureCellFederationIncidentResponsePartyLocalOrg
	default:
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	}
}

func secureCellFederationIncidentResponseOppositeParty(party SecureCellFederationIncidentResponseParty) SecureCellFederationIncidentResponseParty {
	switch secureCellNormalizedFederationIncidentResponseParty(party) {
	case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
		return SecureCellFederationIncidentResponsePartyLocalOrg
	case SecureCellFederationIncidentResponsePartyLocalOrg:
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	default:
		return ""
	}
}

func secureCellFederationIncidentResponseClosureParty(response SecureCellFederationIncidentResponse) SecureCellFederationIncidentResponseParty {
	if party := secureCellFederationIncidentResponseOppositeParty(response.VerificationRequiredFrom); party != "" {
		return party
	}
	if party := secureCellFederationIncidentResponseOppositeParty(response.ExpectedRemediationFrom); party != "" {
		return party
	}
	return secureCellFederationIncidentResponseOppositeParty(response.RequiredAcknowledgement)
}

func firstNonEmptyFederationIncidentResponseParty(values ...SecureCellFederationIncidentResponseParty) SecureCellFederationIncidentResponseParty {
	for _, value := range values {
		if normalized := secureCellNormalizedFederationIncidentResponseParty(value); normalized != "" {
			return normalized
		}
	}
	return ""
}

func secureCellNormalizedFederationIncidentResponseParty(value SecureCellFederationIncidentResponseParty) SecureCellFederationIncidentResponseParty {
	switch SecureCellFederationIncidentResponseParty(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentResponsePartyLocalOrg:
		return SecureCellFederationIncidentResponsePartyLocalOrg
	case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg
	default:
		return ""
	}
}

func secureCellNormalizedFederationIncidentRemediationVerificationDecision(value SecureCellFederationIncidentRemediationVerificationDecision) SecureCellFederationIncidentRemediationVerificationDecision {
	switch SecureCellFederationIncidentRemediationVerificationDecision(strings.ToLower(strings.TrimSpace(string(value)))) {
	case SecureCellFederationIncidentRemediationVerificationDecisionAccepted:
		return SecureCellFederationIncidentRemediationVerificationDecisionAccepted
	case SecureCellFederationIncidentRemediationVerificationDecisionRejected:
		return SecureCellFederationIncidentRemediationVerificationDecisionRejected
	default:
		return ""
	}
}

func secureCellFederationIncidentResponsePartyAllowed(run *secureCellRun, response SecureCellFederationIncidentResponse, actorDID string, party SecureCellFederationIncidentResponseParty) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" || run == nil || run.result == nil || run.request.OwnerIdentity == nil {
		return false
	}
	switch secureCellNormalizedFederationIncidentResponseParty(party) {
	case SecureCellFederationIncidentResponsePartyLocalOrg:
		return secureCellActorAllowed(run, actorDID, true)
	case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
		_, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, response.OrganizationID)
		if org == nil {
			return false
		}
		for _, participantDID := range org.ParticipantDIDs {
			if strings.TrimSpace(participantDID) != actorDID {
				continue
			}
			state, ok := participantStateForResult(run.result, actorDID)
			return ok && state.Status == SecureCellParticipantStatusActive
		}
	}
	return false
}

func secureCellFederationIncidentResponsePlaybook(run *secureCellRun, responseID string, organizationID string, party SecureCellFederationIncidentResponseParty, verificationParty SecureCellFederationIncidentResponseParty, incident SecureCellFederationIncidentSummary, createdAt time.Time) (string, []SecureCellFederationIncidentPlaybookStep, []SecureCellFederationEscalationTier) {
	template, ackAfter, remediationAfter, verificationAfter := secureCellFederationIncidentPlaybookDefaults(incident.Severity)
	ackDueAt := createdAt.Add(ackAfter).UTC()
	remediationDueAt := createdAt.Add(remediationAfter).UTC()
	verificationDueAt := createdAt.Add(verificationAfter).UTC()
	ackTarget := secureCellFederationIncidentEscalationTarget(run, organizationID, party, "")
	remediationTarget := secureCellFederationIncidentEscalationTarget(run, organizationID, SecureCellFederationIncidentResponsePartyLocalOrg, ackTarget)
	verificationTarget := secureCellFederationIncidentEscalationTarget(run, organizationID, verificationParty, remediationTarget)
	steps := []SecureCellFederationIncidentPlaybookStep{
		{
			StepID:           responseID + "-acknowledge",
			ResponseID:       responseID,
			Type:             SecureCellFederationIncidentPlaybookStepTypeAcknowledge,
			ResponsibleParty: party,
			Title:            "Acknowledge federation incident",
			Description:      "Record cross-organization acknowledgement of the active federation incident.",
			DueAt:            cloneTimePtr(&ackDueAt),
			Status:           SecureCellFederationIncidentPlaybookStepStatusPending,
		},
		{
			StepID:           responseID + "-remediate",
			ResponseID:       responseID,
			Type:             SecureCellFederationIncidentPlaybookStepTypeRemediate,
			ResponsibleParty: party,
			Title:            "Attest incident remediation",
			Description:      "Submit evidence-bearing remediation attestation for the active federation incident.",
			DueAt:            cloneTimePtr(&remediationDueAt),
			Status:           SecureCellFederationIncidentPlaybookStepStatusPending,
		},
		{
			StepID:           responseID + "-verify",
			ResponseID:       responseID,
			Type:             SecureCellFederationIncidentPlaybookStepTypeVerify,
			ResponsibleParty: verificationParty,
			Title:            "Verify bilateral remediation",
			Description:      "The opposite organization verifies whether remediation evidence is sufficient to close the incident.",
			DueAt:            cloneTimePtr(&verificationDueAt),
			Status:           SecureCellFederationIncidentPlaybookStepStatusPending,
		},
	}
	ladder := make([]SecureCellFederationEscalationTier, 0, 3)
	if strings.TrimSpace(ackTarget) != "" {
		ladder = append(ladder, SecureCellFederationEscalationTier{
			TierID:    "acknowledge",
			TargetDID: ackTarget,
			DueAt:     cloneTimePtr(&ackDueAt),
			Reason:    "incident acknowledgement deadline reached",
		})
	}
	if strings.TrimSpace(remediationTarget) != "" {
		ladder = append(ladder, SecureCellFederationEscalationTier{
			TierID:    "remediate",
			TargetDID: remediationTarget,
			DueAt:     cloneTimePtr(&remediationDueAt),
			Reason:    "incident remediation deadline reached",
		})
	}
	if strings.TrimSpace(verificationTarget) != "" {
		ladder = append(ladder, SecureCellFederationEscalationTier{
			TierID:    "verify_remediation",
			TargetDID: verificationTarget,
			DueAt:     cloneTimePtr(&verificationDueAt),
			Reason:    "incident remediation verification deadline reached",
		})
	}
	return template, steps, ladder
}

func secureCellFederationIncidentPlaybookDefaults(severity SecureCellFederationIncidentSeverity) (string, time.Duration, time.Duration, time.Duration) {
	switch severity {
	case SecureCellFederationIncidentSeverityCritical:
		return "critical_incident_bilateral_v1", 15 * time.Minute, 2 * time.Hour, 4 * time.Hour
	case SecureCellFederationIncidentSeverityHigh:
		return "high_incident_bilateral_v1", 30 * time.Minute, 6 * time.Hour, 12 * time.Hour
	case SecureCellFederationIncidentSeverityWarning:
		return "warning_incident_bilateral_v1", 2 * time.Hour, 24 * time.Hour, 36 * time.Hour
	default:
		return "standard_incident_bilateral_v1", 4 * time.Hour, 48 * time.Hour, 72 * time.Hour
	}
}

func secureCellFederationIncidentEscalationTarget(run *secureCellRun, organizationID string, party SecureCellFederationIncidentResponseParty, exclude string) string {
	exclude = strings.TrimSpace(exclude)
	switch secureCellNormalizedFederationIncidentResponseParty(party) {
	case SecureCellFederationIncidentResponsePartyCounterpartyOrg:
		if run != nil && run.result != nil {
			if _, org := findSecureCellFederationOrganization(run.result.FederationOrganizations, organizationID); org != nil {
				for _, participantDID := range uniqueTrimmedStrings(org.ParticipantDIDs) {
					if participantDID != "" && participantDID != exclude {
						if state, ok := participantStateForResult(run.result, participantDID); ok && state.Status == SecureCellParticipantStatusActive {
							return participantDID
						}
					}
				}
			}
		}
	}
	if run != nil && run.request.OwnerIdentity != nil {
		owner := strings.TrimSpace(run.request.OwnerIdentity.AgentID())
		if owner != "" && owner != exclude {
			return owner
		}
	}
	return ""
}

func secureCellCompleteFederationIncidentPlaybookStep(response *SecureCellFederationIncidentResponse, stepType SecureCellFederationIncidentPlaybookStepType, actorDID string, at time.Time, attestationID string) {
	if response == nil {
		return
	}
	for idx := range response.PlaybookSteps {
		if response.PlaybookSteps[idx].Type != stepType {
			continue
		}
		response.PlaybookSteps[idx].Status = SecureCellFederationIncidentPlaybookStepStatusCompleted
		response.PlaybookSteps[idx].CompletedBy = strings.TrimSpace(actorDID)
		response.PlaybookSteps[idx].CompletedAt = cloneTimePtr(&at)
		if attestationID != "" {
			response.PlaybookSteps[idx].RemediationAttestationID = strings.TrimSpace(attestationID)
		}
	}
}

func secureCellResetFederationIncidentPlaybookStep(response *SecureCellFederationIncidentResponse, stepType SecureCellFederationIncidentPlaybookStepType, at time.Time, dueAt time.Time, clearAttachment bool) {
	if response == nil {
		return
	}
	for idx := range response.PlaybookSteps {
		if response.PlaybookSteps[idx].Type != stepType {
			continue
		}
		response.PlaybookSteps[idx].Status = SecureCellFederationIncidentPlaybookStepStatusPending
		response.PlaybookSteps[idx].CompletedBy = ""
		response.PlaybookSteps[idx].CompletedAt = nil
		if clearAttachment {
			response.PlaybookSteps[idx].RemediationAttestationID = ""
		}
		response.PlaybookSteps[idx].DueAt = cloneTimePtr(&dueAt)
	}
}

func secureCellMarkFederationIncidentPlaybookStepOverdue(response *SecureCellFederationIncidentResponse, stepType SecureCellFederationIncidentPlaybookStepType, at time.Time) {
	if response == nil {
		return
	}
	for idx := range response.PlaybookSteps {
		if response.PlaybookSteps[idx].Type != stepType {
			continue
		}
		if response.PlaybookSteps[idx].Status == SecureCellFederationIncidentPlaybookStepStatusCompleted {
			continue
		}
		if response.PlaybookSteps[idx].DueAt != nil && !response.PlaybookSteps[idx].DueAt.IsZero() && !response.PlaybookSteps[idx].DueAt.After(at.UTC()) {
			response.PlaybookSteps[idx].Status = SecureCellFederationIncidentPlaybookStepStatusOverdue
		}
	}
}

func secureCellFederationIncidentResponseHasExpectedRemediation(response SecureCellFederationIncidentResponse) bool {
	for _, attestation := range response.RemediationAttestations {
		if attestation.AttestingParty == response.ExpectedRemediationFrom {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentResponseHasAcceptedVerification(response SecureCellFederationIncidentResponse) bool {
	for idx := len(response.RemediationVerifications) - 1; idx >= 0; idx-- {
		switch response.RemediationVerifications[idx].Decision {
		case SecureCellFederationIncidentRemediationVerificationDecisionAccepted:
			return true
		case SecureCellFederationIncidentRemediationVerificationDecisionRejected:
			return false
		}
	}
	return false
}

func secureCellFederationIncidentResponseClosureReady(response SecureCellFederationIncidentResponse) bool {
	return response.IncidentStatus == SecureCellFederationIncidentStatusResolved &&
		response.AcknowledgedAt != nil && !response.AcknowledgedAt.IsZero() &&
		response.RemediatedAt != nil && !response.RemediatedAt.IsZero() &&
		secureCellFederationIncidentResponseHasAcceptedVerification(response)
}

func secureCellReopenFederationIncidentResponse(response *SecureCellFederationIncidentResponse, req SecureCellFederationIncidentResponseDisputeRequest, receipt *policy.SignedPolicyReceipt, at time.Time) SecureCellFederationIncidentDisputeRecord {
	if response == nil {
		return SecureCellFederationIncidentDisputeRecord{}
	}
	actorDID := strings.TrimSpace(req.ActorDID)
	disputingParty := secureCellNormalizedFederationIncidentResponseParty(req.DisputingParty)
	if disputingParty == "" {
		disputingParty = secureCellFederationIncidentResponseClosureParty(*response)
	}
	dispute := SecureCellFederationIncidentDisputeRecord{
		ID:                     secureCellFederationIncidentDisputeID(*response, actorDID, at, len(response.Disputes)),
		ResponseID:             response.ID,
		OrganizationID:         response.OrganizationID,
		SponsorOfRecord:        response.SponsorOfRecord,
		IncidentID:             response.IncidentID,
		DisputingParty:         disputingParty,
		SubmittedBy:            actorDID,
		RelatedVerificationID:  strings.TrimSpace(req.RelatedVerificationID),
		RelatedClosureID:       strings.TrimSpace(req.RelatedClosureID),
		Summary:                strings.TrimSpace(req.Summary),
		Description:            strings.TrimSpace(req.Description),
		EvidenceIDs:            append([]string(nil), uniqueTrimmedStrings(req.EvidenceIDs)...),
		Reopened:               true,
		ReopenedResponseStatus: SecureCellFederationIncidentResponseStatusRemediating,
		CreatedAt:              at.UTC(),
		Metadata:               cloneStringMap(req.Metadata),
	}
	if receipt != nil {
		dispute.PolicyReceiptID = strings.TrimSpace(receipt.ID)
		dispute.PolicyReceiptHash = strings.TrimSpace(receipt.ContentHash)
	}
	response.Disputes = append(response.Disputes, dispute)
	response.Status = SecureCellFederationIncidentResponseStatusRemediating
	response.RemediatedBy = ""
	response.RemediatedAt = nil
	response.VerifiedBy = ""
	response.VerifiedAt = nil
	response.ClosedBy = ""
	response.ClosedAt = nil
	response.LastDisputedBy = actorDID
	response.LastDisputedAt = cloneTimePtr(&at)
	response.ReopenedBy = actorDID
	response.ReopenedAt = cloneTimePtr(&at)
	response.ReopenReason = firstNonEmpty(strings.TrimSpace(req.Reason), strings.TrimSpace(req.Summary))
	response.UpdatedAt = at.UTC()
	response.Metadata = mergeStringMaps(response.Metadata, req.Metadata)
	secureCellResetFederationIncidentPlaybookStep(response, SecureCellFederationIncidentPlaybookStepTypeRemediate, at, secureCellFederationIncidentResponseRemediationDeadline(*response, at), true)
	secureCellResetFederationIncidentPlaybookStep(response, SecureCellFederationIncidentPlaybookStepTypeVerify, at, secureCellFederationIncidentResponseVerifyDeadline(*response, at), false)
	return dispute
}

func secureCellFederationIncidentResponseClosed(response SecureCellFederationIncidentResponse) bool {
	switch response.Status {
	case SecureCellFederationIncidentResponseStatusClosed:
		return true
	default:
		return false
	}
}

func secureCellResolveFederationIncidentResponseEscalation(response SecureCellFederationIncidentResponse, at time.Time, requestedTierID string) (SecureCellFederationEscalationTier, SecureCellFederationIncidentPlaybookStepType, string, error) {
	if requestedTierID != "" {
		for _, tier := range response.EscalationLadder {
			if strings.TrimSpace(tier.TierID) != strings.TrimSpace(requestedTierID) {
				continue
			}
			if secureCellStringSliceContains(response.EscalatedTierIDs, tier.TierID) {
				return SecureCellFederationEscalationTier{}, "", "", fmt.Errorf("securecells/federation-incident-response: %w: escalation tier %q already applied", ErrFederationIncidentResponseImmutable, requestedTierID)
			}
			stepType := secureCellFederationIncidentResponseTierStepType(tier.TierID)
			if stepType == "" {
				stepType = SecureCellFederationIncidentPlaybookStepTypeAcknowledge
			}
			if secureCellFederationIncidentResponseStepStatus(response, stepType) == SecureCellFederationIncidentPlaybookStepStatusCompleted {
				return SecureCellFederationEscalationTier{}, "", "", fmt.Errorf("securecells/federation-incident-response: %w: escalation tier %q already satisfied", ErrFederationIncidentResponseImmutable, requestedTierID)
			}
			reason := firstNonEmpty(strings.TrimSpace(tier.Reason), "incident response escalation requested")
			return tier, stepType, reason, nil
		}
		return SecureCellFederationEscalationTier{}, "", "", fmt.Errorf("securecells/federation-incident-response: %w: escalation tier %q is not configured", ErrFederationIncidentResponseImmutable, requestedTierID)
	}
	stepType, _, reason, tierID, _, _, ok := secureCellFederationIncidentResponseOverdueAction(response, at)
	if !ok {
		return SecureCellFederationEscalationTier{}, "", "", fmt.Errorf("securecells/federation-incident-response: %w: response %q has no overdue playbook tier", ErrFederationIncidentResponseImmutable, response.ID)
	}
	for _, tier := range response.EscalationLadder {
		if strings.TrimSpace(tier.TierID) == strings.TrimSpace(tierID) {
			return tier, stepType, reason, nil
		}
	}
	return SecureCellFederationEscalationTier{}, "", "", fmt.Errorf("securecells/federation-incident-response: %w: escalation tier %q is not configured", ErrFederationIncidentResponseImmutable, tierID)
}

func secureCellFederationIncidentResponseOverdueAction(response SecureCellFederationIncidentResponse, at time.Time) (SecureCellFederationIncidentPlaybookStepType, string, string, string, string, time.Time, bool) {
	if response.Status == SecureCellFederationIncidentResponseStatusClosed {
		return "", "", "", "", "", time.Time{}, false
	}
	for _, tier := range response.EscalationLadder {
		if tier.DueAt == nil || tier.DueAt.IsZero() {
			continue
		}
		if secureCellStringSliceContains(response.EscalatedTierIDs, tier.TierID) {
			continue
		}
		stepType := secureCellFederationIncidentResponseTierStepType(tier.TierID)
		if stepType != "" && secureCellFederationIncidentResponseStepStatus(response, stepType) == SecureCellFederationIncidentPlaybookStepStatusCompleted {
			continue
		}
		if tier.DueAt.After(at.UTC()) {
			continue
		}
		if stepType == "" {
			stepType = SecureCellFederationIncidentPlaybookStepTypeAcknowledge
		}
		action := "escalate_ack"
		reason := firstNonEmpty(strings.TrimSpace(tier.Reason), "incident acknowledgement deadline reached")
		if stepType == SecureCellFederationIncidentPlaybookStepTypeRemediate {
			stepType = SecureCellFederationIncidentPlaybookStepTypeRemediate
			action = "escalate_remediation"
			reason = firstNonEmpty(strings.TrimSpace(tier.Reason), "incident remediation deadline reached")
		} else if stepType == SecureCellFederationIncidentPlaybookStepTypeVerify {
			action = "escalate_verification"
			reason = firstNonEmpty(strings.TrimSpace(tier.Reason), "incident remediation verification deadline reached")
		}
		return stepType, action, reason, strings.TrimSpace(tier.TierID), strings.TrimSpace(tier.TargetDID), tier.DueAt.UTC(), true
	}
	return "", "", "", "", "", time.Time{}, false
}

func secureCellFederationIncidentResponseSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse) SecureCellFederationIncidentResponseSummary {
	summary := SecureCellFederationIncidentResponseSummary{
		CellID:                   strings.TrimSpace(run.result.CellID),
		CellName:                 strings.TrimSpace(run.result.Name),
		CellStatus:               run.result.Status,
		Jurisdiction:             strings.TrimSpace(run.request.Jurisdiction),
		ResponseID:               strings.TrimSpace(response.ID),
		OrganizationID:           strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:          strings.TrimSpace(response.SponsorOfRecord),
		OrganizationName:         strings.TrimSpace(response.OrganizationName),
		SourceType:               response.SourceType,
		SourceSnapshotID:         strings.TrimSpace(response.SourceSnapshotID),
		SourceBulletinID:         strings.TrimSpace(response.SourceBulletinID),
		IncidentID:               strings.TrimSpace(response.IncidentID),
		IncidentStatus:           response.IncidentStatus,
		IncidentSeverity:         response.IncidentSeverity,
		IncidentCategory:         response.IncidentCategory,
		IncidentSummary:          strings.TrimSpace(response.IncidentSummary),
		IncidentDescription:      strings.TrimSpace(response.IncidentDescription),
		Status:                   response.Status,
		RequiredAcknowledgement:  response.RequiredAcknowledgement,
		ExpectedRemediationFrom:  response.ExpectedRemediationFrom,
		VerificationRequiredFrom: response.VerificationRequiredFrom,
		PlaybookTemplate:         strings.TrimSpace(response.PlaybookTemplate),
		ContractIDs:              append([]string(nil), response.ContractIDs...),
		SessionIDs:               append([]string(nil), response.SessionIDs...),
		ThreadIDs:                append([]string(nil), response.ThreadIDs...),
		SharedOutputIDs:          append([]string(nil), response.SharedOutputIDs...),
		SessionExchangeIDs:       append([]string(nil), response.SessionExchangeIDs...),
		ContractCount:            len(response.ContractIDs),
		SessionCount:             len(response.SessionIDs),
		ThreadCount:              len(response.ThreadIDs),
		SharedOutputCount:        len(response.SharedOutputIDs),
		SessionExchangeCount:     len(response.SessionExchangeIDs),
		EscalationTierCount:      len(response.EscalationLadder),
		EscalatedTierCount:       len(uniqueTrimmedStrings(response.EscalatedTierIDs)),
		RemediationCount:         len(response.RemediationAttestations),
		VerificationCount:        len(response.RemediationVerifications),
		ReportCount:              len(response.IncidentReports),
		PendingReportCount:       secureCellFederationIncidentReportCountByStatus(response.IncidentReports, SecureCellFederationIncidentReportStatusPendingSubmission),
		AcknowledgedReportCount:  secureCellFederationIncidentReportCountByStatus(response.IncidentReports, SecureCellFederationIncidentReportStatusAcknowledged),
		OverdueReportCount:       secureCellFederationIncidentReportOverdueCount(response.IncidentReports, time.Now().UTC()),
		DirectiveCount:           len(response.IncidentDirectives),
		PendingDirectiveCount:    secureCellFederationIncidentDirectivePendingCount(response.IncidentDirectives),
		OverdueDirectiveCount:    secureCellFederationIncidentDirectiveOverdueCount(response.IncidentDirectives, time.Now().UTC()),
		ClosureAttestationCount:  len(response.ClosureAttestations),
		DisputeCount:             len(response.Disputes),
		AcknowledgedBy:           strings.TrimSpace(response.AcknowledgedBy),
		AcknowledgedAt:           cloneTimePtr(response.AcknowledgedAt),
		RemediatedBy:             strings.TrimSpace(response.RemediatedBy),
		RemediatedAt:             cloneTimePtr(response.RemediatedAt),
		VerifiedBy:               strings.TrimSpace(response.VerifiedBy),
		VerifiedAt:               cloneTimePtr(response.VerifiedAt),
		ClosedBy:                 strings.TrimSpace(response.ClosedBy),
		ClosedAt:                 cloneTimePtr(response.ClosedAt),
		LastDisputedBy:           strings.TrimSpace(response.LastDisputedBy),
		LastDisputedAt:           cloneTimePtr(response.LastDisputedAt),
		ReopenedBy:               strings.TrimSpace(response.ReopenedBy),
		ReopenedAt:               cloneTimePtr(response.ReopenedAt),
		ClosureReady:             secureCellFederationIncidentResponseClosureReady(response),
		CreatedAt:                response.CreatedAt.UTC(),
		UpdatedAt:                response.UpdatedAt.UTC(),
	}
	summary.AckDueAt, summary.AckStatus = secureCellFederationIncidentResponseStepDueAndStatus(response, SecureCellFederationIncidentPlaybookStepTypeAcknowledge)
	summary.RemediationDueAt, summary.RemediationStatus = secureCellFederationIncidentResponseStepDueAndStatus(response, SecureCellFederationIncidentPlaybookStepTypeRemediate)
	summary.VerificationDueAt, summary.VerificationStatus = secureCellFederationIncidentResponseStepDueAndStatus(response, SecureCellFederationIncidentPlaybookStepTypeVerify)
	summary.LastVerificationDecision = secureCellLatestFederationIncidentVerificationDecision(response)
	if nextTier, ok := secureCellFederationIncidentResponseNextEscalationTier(response); ok {
		summary.NextEscalationTierID = strings.TrimSpace(nextTier.TierID)
		summary.NextEscalationTargetDID = strings.TrimSpace(nextTier.TargetDID)
	}
	summary.NextReportDueAt = secureCellFederationIncidentReportNextDueAt(response.IncidentReports, time.Now().UTC())
	summary.NextDirectiveDueAt = secureCellFederationIncidentDirectiveNextDueAt(response.IncidentDirectives, time.Now().UTC())
	return summary
}

func secureCellFederationIncidentResponseNextEscalationTier(response SecureCellFederationIncidentResponse) (SecureCellFederationEscalationTier, bool) {
	for _, tier := range response.EscalationLadder {
		if secureCellStringSliceContains(response.EscalatedTierIDs, tier.TierID) {
			continue
		}
		stepType := secureCellFederationIncidentResponseTierStepType(tier.TierID)
		if stepType != "" && secureCellFederationIncidentResponseStepStatus(response, stepType) == SecureCellFederationIncidentPlaybookStepStatusCompleted {
			continue
		}
		return tier, true
	}
	return SecureCellFederationEscalationTier{}, false
}

func secureCellFederationIncidentResponseTierStepType(tierID string) SecureCellFederationIncidentPlaybookStepType {
	switch strings.ToLower(strings.TrimSpace(tierID)) {
	case "acknowledge":
		return SecureCellFederationIncidentPlaybookStepTypeAcknowledge
	case "remediate":
		return SecureCellFederationIncidentPlaybookStepTypeRemediate
	case "verify_remediation":
		return SecureCellFederationIncidentPlaybookStepTypeVerify
	default:
		return ""
	}
}

func secureCellFederationIncidentResponseStepDueAndStatus(response SecureCellFederationIncidentResponse, stepType SecureCellFederationIncidentPlaybookStepType) (*time.Time, SecureCellFederationIncidentPlaybookStepStatus) {
	for _, step := range response.PlaybookSteps {
		if step.Type == stepType {
			return cloneTimePtr(step.DueAt), step.Status
		}
	}
	return nil, ""
}

func secureCellFederationIncidentResponseStepStatus(response SecureCellFederationIncidentResponse, stepType SecureCellFederationIncidentPlaybookStepType) SecureCellFederationIncidentPlaybookStepStatus {
	_, status := secureCellFederationIncidentResponseStepDueAndStatus(response, stepType)
	return status
}

func secureCellFederationIncidentResponseRemediationDeadline(response SecureCellFederationIncidentResponse, from time.Time) time.Time {
	_, _, remediationAfter, _ := secureCellFederationIncidentPlaybookDefaults(response.IncidentSeverity)
	return from.UTC().Add(remediationAfter).UTC()
}

func secureCellFederationIncidentResponseVerifyDeadline(response SecureCellFederationIncidentResponse, from time.Time) time.Time {
	_, _, _, verifyAfter := secureCellFederationIncidentPlaybookDefaults(response.IncidentSeverity)
	return from.UTC().Add(verifyAfter).UTC()
}

func secureCellLatestFederationIncidentRemediationAttestationID(response SecureCellFederationIncidentResponse, party SecureCellFederationIncidentResponseParty) string {
	for idx := len(response.RemediationAttestations) - 1; idx >= 0; idx-- {
		if party != "" && response.RemediationAttestations[idx].AttestingParty != party {
			continue
		}
		return strings.TrimSpace(response.RemediationAttestations[idx].ID)
	}
	return ""
}

func secureCellLatestFederationIncidentVerificationDecision(response SecureCellFederationIncidentResponse) SecureCellFederationIncidentRemediationVerificationDecision {
	for idx := len(response.RemediationVerifications) - 1; idx >= 0; idx-- {
		if normalized := secureCellNormalizedFederationIncidentRemediationVerificationDecision(response.RemediationVerifications[idx].Decision); normalized != "" {
			return normalized
		}
	}
	return ""
}

func secureCellLatestFederationIncidentClosureAttestationID(response SecureCellFederationIncidentResponse) string {
	for idx := len(response.ClosureAttestations) - 1; idx >= 0; idx-- {
		return strings.TrimSpace(response.ClosureAttestations[idx].ID)
	}
	return ""
}

func secureCellLatestFederationIncidentDisputeID(response SecureCellFederationIncidentResponse) string {
	for idx := len(response.Disputes) - 1; idx >= 0; idx-- {
		return strings.TrimSpace(response.Disputes[idx].ID)
	}
	return ""
}

func matchesSecureCellFederationIncidentResponseFilter(summary SecureCellFederationIncidentResponseSummary, filter SecureCellFederationIncidentResponseFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(summary.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(summary.IncidentID, strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(summary.ResponseID, strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.ContractID != "" && !secureCellStringSliceContains(summary.ContractIDs, strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.Status != "" && summary.Status != filter.Status {
		return false
	}
	if filter.SourceType != "" && summary.SourceType != filter.SourceType {
		return false
	}
	return true
}

func secureCellFederationIncidentResponseActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentResponseActionRecord, bool) {
	responseID := strings.TrimSpace(transition.Metadata["federation_incident_response_id"])
	if responseID == "" {
		return SecureCellFederationIncidentResponseActionRecord{}, false
	}
	record := SecureCellFederationIncidentResponseActionRecord{
		CellID:               strings.TrimSpace(run.result.CellID),
		CellName:             strings.TrimSpace(run.result.Name),
		Jurisdiction:         strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:           run.result.Status,
		OrganizationID:       strings.TrimSpace(transition.Metadata["federation_organization_id"]),
		SponsorOfRecord:      strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
		IncidentID:           strings.TrimSpace(transition.Metadata["federation_incident_id"]),
		ResponseID:           responseID,
		ContractIDs:          uniqueTrimmedStrings(strings.Split(transition.Metadata["federation_contract_ids"], ",")),
		SourceType:           SecureCellFederationIncidentResponseSource(strings.TrimSpace(transition.Metadata["federation_incident_response_source"])),
		ResponseStatusBefore: SecureCellFederationIncidentResponseStatus(strings.TrimSpace(transition.Metadata["federation_incident_response_status_before"])),
		ResponseStatusAfter:  SecureCellFederationIncidentResponseStatus(strings.TrimSpace(transition.Metadata["federation_incident_response_status_after"])),
		Action:               firstNonEmpty(strings.TrimSpace(transition.Metadata["federation_incident_response_action"]), strings.TrimSpace(transition.Action)),
		Trigger:              strings.TrimSpace(transition.Metadata["federation_incident_response_trigger"]),
		TierID:               strings.TrimSpace(transition.Metadata["federation_incident_response_tier_id"]),
		TargetDID:            strings.TrimSpace(transition.Metadata["federation_incident_response_target_did"]),
		Actor:                strings.TrimSpace(transition.Actor),
		AutomatedActor:       strings.TrimSpace(transition.Metadata["automated_actor"]),
		Reason:               strings.TrimSpace(transition.Reason),
		TransitionID:         strings.TrimSpace(transition.ID),
		OccurredAt:           transition.OccurredAt.UTC(),
		Metadata:             cloneStringMap(transition.Metadata),
	}
	return record, true
}

func matchesSecureCellFederationIncidentResponseActionFilter(record SecureCellFederationIncidentResponseActionRecord, filter SecureCellFederationIncidentResponseActionFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(record.OrganizationID, strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(record.IncidentID, strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(record.ResponseID, strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.ContractID != "" && !secureCellStringSliceContains(record.ContractIDs, strings.TrimSpace(filter.ContractID)) {
		return false
	}
	if filter.Action != "" && !strings.EqualFold(record.Action, strings.TrimSpace(filter.Action)) {
		return false
	}
	if filter.Since != nil && record.OccurredAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && record.OccurredAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFederationIncidentRemediationSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, attestation SecureCellFederationIncidentRemediationAttestation) SecureCellFederationIncidentRemediationSummary {
	return SecureCellFederationIncidentRemediationSummary{
		CellID:            strings.TrimSpace(run.result.CellID),
		CellName:          strings.TrimSpace(run.result.Name),
		Jurisdiction:      strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:        run.result.Status,
		ResponseID:        strings.TrimSpace(response.ID),
		OrganizationID:    strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:   strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:        strings.TrimSpace(response.IncidentID),
		AttestationID:     strings.TrimSpace(attestation.ID),
		AttestingParty:    attestation.AttestingParty,
		SubmittedBy:       strings.TrimSpace(attestation.SubmittedBy),
		Summary:           strings.TrimSpace(attestation.Summary),
		Description:       strings.TrimSpace(attestation.Description),
		EvidenceIDs:       append([]string(nil), attestation.EvidenceIDs...),
		PolicyReceiptID:   strings.TrimSpace(attestation.PolicyReceiptID),
		PolicyReceiptHash: strings.TrimSpace(attestation.PolicyReceiptHash),
		SealID:            strings.TrimSpace(attestation.SealID),
		TraceLinkID:       strings.TrimSpace(attestation.TraceLinkID),
		CreatedAt:         attestation.CreatedAt.UTC(),
		Metadata:          cloneStringMap(attestation.Metadata),
	}
}

func secureCellFederationIncidentVerificationSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, verification SecureCellFederationIncidentRemediationVerification) SecureCellFederationIncidentVerificationSummary {
	return SecureCellFederationIncidentVerificationSummary{
		CellID:                strings.TrimSpace(run.result.CellID),
		CellName:              strings.TrimSpace(run.result.Name),
		Jurisdiction:          strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:            run.result.Status,
		ResponseID:            strings.TrimSpace(response.ID),
		OrganizationID:        strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:       strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:            strings.TrimSpace(response.IncidentID),
		VerificationID:        strings.TrimSpace(verification.ID),
		ReviewingParty:        verification.ReviewingParty,
		Decision:              verification.Decision,
		VerifiedAttestationID: strings.TrimSpace(verification.VerifiedAttestationID),
		SubmittedBy:           strings.TrimSpace(verification.SubmittedBy),
		Summary:               strings.TrimSpace(verification.Summary),
		Description:           strings.TrimSpace(verification.Description),
		EvidenceIDs:           append([]string(nil), verification.EvidenceIDs...),
		PolicyReceiptID:       strings.TrimSpace(verification.PolicyReceiptID),
		PolicyReceiptHash:     strings.TrimSpace(verification.PolicyReceiptHash),
		SealID:                strings.TrimSpace(verification.SealID),
		TraceLinkID:           strings.TrimSpace(verification.TraceLinkID),
		CreatedAt:             verification.CreatedAt.UTC(),
		Metadata:              cloneStringMap(verification.Metadata),
	}
}

func secureCellFederationIncidentClosureAttestationSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, attestation SecureCellFederationIncidentClosureAttestation) SecureCellFederationIncidentClosureAttestationSummary {
	return SecureCellFederationIncidentClosureAttestationSummary{
		CellID:            strings.TrimSpace(run.result.CellID),
		CellName:          strings.TrimSpace(run.result.Name),
		Jurisdiction:      strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:        run.result.Status,
		ResponseID:        strings.TrimSpace(response.ID),
		OrganizationID:    strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:   strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:        strings.TrimSpace(response.IncidentID),
		AttestationID:     strings.TrimSpace(attestation.ID),
		AttestingParty:    attestation.AttestingParty,
		SubmittedBy:       strings.TrimSpace(attestation.SubmittedBy),
		Summary:           strings.TrimSpace(attestation.Summary),
		Description:       strings.TrimSpace(attestation.Description),
		EvidenceIDs:       append([]string(nil), attestation.EvidenceIDs...),
		PolicyReceiptID:   strings.TrimSpace(attestation.PolicyReceiptID),
		PolicyReceiptHash: strings.TrimSpace(attestation.PolicyReceiptHash),
		SealID:            strings.TrimSpace(attestation.SealID),
		TraceLinkID:       strings.TrimSpace(attestation.TraceLinkID),
		CreatedAt:         attestation.CreatedAt.UTC(),
		Metadata:          cloneStringMap(attestation.Metadata),
	}
}

func secureCellFederationIncidentDisputeSummaryFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, dispute SecureCellFederationIncidentDisputeRecord) SecureCellFederationIncidentDisputeSummary {
	return SecureCellFederationIncidentDisputeSummary{
		CellID:                 strings.TrimSpace(run.result.CellID),
		CellName:               strings.TrimSpace(run.result.Name),
		Jurisdiction:           strings.TrimSpace(run.request.Jurisdiction),
		CellStatus:             run.result.Status,
		ResponseID:             strings.TrimSpace(response.ID),
		OrganizationID:         strings.TrimSpace(response.OrganizationID),
		SponsorOfRecord:        strings.TrimSpace(response.SponsorOfRecord),
		IncidentID:             strings.TrimSpace(response.IncidentID),
		DisputeID:              strings.TrimSpace(dispute.ID),
		DisputingParty:         dispute.DisputingParty,
		SubmittedBy:            strings.TrimSpace(dispute.SubmittedBy),
		RelatedVerificationID:  strings.TrimSpace(dispute.RelatedVerificationID),
		RelatedClosureID:       strings.TrimSpace(dispute.RelatedClosureID),
		Summary:                strings.TrimSpace(dispute.Summary),
		Description:            strings.TrimSpace(dispute.Description),
		EvidenceIDs:            append([]string(nil), dispute.EvidenceIDs...),
		Reopened:               dispute.Reopened,
		ReopenedResponseStatus: dispute.ReopenedResponseStatus,
		PolicyReceiptID:        strings.TrimSpace(dispute.PolicyReceiptID),
		PolicyReceiptHash:      strings.TrimSpace(dispute.PolicyReceiptHash),
		SealID:                 strings.TrimSpace(dispute.SealID),
		TraceLinkID:            strings.TrimSpace(dispute.TraceLinkID),
		CreatedAt:              dispute.CreatedAt.UTC(),
		Metadata:               cloneStringMap(dispute.Metadata),
	}
}

func secureCellFederationIncidentResponsesByStatus(items []SecureCellFederationIncidentResponse, status SecureCellFederationIncidentResponseStatus) []SecureCellFederationIncidentResponse {
	if len(items) == 0 {
		return nil
	}
	out := make([]SecureCellFederationIncidentResponse, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			out = append(out, item)
		}
	}
	return out
}

func secureCellFederationIncidentResponseIDsForIncident(items []SecureCellFederationIncidentResponse, incidentID string) []string {
	incidentID = strings.TrimSpace(incidentID)
	if incidentID == "" {
		return nil
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.IncidentID) != incidentID {
			continue
		}
		ids = append(ids, strings.TrimSpace(item.ID))
	}
	return uniqueTrimmedStrings(ids)
}

func secureCellFederationIncidentResponseRemediationTotal(items []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, item := range items {
		total += len(item.RemediationAttestations)
	}
	return total
}

func secureCellFederationIncidentResponseVerificationTotal(items []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, item := range items {
		total += len(item.RemediationVerifications)
	}
	return total
}

func secureCellFederationIncidentResponseClosureAttestationTotal(items []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, item := range items {
		total += len(item.ClosureAttestations)
	}
	return total
}

func secureCellFederationIncidentResponseDisputeTotal(items []SecureCellFederationIncidentResponse) int {
	total := 0
	for _, item := range items {
		total += len(item.Disputes)
	}
	return total
}
