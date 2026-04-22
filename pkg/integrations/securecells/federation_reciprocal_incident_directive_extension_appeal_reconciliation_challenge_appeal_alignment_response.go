package securecells

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus
// tracks verification and freshness posture for one imported signed
// correction-board bundle.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus string

const (
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusVerified SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "verified"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusStale    SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "stale"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusExpired  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "expired"
	SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusInvalid  SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus = "invalid"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus
// captures the local review posture over one imported counterparty
// correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusUnreviewed   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus = "unreviewed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus = "acknowledged"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusDisputed     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus = "disputed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusEscalated    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus = "escalated"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusResolved     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus = "resolved"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType
// captures one evidence-bearing local response to a signed counterparty
// correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionAcknowledge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType = "acknowledge_counterparty_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionDispute     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType = "dispute_counterparty_ruling"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionEscalate    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType = "escalate_counterparty_ruling_dispute"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionResolve     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType = "resolve_counterparty_ruling_dispute"
)

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot
// persists one imported signed alignment-response bundle in the secure-cell
// trace.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot struct {
	SnapshotID          string                                                                                                               `json:"snapshot_id"`
	OrganizationID      string                                                                                                               `json:"organization_id"`
	Bundle              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle             `json:"bundle"`
	Status              SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus `json:"status"`
	Verified            bool                                                                                                                 `json:"verified"`
	VerificationMessage string                                                                                                               `json:"verification_message,omitempty"`
	Signer              string                                                                                                               `json:"signer,omitempty"`
	ReceivedBy          string                                                                                                               `json:"received_by,omitempty"`
	ReceivedAt          time.Time                                                                                                            `json:"received_at"`
	Metadata            map[string]string                                                                                                    `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest
// ingests one signed counterparty alignment-response bundle into the evidence
// chain.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest struct {
	ActorDID string                                                                                                    `json:"actor_did,omitempty"`
	Bundle   *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle `json:"bundle,omitempty"`
	Reason   string                                                                                                    `json:"reason,omitempty"`
	Metadata map[string]string                                                                                         `json:"metadata,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter
// narrows operator queries across imported counterparty correction-board bundles.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter struct {
	CellID            string                                                                                                                           `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                                           `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                                           `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                                           `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                                           `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                                           `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                                           `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                                           `json:"appeal_id,omitempty"`
	ChallengeID       string                                                                                                                           `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                                           `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID  string                                                                                                                           `json:"response_appeal_id,omitempty"`
	SnapshotID        string                                                                                                                           `json:"snapshot_id,omitempty"`
	Status            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus             `json:"status,omitempty"`
	AlignmentStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                 `json:"alignment_status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status,omitempty"`
	Signer            string                                                                                                                           `json:"signer,omitempty"`
	Limit             int                                                                                                                              `json:"limit,omitempty"`
}

// SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
// is the operator-facing summary of one imported counterparty correction-board
// appeal.
type SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary struct {
	CellID                          string                                                                                                                           `json:"cell_id"`
	CellName                        string                                                                                                                           `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                                                 `json:"cell_status"`
	Jurisdiction                    string                                                                                                                           `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                                                           `json:"organization_id"`
	SponsorOfRecord                 string                                                                                                                           `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                                                           `json:"organization_name,omitempty"`
	SnapshotID                      string                                                                                                                           `json:"snapshot_id"`
	BundleID                        string                                                                                                                           `json:"bundle_id,omitempty"`
	BundleVersion                   string                                                                                                                           `json:"bundle_version,omitempty"`
	BundleName                      string                                                                                                                           `json:"bundle_name,omitempty"`
	Status                          SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus             `json:"status"`
	Verified                        bool                                                                                                                             `json:"verified"`
	Signer                          string                                                                                                                           `json:"signer,omitempty"`
	KeyID                           string                                                                                                                           `json:"key_id,omitempty"`
	IncidentID                      string                                                                                                                           `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                                                           `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                                                           `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                                                                           `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                                                           `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                                                           `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                                                           `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                                                           `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                string                                                                                                                           `json:"response_appeal_id"`
	ParentResponseAppealID          string                                                                                                                           `json:"parent_response_appeal_id,omitempty"`
	ResponseAppealGeneration        int                                                                                                                              `json:"response_appeal_generation,omitempty"`
	ResponseAppealStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"response_appeal_status"`
	ResponseStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                         `json:"response_status,omitempty"`
	ResponseAction                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                     `json:"response_action,omitempty"`
	ResponseTransitionID            string                                                                                                                           `json:"response_transition_id,omitempty"`
	ResponseCounterpartyReference   string                                                                                                                           `json:"response_counterparty_reference,omitempty"`
	ResponseCounterpartySnapshotID  string                                                                                                                           `json:"response_counterparty_snapshot_id,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                                                        `json:"appealing_party,omitempty"`
	CorrectionBoardParty            SecureCellFederationIncidentResponseParty                                                                                        `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                                                        `json:"enforcement_acknowledgement_party,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                       `json:"ruling,omitempty"`
	BoardReviewThreshold            int                                                                                                                              `json:"board_review_threshold,omitempty"`
	BoardDelegationCount            int                                                                                                                              `json:"board_delegation_count,omitempty"`
	BoardRecusalCount               int                                                                                                                              `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                                                              `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                                                              `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                                                              `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                                                              `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                                                             `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                                                              `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                                                              `json:"overturn_vote_count,omitempty"`
	GeneratedAt                     time.Time                                                                                                                        `json:"generated_at,omitempty"`
	ExpiresAt                       *time.Time                                                                                                                       `json:"expires_at,omitempty"`
	ReceivedAt                      time.Time                                                                                                                        `json:"received_at,omitempty"`
	ControlLedgerID                 string                                                                                                                           `json:"control_ledger_id,omitempty"`
	ControlLedgerHash               string                                                                                                                           `json:"control_ledger_hash,omitempty"`
	PortablePackageHash             string                                                                                                                           `json:"portable_package_hash,omitempty"`
	PortablePackageSigned           bool                                                                                                                             `json:"portable_package_signed"`
	PortablePackageAnchored         bool                                                                                                                             `json:"portable_package_anchored"`
	VerificationMessage             string                                                                                                                           `json:"verification_message,omitempty"`
	MatchedLocalResponseAppealID    string                                                                                                                           `json:"matched_local_response_appeal_id,omitempty"`
	AlignmentStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                 `json:"alignment_status,omitempty"`
	AlignmentDivergenceCount        int                                                                                                                              `json:"alignment_divergence_count"`
	ReviewStatus                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status,omitempty"`
	LastReviewedBy                  string                                                                                                                           `json:"last_reviewed_by,omitempty"`
	LastReviewedAt                  *time.Time                                                                                                                       `json:"last_reviewed_at,omitempty"`
	ReviewActionCount               int                                                                                                                              `json:"review_action_count"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest
// records local acknowledgement of one imported correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest struct {
	ActorDID                     string            `json:"actor_did,omitempty"`
	CounterpartySnapshotID       string            `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyResponseAppealID string            `json:"counterparty_response_appeal_id,omitempty"`
	CounterpartyReference        string            `json:"counterparty_reference,omitempty"`
	Reason                       string            `json:"reason,omitempty"`
	Metadata                     map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest
// records local dispute of one imported correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest struct {
	ActorDID                     string            `json:"actor_did,omitempty"`
	CounterpartySnapshotID       string            `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyResponseAppealID string            `json:"counterparty_response_appeal_id,omitempty"`
	CounterpartyReference        string            `json:"counterparty_reference,omitempty"`
	Reason                       string            `json:"reason,omitempty"`
	Divergences                  []string          `json:"divergences,omitempty"`
	Metadata                     map[string]string `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeEscalationRequest
// opens a fresh local rehearing generation after a disputed imported
// counterparty correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeEscalationRequest struct {
	ActorDID                            string                                    `json:"actor_did,omitempty"`
	CounterpartySnapshotID              string                                    `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyResponseAppealID        string                                    `json:"counterparty_response_appeal_id,omitempty"`
	CounterpartyReference               string                                    `json:"counterparty_reference,omitempty"`
	AppealingParty                      SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	CorrectionBoardParty                SecureCellFederationIncidentResponseParty `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty     SecureCellFederationIncidentResponseParty `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                             string                                    `json:"summary,omitempty"`
	Description                         string                                    `json:"description,omitempty"`
	EvidenceIDs                         []string                                  `json:"evidence_ids,omitempty"`
	Divergences                         []string                                  `json:"divergences,omitempty"`
	CorrectionBoardReviewThreshold      int                                       `json:"correction_board_review_threshold,omitempty"`
	EligibleCorrectionBoardReviewerDIDs []string                                  `json:"eligible_correction_board_reviewer_dids,omitempty"`
	Reason                              string                                    `json:"reason,omitempty"`
	Metadata                            map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter
// narrows operator queries across bilateral review actions over imported
// correction-board rulings.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter struct {
	CellID                       string                                                                                                                           `json:"cell_id,omitempty"`
	OrganizationID               string                                                                                                                           `json:"organization_id,omitempty"`
	IncidentID                   string                                                                                                                           `json:"incident_id,omitempty"`
	ResponseID                   string                                                                                                                           `json:"response_id,omitempty"`
	DirectiveID                  string                                                                                                                           `json:"directive_id,omitempty"`
	ExtensionID                  string                                                                                                                           `json:"extension_id,omitempty"`
	DisputeID                    string                                                                                                                           `json:"dispute_id,omitempty"`
	AppealID                     string                                                                                                                           `json:"appeal_id,omitempty"`
	ChallengeID                  string                                                                                                                           `json:"challenge_id,omitempty"`
	ChallengeAppealID            string                                                                                                                           `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID             string                                                                                                                           `json:"response_appeal_id,omitempty"`
	CounterpartySnapshotID       string                                                                                                                           `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyResponseAppealID string                                                                                                                           `json:"counterparty_response_appeal_id,omitempty"`
	AlignmentStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                 `json:"alignment_status,omitempty"`
	ReviewStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status,omitempty"`
	Action                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType   `json:"action,omitempty"`
	ActorDID                     string                                                                                                                           `json:"actor_did,omitempty"`
	Limit                        int                                                                                                                              `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord
// projects one bilateral acknowledgement or dispute over an imported
// correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord struct {
	CellID                           string                                                                                                                           `json:"cell_id"`
	CellName                         string                                                                                                                           `json:"cell_name,omitempty"`
	CellStatus                       SecureCellStatus                                                                                                                 `json:"cell_status"`
	Jurisdiction                     string                                                                                                                           `json:"jurisdiction,omitempty"`
	OrganizationID                   string                                                                                                                           `json:"organization_id"`
	SponsorOfRecord                  string                                                                                                                           `json:"sponsor_of_record,omitempty"`
	OrganizationName                 string                                                                                                                           `json:"organization_name,omitempty"`
	IncidentID                       string                                                                                                                           `json:"incident_id,omitempty"`
	ResponseID                       string                                                                                                                           `json:"response_id,omitempty"`
	DirectiveID                      string                                                                                                                           `json:"directive_id,omitempty"`
	ExtensionID                      string                                                                                                                           `json:"extension_id,omitempty"`
	DisputeID                        string                                                                                                                           `json:"dispute_id,omitempty"`
	AppealID                         string                                                                                                                           `json:"appeal_id,omitempty"`
	ChallengeID                      string                                                                                                                           `json:"challenge_id,omitempty"`
	ChallengeAppealID                string                                                                                                                           `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                 string                                                                                                                           `json:"response_appeal_id,omitempty"`
	LocalResponseAppealStatus        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"local_response_appeal_status,omitempty"`
	LocalResponseStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                         `json:"local_response_status,omitempty"`
	LocalResponseAction              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                     `json:"local_response_action,omitempty"`
	LocalResponseTransitionID        string                                                                                                                           `json:"local_response_transition_id,omitempty"`
	LocalRuling                      SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                       `json:"local_ruling,omitempty"`
	CounterpartySnapshotID           string                                                                                                                           `json:"counterparty_snapshot_id"`
	CounterpartyBundleID             string                                                                                                                           `json:"counterparty_bundle_id,omitempty"`
	CounterpartyResponseAppealID     string                                                                                                                           `json:"counterparty_response_appeal_id"`
	CounterpartyResponseAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus                   `json:"counterparty_response_appeal_status,omitempty"`
	CounterpartyResponseStatus       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus                         `json:"counterparty_response_status,omitempty"`
	CounterpartyResponseAction       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType                     `json:"counterparty_response_action,omitempty"`
	CounterpartyResponseTransitionID string                                                                                                                           `json:"counterparty_response_transition_id,omitempty"`
	CounterpartyRuling               SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                                       `json:"counterparty_ruling,omitempty"`
	CounterpartyReference            string                                                                                                                           `json:"counterparty_reference,omitempty"`
	AlignmentStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus                                 `json:"alignment_status,omitempty"`
	AlignmentDivergenceCount         int                                                                                                                              `json:"alignment_divergence_count"`
	ReviewStatus                     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus `json:"review_status"`
	Action                           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType   `json:"action"`
	Divergences                      []string                                                                                                                         `json:"divergences,omitempty"`
	TransitionID                     string                                                                                                                           `json:"transition_id,omitempty"`
	PolicyReceiptID                  string                                                                                                                           `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash                string                                                                                                                           `json:"policy_receipt_hash,omitempty"`
	SealID                           string                                                                                                                           `json:"seal_id,omitempty"`
	TraceLinkID                      string                                                                                                                           `json:"trace_link_id,omitempty"`
	ActorDID                         string                                                                                                                           `json:"actor_did,omitempty"`
	Reason                           string                                                                                                                           `json:"reason,omitempty"`
	Metadata                         map[string]string                                                                                                                `json:"metadata,omitempty"`
	OccurredAt                       time.Time                                                                                                                        `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionSpec struct {
	stage                        string
	action                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType
	reviewStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus
	actorDID                     string
	counterpartySnapshotID       string
	counterpartyResponseAppealID string
	counterpartyReference        string
	reason                       string
	divergences                  []string
	metadata                     map[string]string
}

func (s *Service) IngestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(ctx context.Context, cellID string, organizationID string, intake SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleIntakeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, _, err := secureCellFederationOrganizationSummaryAndRef(run, organizationID)
	if err != nil {
		return nil, err
	}
	if intake.Bundle == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: bundle is required")
	}
	bundle := secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(*intake.Bundle)
	actorDID := firstNonEmpty(strings.TrimSpace(intake.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: %w: actor %q is not permitted to intake alignment-response bundles", ErrPolicyDenied, actorDID)
	}

	verificationErr := VerifyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(&bundle)
	if verificationErr == nil {
		verificationErr = secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSemantics(&bundle, strings.TrimSpace(summary.OrganizationID))
	}
	now := time.Now().UTC()
	status, verificationMessage, verified := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleStatusAt(&bundle, verificationErr, now)

	latestAppeal, ok := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFromBundle(bundle)
	if !ok {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: at least one counterparty response appeal is required")
	}

	receipt, err := s.evaluateStage(ctx, run.request, "intake_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_bundle", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":   strings.TrimSpace(summary.OrganizationID),
		"federation_sponsor_of_record": strings.TrimSpace(summary.SponsorOfRecord),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                           strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeAppealID),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id": strings.TrimSpace(latestAppeal.ResponseAppealID),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":    string(status),
		"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_signer":    secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignerName(&bundle),
		"transition_reason": strings.TrimSpace(intake.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: %w", ErrPolicyDenied)
	}

	snapshot := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot{
		SnapshotID:          fmt.Sprintf("%s-federation-counterparty-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-%x", strings.TrimSpace(cellID), sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", strings.TrimSpace(summary.OrganizationID), strings.TrimSpace(bundle.ID), now.Format(time.RFC3339Nano))))),
		OrganizationID:      strings.TrimSpace(summary.OrganizationID),
		Bundle:              bundle,
		Status:              status,
		Verified:            verified,
		VerificationMessage: strings.TrimSpace(verificationMessage),
		Signer:              secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignerName(&bundle),
		ReceivedBy:          strings.TrimSpace(actorDID),
		ReceivedAt:          now,
		Metadata:            cloneStringMap(intake.Metadata),
	}
	run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponses = append(run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponses, snapshot)
	run.result.UpdatedAt = now

	alignmentStatus, matchedLocalResponseAppealID, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAlignmentForBundleAppeal(run, snapshot, latestAppeal)

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_bundle_ingested", snapshot.SnapshotID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_bundle_ingested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_bundle",
		TargetDID:        snapshot.SnapshotID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(intake.Reason),
		Metadata: mergeStringMaps(intake.Metadata, map[string]string{
			"federation_organization_id":   strings.TrimSpace(summary.OrganizationID),
			"federation_sponsor_of_record": strings.TrimSpace(summary.SponsorOfRecord),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_snapshot_id":           snapshot.SnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_bundle_id":             strings.TrimSpace(bundle.ID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":             strings.TrimSpace(latestAppeal.ResponseAppealID),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                string(snapshot.Status),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_verified":              fmt.Sprintf("%t", snapshot.Verified),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_signer":                snapshot.Signer,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_generated_at":          bundle.GeneratedAt.UTC().Format(time.RFC3339Nano),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_expires_at":            safeTimeString(bundle.ExpiresAt),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_content_hash":          strings.TrimSpace(bundle.ContentHash),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_verification_message":  snapshot.VerificationMessage,
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_alignment_status":      string(alignmentStatus),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_alignment_divergences": fmt.Sprintf("%d", divergenceCount),
			"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_matched_local_id":      matchedLocalResponseAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(_ context.Context, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter) ([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponses {
			for _, item := range secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummariesFromRun(run, snapshot) {
				if !matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter(item, filter) {
					continue
				}
				items = append(items, item)
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			if items[i].GeneratedAt.Equal(items[j].GeneratedAt) {
				return items[i].ResponseAppealID > items[j].ResponseAppealID
			}
			return items[i].GeneratedAt.After(items[j].GeneratedAt)
		}
		return items[i].ReceivedAt.After(items[j].ReceivedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyRuling(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAcknowledgeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAction(ctx, cellID, responseAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionSpec{
		stage:                        "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling",
		action:                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionAcknowledge,
		reviewStatus:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusAcknowledged,
		actorDID:                     req.ActorDID,
		counterpartySnapshotID:       req.CounterpartySnapshotID,
		counterpartyResponseAppealID: req.CounterpartyResponseAppealID,
		counterpartyReference:        req.CounterpartyReference,
		reason:                       req.Reason,
		metadata:                     req.Metadata,
	})
}

func (s *Service) DisputeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyRuling(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeRequest) (*SecureCellResult, error) {
	return s.applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAction(ctx, cellID, responseAppealID, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionSpec{
		stage:                        "dispute_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling",
		action:                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionDispute,
		reviewStatus:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusDisputed,
		actorDID:                     req.ActorDID,
		counterpartySnapshotID:       req.CounterpartySnapshotID,
		counterpartyResponseAppealID: req.CounterpartyResponseAppealID,
		counterpartyReference:        req.CounterpartyReference,
		reason:                       req.Reason,
		divergences:                  req.Divergences,
		metadata:                     req.Metadata,
	})
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter(record, filter) {
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

func (s *Service) applyFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyAction(ctx context.Context, cellID string, responseAppealID string, spec secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionSpec) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	localAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, responseAppealID)
	if err != nil {
		return nil, err
	}
	counterpartySummary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryBySnapshotAndAppeal(run, strings.TrimSpace(spec.counterpartySnapshotID), strings.TrimSpace(spec.counterpartyResponseAppealID))
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(counterpartySummary.ChallengeAppealID), strings.TrimSpace(localAppeal.ChallengeAppealID)) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: counterparty ruling %q does not belong to challenge appeal %q", counterpartySummary.ResponseAppealID, localAppeal.ChallengeAppealID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(spec.actorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: %w: actor %q is not permitted to review counterparty ruling %q", ErrPolicyDenied, actorDID, responseAppealID)
	}

	alignmentStatus, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAlignmentForLocalAndCounterparty(*localAppeal, counterpartySummary)
	divergences := uniqueTrimmedStrings(spec.divergences)
	if spec.action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionDispute && len(divergences) == 0 {
		divergences = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDivergences(*localAppeal, counterpartySummary)
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAction(run, responseAppealID, counterpartySummary.SnapshotID, counterpartySummary.ResponseAppealID)
	if latestReview != nil && latestReview.ReviewStatus == spec.reviewStatus {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: counterparty ruling %q is already %s", counterpartySummary.ResponseAppealID, spec.reviewStatus)
	}

	receipt, err := s.evaluateStage(ctx, run.request, spec.stage, lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                        counterpartySummary.OrganizationID,
		"federation_incident_id":                                                            counterpartySummary.IncidentID,
		"federation_incident_response_id":                                                   counterpartySummary.ResponseID,
		"federation_incident_directive_id":                                                  counterpartySummary.DirectiveID,
		"federation_incident_directive_extension_id":                                        counterpartySummary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                counterpartySummary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                 counterpartySummary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        counterpartySummary.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": counterpartySummary.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                     counterpartySummary.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_snapshot_id":      counterpartySummary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_bundle_id":        counterpartySummary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_status":    string(spec.reviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_action":    string(spec.action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_reference":        strings.TrimSpace(spec.counterpartyReference),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_alignment_status": string(alignmentStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_alignment_count":  fmt.Sprintf("%d", divergenceCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_divergences":      strings.Join(divergences, ","),
		"transition_reason": strings.TrimSpace(spec.reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyTransitionSuffix(spec.action), responseAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyTransitionSuffix(spec.action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_review",
		TargetDID:        responseAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(spec.reason),
		Metadata: mergeStringMaps(spec.metadata, map[string]string{
			"federation_organization_id":                                                        counterpartySummary.OrganizationID,
			"federation_sponsor_of_record":                                                      counterpartySummary.SponsorOfRecord,
			"federation_organization_name":                                                      counterpartySummary.OrganizationName,
			"federation_incident_id":                                                            counterpartySummary.IncidentID,
			"federation_incident_response_id":                                                   counterpartySummary.ResponseID,
			"federation_incident_directive_id":                                                  counterpartySummary.DirectiveID,
			"federation_incident_directive_extension_id":                                        counterpartySummary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                counterpartySummary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                 counterpartySummary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        counterpartySummary.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": counterpartySummary.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_appeal_id":            localAppeal.ResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_status":               string(localAppeal.ResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_action":               string(localAppeal.ResponseAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_transition_id":        localAppeal.ResponseTransitionID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_appeal_status":        string(localAppeal.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_appeal_ruling":        string(localAppeal.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_snapshot_id":            counterpartySummary.SnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_bundle_id":              counterpartySummary.BundleID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_appeal_id":     counterpartySummary.ResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_status":        string(counterpartySummary.ResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_action":        string(counterpartySummary.ResponseAction),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_transition_id": counterpartySummary.ResponseTransitionID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_appeal_status": string(counterpartySummary.ResponseAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_appeal_ruling": string(counterpartySummary.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_status":          string(spec.reviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_action":          string(spec.action),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_reference":              strings.TrimSpace(spec.counterpartyReference),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_alignment_status":       string(alignmentStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_alignment_count":        fmt.Sprintf("%d", divergenceCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_divergences":            strings.Join(divergences, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummariesFromRun(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, 0, len(snapshot.Bundle.ResponseAppeals))
	for _, appeal := range snapshot.Bundle.ResponseAppeals {
		alignmentStatus, matchedLocalResponseAppealID, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAlignmentForBundleAppeal(run, snapshot, appeal)
		reviewStatus, lastReviewedBy, lastReviewedAt, reviewActionCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStateForTarget(run, strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(appeal.ResponseAppealID))
		item := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{
			CellID:                          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
			CellName:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
			CellStatus:                      safeSecureCellStatus(run),
			Jurisdiction:                    safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
			OrganizationID:                  strings.TrimSpace(snapshot.OrganizationID),
			SponsorOfRecord:                 strings.TrimSpace(orgSummary.SponsorOfRecord),
			OrganizationName:                strings.TrimSpace(orgSummary.OrganizationName),
			SnapshotID:                      strings.TrimSpace(snapshot.SnapshotID),
			BundleID:                        strings.TrimSpace(snapshot.Bundle.ID),
			BundleVersion:                   strings.TrimSpace(snapshot.Bundle.Version),
			BundleName:                      strings.TrimSpace(snapshot.Bundle.Name),
			Status:                          snapshot.Status,
			Verified:                        snapshot.Verified,
			Signer:                          strings.TrimSpace(snapshot.Signer),
			IncidentID:                      strings.TrimSpace(appeal.IncidentID),
			ResponseID:                      strings.TrimSpace(appeal.ResponseID),
			DirectiveID:                     strings.TrimSpace(appeal.DirectiveID),
			ExtensionID:                     strings.TrimSpace(appeal.ExtensionID),
			DisputeID:                       strings.TrimSpace(appeal.DisputeID),
			AppealID:                        strings.TrimSpace(appeal.AppealID),
			ChallengeID:                     strings.TrimSpace(appeal.ChallengeID),
			ChallengeAppealID:               strings.TrimSpace(appeal.ChallengeAppealID),
			ResponseAppealID:                strings.TrimSpace(appeal.ResponseAppealID),
			ParentResponseAppealID:          strings.TrimSpace(appeal.ParentResponseAppealID),
			ResponseAppealGeneration:        secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(appeal),
			ResponseAppealStatus:            appeal.Status,
			ResponseStatus:                  appeal.ResponseStatus,
			ResponseAction:                  appeal.ResponseAction,
			ResponseTransitionID:            strings.TrimSpace(appeal.ResponseTransitionID),
			ResponseCounterpartyReference:   strings.TrimSpace(appeal.ResponseCounterpartyReference),
			ResponseCounterpartySnapshotID:  strings.TrimSpace(appeal.ResponseCounterpartySnapshotID),
			AppealingParty:                  appeal.AppealingParty,
			CorrectionBoardParty:            appeal.CorrectionBoardParty,
			EnforcementAcknowledgementParty: appeal.EnforcementAcknowledgementParty,
			Ruling:                          appeal.Ruling,
			BoardReviewThreshold:            appeal.BoardReviewThreshold,
			BoardDelegationCount:            appeal.BoardDelegationCount,
			BoardRecusalCount:               appeal.BoardRecusalCount,
			BoardCommitteeMemberCount:       appeal.BoardCommitteeMemberCount,
			BoardRecordedVoteCount:          appeal.BoardRecordedVoteCount,
			BoardOutstandingVotes:           appeal.BoardOutstandingVotes,
			BoardMissingQuorumCount:         appeal.BoardMissingQuorumCount,
			BoardThresholdSatisfied:         appeal.BoardThresholdSatisfied,
			RatifyVoteCount:                 appeal.RatifyVoteCount,
			OverturnVoteCount:               appeal.OverturnVoteCount,
			GeneratedAt:                     snapshot.Bundle.GeneratedAt.UTC(),
			ExpiresAt:                       cloneTimePtr(snapshot.Bundle.ExpiresAt),
			ReceivedAt:                      snapshot.ReceivedAt.UTC(),
			ControlLedgerID:                 strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
			ControlLedgerHash:               strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
			PortablePackageHash:             strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
			PortablePackageSigned:           snapshot.Bundle.PortablePackageSigned,
			PortablePackageAnchored:         snapshot.Bundle.PortablePackageAnchored,
			VerificationMessage:             strings.TrimSpace(snapshot.VerificationMessage),
			MatchedLocalResponseAppealID:    matchedLocalResponseAppealID,
			AlignmentStatus:                 alignmentStatus,
			AlignmentDivergenceCount:        divergenceCount,
			ReviewStatus:                    reviewStatus,
			LastReviewedBy:                  strings.TrimSpace(lastReviewedBy),
			LastReviewedAt:                  cloneTimePtr(lastReviewedAt),
			ReviewActionCount:               reviewActionCount,
		}
		if snapshot.Bundle.Signature != nil {
			item.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
		}
		items = append(items, item)
	}
	return items
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryBySnapshotAndAppeal(run *secureCellRun, snapshotID string, responseAppealID string) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, error) {
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponses {
		if !strings.EqualFold(strings.TrimSpace(snapshot.SnapshotID), strings.TrimSpace(snapshotID)) {
			continue
		}
		for _, item := range secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummariesFromRun(run, snapshot) {
			if strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
				return item, nil
			}
		}
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: %w: counterparty response appeal %q", ErrFederationIncidentDirectiveNotFound, responseAppealID)
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{}, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-counterparty: %w: counterparty snapshot %q", ErrFederationIncidentDirectiveNotFound, snapshotID)
}

func matchesSecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, filter SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseFilter) bool {
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseID), strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(item.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
		return false
	}
	if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(item.DisputeID), strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealID), strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(filter.ResponseAppealID)) {
		return false
	}
	if filter.SnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.SnapshotID), strings.TrimSpace(filter.SnapshotID)) {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	if filter.AlignmentStatus != "" && item.AlignmentStatus != filter.AlignmentStatus {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.Signer != "" && !strings.EqualFold(strings.TrimSpace(item.Signer), strings.TrimSpace(filter.Signer)) {
		return false
	}
	return true
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponsesByStatus(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot, status SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot {
	if status == "" {
		return append([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot(nil), items...)
	}
	filtered := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot, 0, len(items))
	for _, item := range items {
		if item.Status == status {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run *secureCellRun) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary {
	if run == nil || run.result == nil {
		return nil
	}
	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, 0)
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponses {
		items = append(items, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummariesFromRun(run, snapshot)...)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			if strings.EqualFold(strings.TrimSpace(items[i].SnapshotID), strings.TrimSpace(items[j].SnapshotID)) {
				return strings.TrimSpace(items[i].ResponseAppealID) < strings.TrimSpace(items[j].ResponseAppealID)
			}
			return strings.TrimSpace(items[i].SnapshotID) < strings.TrimSpace(items[j].SnapshotID)
		}
		return items[i].ReceivedAt.Before(items[j].ReceivedAt)
	})
	return items
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseReviewStatusCount(items []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus) int {
	if status == "" {
		return len(items)
	}
	count := 0
	for _, item := range items {
		if item.ReviewStatus == status {
			count++
		}
	}
	return count
}

func secureCellValidateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSemantics(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle, organizationID string) error {
	if bundle == nil {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: bundle is required")
	}
	if strings.TrimSpace(bundle.Organization.OrganizationID) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: bundle organization_id is required")
	}
	if !strings.EqualFold(strings.TrimSpace(bundle.Organization.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: bundle organization_id %q does not match organization %q", bundle.Organization.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ChallengeAppealSummary.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(bundle.ChallengeAppealSummary.OrganizationID), strings.TrimSpace(organizationID)) {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: challenge appeal organization_id %q does not match organization %q", bundle.ChallengeAppealSummary.OrganizationID, organizationID)
	}
	if strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeAppealID) == "" {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: challenge appeal id is required")
	}
	if len(bundle.ResponseAppeals) == 0 {
		return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: at least one response appeal is required")
	}
	for _, appeal := range bundle.ResponseAppeals {
		if strings.TrimSpace(appeal.OrganizationID) != "" && !strings.EqualFold(strings.TrimSpace(appeal.OrganizationID), strings.TrimSpace(organizationID)) {
			return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: response appeal organization_id %q does not match organization %q", appeal.OrganizationID, organizationID)
		}
		if !strings.EqualFold(strings.TrimSpace(appeal.ChallengeAppealID), strings.TrimSpace(bundle.ChallengeAppealSummary.ChallengeAppealID)) {
			return fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response: response appeal %q challenge appeal mismatch", appeal.ResponseAppealID)
		}
	}
	return nil
}

func secureCellCloneFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle(in SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle {
	payload, _ := json.Marshal(in)
	var out SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle
	_ = json.Unmarshal(payload, &out)
	return out
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleSignerName(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) string {
	if bundle == nil || bundle.Signature == nil {
		return ""
	}
	return strings.TrimSpace(bundle.Signature.Signer)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundleStatusAt(bundle *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle, verificationErr error, now time.Time) (SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus, string, bool) {
	if verificationErr != nil {
		return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusInvalid, verificationErr.Error(), false
	}
	if bundle != nil && bundle.ExpiresAt != nil {
		if bundle.ExpiresAt.Before(now) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusExpired, "bundle has expired", false
		}
		if bundle.ExpiresAt.Before(now.Add(24 * time.Hour)) {
			return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusStale, "bundle is nearing expiry", true
		}
	}
	return SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatusVerified, "", true
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFromBundle(bundle SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, bool) {
	if len(bundle.ResponseAppeals) == 0 {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{}, false
	}
	items := append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary(nil), bundle.ResponseAppeals...)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ResponseAppealID < items[j].ResponseAppealID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
	return items[len(items)-1], true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAlignmentForBundleAppeal(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot, appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus, string, int) {
	local := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByStableKey(run, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStableKeyFromCounterparty(appeal, snapshot.Bundle))
	if local == nil {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusCounterpartyOnly, "", 0
	}
	status, divergenceCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAlignmentForLocalAndCounterparty(*local, secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryFromLocal(run, snapshot, appeal, 0, "", nil, 0))
	return status, local.ResponseAppealID, divergenceCount
}

func secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryFromLocal(run *secureCellRun, snapshot SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseSnapshot, appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, divergenceCount int, lastReviewedBy string, lastReviewedAt *time.Time, reviewActionCount int) SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary {
	orgSummary, _, _ := secureCellFederationOrganizationSummaryAndRef(run, strings.TrimSpace(snapshot.OrganizationID))
	item := SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{
		CellID:                          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                      safeSecureCellStatus(run),
		Jurisdiction:                    safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                  strings.TrimSpace(snapshot.OrganizationID),
		SponsorOfRecord:                 strings.TrimSpace(orgSummary.SponsorOfRecord),
		OrganizationName:                strings.TrimSpace(orgSummary.OrganizationName),
		SnapshotID:                      strings.TrimSpace(snapshot.SnapshotID),
		BundleID:                        strings.TrimSpace(snapshot.Bundle.ID),
		BundleVersion:                   strings.TrimSpace(snapshot.Bundle.Version),
		BundleName:                      strings.TrimSpace(snapshot.Bundle.Name),
		Status:                          snapshot.Status,
		Verified:                        snapshot.Verified,
		Signer:                          strings.TrimSpace(snapshot.Signer),
		IncidentID:                      strings.TrimSpace(appeal.IncidentID),
		ResponseID:                      strings.TrimSpace(appeal.ResponseID),
		DirectiveID:                     strings.TrimSpace(appeal.DirectiveID),
		ExtensionID:                     strings.TrimSpace(appeal.ExtensionID),
		DisputeID:                       strings.TrimSpace(appeal.DisputeID),
		AppealID:                        strings.TrimSpace(appeal.AppealID),
		ChallengeID:                     strings.TrimSpace(appeal.ChallengeID),
		ChallengeAppealID:               strings.TrimSpace(appeal.ChallengeAppealID),
		ResponseAppealID:                strings.TrimSpace(appeal.ResponseAppealID),
		ParentResponseAppealID:          strings.TrimSpace(appeal.ParentResponseAppealID),
		ResponseAppealGeneration:        secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(appeal),
		ResponseAppealStatus:            appeal.Status,
		ResponseStatus:                  appeal.ResponseStatus,
		ResponseAction:                  appeal.ResponseAction,
		ResponseTransitionID:            strings.TrimSpace(appeal.ResponseTransitionID),
		ResponseCounterpartyReference:   strings.TrimSpace(appeal.ResponseCounterpartyReference),
		ResponseCounterpartySnapshotID:  strings.TrimSpace(appeal.ResponseCounterpartySnapshotID),
		AppealingParty:                  appeal.AppealingParty,
		CorrectionBoardParty:            appeal.CorrectionBoardParty,
		EnforcementAcknowledgementParty: appeal.EnforcementAcknowledgementParty,
		Ruling:                          appeal.Ruling,
		BoardReviewThreshold:            appeal.BoardReviewThreshold,
		BoardDelegationCount:            appeal.BoardDelegationCount,
		BoardRecusalCount:               appeal.BoardRecusalCount,
		BoardCommitteeMemberCount:       appeal.BoardCommitteeMemberCount,
		BoardRecordedVoteCount:          appeal.BoardRecordedVoteCount,
		BoardOutstandingVotes:           appeal.BoardOutstandingVotes,
		BoardMissingQuorumCount:         appeal.BoardMissingQuorumCount,
		BoardThresholdSatisfied:         appeal.BoardThresholdSatisfied,
		RatifyVoteCount:                 appeal.RatifyVoteCount,
		OverturnVoteCount:               appeal.OverturnVoteCount,
		GeneratedAt:                     snapshot.Bundle.GeneratedAt.UTC(),
		ExpiresAt:                       cloneTimePtr(snapshot.Bundle.ExpiresAt),
		ReceivedAt:                      snapshot.ReceivedAt.UTC(),
		ControlLedgerID:                 strings.TrimSpace(snapshot.Bundle.ControlLedgerID),
		ControlLedgerHash:               strings.TrimSpace(snapshot.Bundle.ControlLedgerHash),
		PortablePackageHash:             strings.TrimSpace(snapshot.Bundle.PortablePackageHash),
		PortablePackageSigned:           snapshot.Bundle.PortablePackageSigned,
		PortablePackageAnchored:         snapshot.Bundle.PortablePackageAnchored,
		VerificationMessage:             strings.TrimSpace(snapshot.VerificationMessage),
		AlignmentDivergenceCount:        divergenceCount,
		LastReviewedBy:                  strings.TrimSpace(lastReviewedBy),
		LastReviewedAt:                  cloneTimePtr(lastReviewedAt),
		ReviewActionCount:               reviewActionCount,
	}
	if snapshot.Bundle.Signature != nil {
		item.KeyID = strings.TrimSpace(snapshot.Bundle.Signature.KeyID)
	}
	return item
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByStableKey(run *secureCellRun, stableKey string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary {
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		candidate := item
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStableKey(candidate, run) == stableKey {
			return &candidate
		}
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStableKey(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, run *secureCellRun) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(item.ChallengeAppealID),
		fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGenerationForRun(run, item)),
		string(item.AppealingParty),
		string(item.CorrectionBoardParty),
		string(item.EnforcementAcknowledgementParty),
	}, "|"))
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStableKeyFromCounterparty(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, bundle SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle) string {
	return strings.ToLower(strings.Join([]string{
		strings.TrimSpace(item.ChallengeAppealID),
		fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyGeneration(bundle, item)),
		string(item.AppealingParty),
		string(item.CorrectionBoardParty),
		string(item.EnforcementAcknowledgementParty),
	}, "|"))
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGenerationForRun(run *secureCellRun, appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) int {
	if generation := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(appeal); generation > 0 {
		return generation
	}
	items := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run)
	sorted := append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ResponseAppealID < sorted[j].ResponseAppealID
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	generation := 0
	for _, item := range sorted {
		if !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(appeal.ResponseAppealID)) {
			continue
		}
		generation++
		return generation
	}
	return 0
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyGeneration(bundle SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseBundle, appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) int {
	if generation := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(appeal); generation > 0 {
		return generation
	}
	sorted := append([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary(nil), bundle.ResponseAppeals...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].ResponseAppealID < sorted[j].ResponseAppealID
		}
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})
	generation := 0
	for _, item := range sorted {
		if !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(appeal.ResponseAppealID)) {
			continue
		}
		generation++
		return generation
	}
	return 0
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAlignmentForLocalAndCounterparty(local SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, counterparty SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus, int) {
	divergenceCount := 0
	if local.Status != counterparty.ResponseAppealStatus {
		divergenceCount++
	}
	if strings.TrimSpace(local.ParentResponseAppealID) != strings.TrimSpace(counterparty.ParentResponseAppealID) {
		divergenceCount++
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(local) != max(counterparty.ResponseAppealGeneration, 1) {
		divergenceCount++
	}
	if local.ResponseStatus != counterparty.ResponseStatus {
		divergenceCount++
	}
	if local.ResponseAction != counterparty.ResponseAction {
		divergenceCount++
	}
	if local.Ruling != counterparty.Ruling {
		divergenceCount++
	}
	if local.AppealingParty != counterparty.AppealingParty {
		divergenceCount++
	}
	if local.CorrectionBoardParty != counterparty.CorrectionBoardParty {
		divergenceCount++
	}
	if local.EnforcementAcknowledgementParty != counterparty.EnforcementAcknowledgementParty {
		divergenceCount++
	}
	if local.BoardReviewThreshold != counterparty.BoardReviewThreshold {
		divergenceCount++
	}
	if local.BoardDelegationCount != counterparty.BoardDelegationCount {
		divergenceCount++
	}
	if local.BoardRecusalCount != counterparty.BoardRecusalCount {
		divergenceCount++
	}
	if local.BoardRecordedVoteCount != counterparty.BoardRecordedVoteCount {
		divergenceCount++
	}
	if local.BoardCommitteeMemberCount != counterparty.BoardCommitteeMemberCount {
		divergenceCount++
	}
	if local.BoardThresholdSatisfied != counterparty.BoardThresholdSatisfied {
		divergenceCount++
	}
	if divergenceCount == 0 {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned, 0
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusDivergent, divergenceCount
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDivergences(local SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, counterparty SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) []string {
	divergences := make([]string, 0, 10)
	if local.Status != counterparty.ResponseAppealStatus {
		divergences = append(divergences, "response appeal status diverged")
	}
	if strings.TrimSpace(local.ParentResponseAppealID) != strings.TrimSpace(counterparty.ParentResponseAppealID) {
		divergences = append(divergences, "response appeal rehearing lineage diverged")
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(local) != max(counterparty.ResponseAppealGeneration, 1) {
		divergences = append(divergences, "response appeal generation diverged")
	}
	if local.Ruling != counterparty.Ruling {
		divergences = append(divergences, "correction-board ruling diverged")
	}
	if local.BoardReviewThreshold != counterparty.BoardReviewThreshold {
		divergences = append(divergences, "correction-board threshold diverged")
	}
	if local.BoardRecusalCount != counterparty.BoardRecusalCount {
		divergences = append(divergences, "correction-board recusal count diverged")
	}
	if local.BoardRecordedVoteCount != counterparty.BoardRecordedVoteCount {
		divergences = append(divergences, "correction-board vote count diverged")
	}
	if local.BoardThresholdSatisfied != counterparty.BoardThresholdSatisfied {
		divergences = append(divergences, "correction-board quorum satisfaction diverged")
	}
	if len(divergences) == 0 {
		divergences = append(divergences, "counterparty correction-board ruling diverged from local response appeal posture")
	}
	return divergences
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStateForTarget(run *secureCellRun, snapshotID string, counterpartyResponseAppealID string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus, string, *time.Time, int) {
	status := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusUnreviewed
	var lastReviewedBy string
	var lastReviewedAt *time.Time
	count := 0
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.CounterpartySnapshotID), strings.TrimSpace(snapshotID)) || !strings.EqualFold(strings.TrimSpace(record.CounterpartyResponseAppealID), strings.TrimSpace(counterpartyResponseAppealID)) {
			continue
		}
		status = record.ReviewStatus
		lastReviewedBy = strings.TrimSpace(record.ActorDID)
		at := record.OccurredAt.UTC()
		lastReviewedAt = &at
		count++
	}
	return status, lastReviewedBy, lastReviewedAt, count
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAction(run *secureCellRun, responseAppealID string, snapshotID string, counterpartyResponseAppealID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord {
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ResponseAppealID), strings.TrimSpace(responseAppealID)) || !strings.EqualFold(strings.TrimSpace(record.CounterpartySnapshotID), strings.TrimSpace(snapshotID)) || !strings.EqualFold(strings.TrimSpace(record.CounterpartyResponseAppealID), strings.TrimSpace(counterpartyResponseAppealID)) {
			continue
		}
		recordCopy := record
		latest = &recordCopy
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord, bool) {
	meta := cloneStringMap(transition.Metadata)
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionTypeFromTransition(transition.Action, meta)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord{}, false
	}
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord{
		CellID:                    safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                  safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                safeSecureCellStatus(run),
		Jurisdiction:              safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:            strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:           strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:          strings.TrimSpace(meta["federation_organization_name"]),
		IncidentID:                strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:               strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:               strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                 strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		ChallengeID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ChallengeAppealID:         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
		ResponseAppealID:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_appeal_id"]),
		LocalResponseAppealStatus: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_appeal_status"])),
		LocalResponseStatus:       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_status"])),
		LocalResponseAction:       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_action"])),
		LocalResponseTransitionID: strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_transition_id"]),
		LocalRuling:               SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_appeal_ruling"])),
		CounterpartySnapshotID: firstNonEmpty(
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_snapshot_id"]),
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_snapshot_id"]),
		),
		CounterpartyBundleID: firstNonEmpty(
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_bundle_id"]),
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_bundle_id"]),
		),
		CounterpartyResponseAppealID: firstNonEmpty(
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_appeal_id"]),
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_response_appeal_id"]),
		),
		CounterpartyResponseAppealStatus: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_appeal_status"])),
		CounterpartyResponseStatus:       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_status"])),
		CounterpartyResponseAction:       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_action"])),
		CounterpartyResponseTransitionID: strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_transition_id"]),
		CounterpartyRuling:               SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_response_appeal_ruling"])),
		CounterpartyReference: firstNonEmpty(
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_reference"]),
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_reference"]),
		),
		AlignmentStatus:          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_alignment_status"])),
		AlignmentDivergenceCount: secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_alignment_count"),
		ReviewStatus:             SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_status"])),
		Action:                   actionType,
		Divergences:              uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_divergences"]), ",")),
		TransitionID:             strings.TrimSpace(transition.ID),
		ActorDID:                 strings.TrimSpace(transition.Actor),
		Reason:                   strings.TrimSpace(transition.Reason),
		Metadata:                 meta,
		OccurredAt:               transition.OccurredAt.UTC(),
	}
	if record.ResponseAppealID == "" && (actionType == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionEscalate || actionType == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionResolve) {
		record.ResponseAppealID = firstNonEmpty(
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_parent_id"]),
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id"]),
		)
	}
	if record.LocalResponseAppealStatus == "" {
		record.LocalResponseAppealStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status"]))
	}
	if record.LocalResponseStatus == "" {
		record.LocalResponseStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status"]))
	}
	if record.LocalResponseAction == "" {
		record.LocalResponseAction = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action"]))
	}
	if record.LocalResponseTransitionID == "" {
		record.LocalResponseTransitionID = firstNonEmpty(
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_local_response_transition_id"]),
			strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id"]),
		)
	}
	if record.LocalRuling == "" {
		record.LocalRuling = SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling"]))
	}
	if actionType == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionEscalate || actionType == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionResolve {
		record.ReviewStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusForAction(actionType)
	} else if record.ReviewStatus == "" {
		record.ReviewStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusForAction(actionType)
	}
	if transition.PolicyReceipt != nil {
		record.PolicyReceiptID = strings.TrimSpace(transition.PolicyReceipt.ID)
		record.PolicyReceiptHash = strings.TrimSpace(transition.PolicyReceipt.ContentHash)
	}
	if transition.ExecutionSeal != nil {
		record.SealID = strings.TrimSpace(transition.ExecutionSeal.SealID)
	}
	if transition.TraceLink != nil {
		record.TraceLinkID = strings.TrimSpace(transition.TraceLink.ID)
	}
	return record, true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionTypeFromTransition(action string, meta map[string]string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionAcknowledge, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_disputed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionDispute, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_rehearing_requested":
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyEscalationMeta(meta) {
			return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionEscalate, true
		}
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruled":
		if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyEscalationMeta(meta) {
			return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionResolve, true
		}
	default:
		return "", false
	}
	return "", false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusForAction(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatus {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionAcknowledge:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusAcknowledged
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionDispute:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusDisputed
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionEscalate:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusEscalated
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionResolve:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusResolved
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyEscalationMeta(meta map[string]string) bool {
	return strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_escalated"]), "true")
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionAcknowledge:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_acknowledged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionDispute:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_disputed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionEscalate:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_escalated"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionResolve:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_resolved"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_counterparty_ruling_reviewed"
	}
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyActionFilter) bool {
	if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(item.CellID), strings.TrimSpace(filter.CellID)) {
		return false
	}
	if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(item.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
		return false
	}
	if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(item.IncidentID), strings.TrimSpace(filter.IncidentID)) {
		return false
	}
	if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseID), strings.TrimSpace(filter.ResponseID)) {
		return false
	}
	if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(item.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
		return false
	}
	if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(item.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
		return false
	}
	if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(item.DisputeID), strings.TrimSpace(filter.DisputeID)) {
		return false
	}
	if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(item.AppealID), strings.TrimSpace(filter.AppealID)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), strings.TrimSpace(filter.ResponseAppealID)) {
		return false
	}
	if filter.CounterpartySnapshotID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartySnapshotID), strings.TrimSpace(filter.CounterpartySnapshotID)) {
		return false
	}
	if filter.CounterpartyResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.CounterpartyResponseAppealID), strings.TrimSpace(filter.CounterpartyResponseAppealID)) {
		return false
	}
	if filter.AlignmentStatus != "" && item.AlignmentStatus != filter.AlignmentStatus {
		return false
	}
	if filter.ReviewStatus != "" && item.ReviewStatus != filter.ReviewStatus {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}
