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

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus
// tracks the lifecycle of one appeal over a ruled bilateral reconciliation
// challenge board.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "pending_board_review"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "ratified"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "overturned"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus = "enforcement_acknowledged"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType
// captures one evidence-bearing action over a challenge-board appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionAppealed                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType = "appeal"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRehearingRequested      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType = "rehearing_requested"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionReviewRecused           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType = "recuse_review"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionVoteRecorded            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType = "vote_recorded"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType = "ruled"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType = "acknowledge_enforcement"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest
// opens one governed appeal over a ruled reconciliation challenge board.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest struct {
	ActorDID                  string                                    `json:"actor_did,omitempty"`
	AppealingParty            SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	Summary                   string                                    `json:"summary,omitempty"`
	Description               string                                    `json:"description,omitempty"`
	EvidenceIDs               []string                                  `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                       `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                  `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                    `json:"reason,omitempty"`
	Metadata                  map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest
// requests one rehearing over a previously ruled reconciliation challenge
// appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest struct {
	ActorDID                  string                                    `json:"actor_did,omitempty"`
	AppealingParty            SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	Summary                   string                                    `json:"summary,omitempty"`
	Description               string                                    `json:"description,omitempty"`
	EvidenceIDs               []string                                  `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                       `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                  `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                    `json:"reason,omitempty"`
	Metadata                  map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest
// records one vote or final ruling over a challenge-board appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest struct {
	ActorDID          string                                                     `json:"actor_did,omitempty"`
	BoardParty        SecureCellFederationIncidentResponseParty                  `json:"board_party,omitempty"`
	Ruling            SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary     string                                                     `json:"ruling_summary,omitempty"`
	RulingDescription string                                                     `json:"ruling_description,omitempty"`
	EvidenceIDs       []string                                                   `json:"evidence_ids,omitempty"`
	Reason            string                                                     `json:"reason,omitempty"`
	Metadata          map[string]string                                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest
// records reciprocal acknowledgement that the final challenge-board appeal
// ruling will be enforced.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest struct {
	ActorDID           string                                    `json:"actor_did,omitempty"`
	AcknowledgingParty SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Summary            string                                    `json:"summary,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	EvidenceIDs        []string                                  `json:"evidence_ids,omitempty"`
	Reason             string                                    `json:"reason,omitempty"`
	Metadata           map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest
// records one challenge-appeal board reviewer recusal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest struct {
	ActorDID    string                                    `json:"actor_did,omitempty"`
	BoardParty  SecureCellFederationIncidentResponseParty `json:"board_party,omitempty"`
	Summary     string                                    `json:"summary,omitempty"`
	Description string                                    `json:"description,omitempty"`
	EvidenceIDs []string                                  `json:"evidence_ids,omitempty"`
	Reason      string                                    `json:"reason,omitempty"`
	Metadata    map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter
// narrows operator views across challenge-board appeals.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter struct {
	CellID                  string                                                                                  `json:"cell_id,omitempty"`
	OrganizationID          string                                                                                  `json:"organization_id,omitempty"`
	IncidentID              string                                                                                  `json:"incident_id,omitempty"`
	ResponseID              string                                                                                  `json:"response_id,omitempty"`
	DirectiveID             string                                                                                  `json:"directive_id,omitempty"`
	ExtensionID             string                                                                                  `json:"extension_id,omitempty"`
	DisputeID               string                                                                                  `json:"dispute_id,omitempty"`
	AppealID                string                                                                                  `json:"appeal_id,omitempty"`
	ComparisonKey           string                                                                                  `json:"comparison_key,omitempty"`
	ChallengeID             string                                                                                  `json:"challenge_id,omitempty"`
	ChallengeAppealID       string                                                                                  `json:"challenge_appeal_id,omitempty"`
	ParentChallengeAppealID string                                                                                  `json:"parent_challenge_appeal_id,omitempty"`
	Status                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"status,omitempty"`
	Since                   *time.Time                                                                              `json:"since,omitempty"`
	Until                   *time.Time                                                                              `json:"until,omitempty"`
	Limit                   int                                                                                     `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter
// narrows operator views across challenge-board appeal evidence records.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter struct {
	CellID            string                                                                                      `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                      `json:"organization_id,omitempty"`
	IncidentID        string                                                                                      `json:"incident_id,omitempty"`
	ResponseID        string                                                                                      `json:"response_id,omitempty"`
	DirectiveID       string                                                                                      `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                      `json:"extension_id,omitempty"`
	DisputeID         string                                                                                      `json:"dispute_id,omitempty"`
	AppealID          string                                                                                      `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                      `json:"comparison_key,omitempty"`
	ChallengeID       string                                                                                      `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                      `json:"challenge_appeal_id,omitempty"`
	Status            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus     `json:"status,omitempty"`
	Action            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType `json:"action,omitempty"`
	ActorDID          string                                                                                      `json:"actor_did,omitempty"`
	Since             *time.Time                                                                                  `json:"since,omitempty"`
	Until             *time.Time                                                                                  `json:"until,omitempty"`
	Limit             int                                                                                         `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord
// projects one appeal-board transition for operator and auditor use.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord struct {
	CellID                          string                                                                                          `json:"cell_id"`
	CellName                        string                                                                                          `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                `json:"cell_status"`
	Jurisdiction                    string                                                                                          `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                          `json:"organization_id"`
	SponsorOfRecord                 string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey                   string                                                                                          `json:"comparison_key"`
	IncidentID                      string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                          `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                          `json:"directive_id,omitempty"`
	DirectiveTitle                  string                                                                                          `json:"directive_title,omitempty"`
	ExtensionID                     string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                          `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                          `json:"challenge_id"`
	ChallengeAppealID               string                                                                                          `json:"challenge_appeal_id"`
	ParentChallengeAppealID         string                                                                                          `json:"parent_challenge_appeal_id,omitempty"`
	ChallengeAppealGeneration       int                                                                                             `json:"challenge_appeal_generation,omitempty"`
	ReconciliationStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	AttestationStatus               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	ChallengeStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status"`
	ChallengeRuling                 SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"challenge_ruling,omitempty"`
	ChallengeAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus         `json:"challenge_appeal_status"`
	Action                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType     `json:"action"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                       `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                       `json:"enforcement_acknowledgement_party,omitempty"`
	BoardReviewThreshold            int                                                                                             `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs       []string                                                                                        `json:"eligible_board_reviewer_dids,omitempty"`
	BoardRecusalCount               int                                                                                             `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                             `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                             `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                             `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                             `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                            `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                             `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                             `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"ruling,omitempty"`
	Summary                         string                                                                                          `json:"summary,omitempty"`
	Description                     string                                                                                          `json:"description,omitempty"`
	RulingSummary                   string                                                                                          `json:"ruling_summary,omitempty"`
	RulingDescription               string                                                                                          `json:"ruling_description,omitempty"`
	EnforcementSummary              string                                                                                          `json:"enforcement_summary,omitempty"`
	EnforcementDescription          string                                                                                          `json:"enforcement_description,omitempty"`
	EvidenceIDs                     []string                                                                                        `json:"evidence_ids,omitempty"`
	RecusalID                       string                                                                                          `json:"recusal_id,omitempty"`
	TransitionID                    string                                                                                          `json:"transition_id,omitempty"`
	PolicyReceiptID                 string                                                                                          `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash               string                                                                                          `json:"policy_receipt_hash,omitempty"`
	SealID                          string                                                                                          `json:"seal_id,omitempty"`
	TraceLinkID                     string                                                                                          `json:"trace_link_id,omitempty"`
	ActorDID                        string                                                                                          `json:"actor_did,omitempty"`
	Reason                          string                                                                                          `json:"reason,omitempty"`
	Metadata                        map[string]string                                                                               `json:"metadata,omitempty"`
	OccurredAt                      time.Time                                                                                       `json:"occurred_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary
// projects one governed appeal over a reconciliation challenge board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary struct {
	CellID                          string                                                                                          `json:"cell_id"`
	CellName                        string                                                                                          `json:"cell_name,omitempty"`
	Jurisdiction                    string                                                                                          `json:"jurisdiction,omitempty"`
	CellStatus                      SecureCellStatus                                                                                `json:"cell_status"`
	OrganizationID                  string                                                                                          `json:"organization_id"`
	SponsorOfRecord                 string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey                   string                                                                                          `json:"comparison_key"`
	IncidentID                      string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                          `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                          `json:"directive_id,omitempty"`
	DirectiveTitle                  string                                                                                          `json:"directive_title,omitempty"`
	ExtensionID                     string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                          `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                          `json:"challenge_id"`
	ChallengeAppealID               string                                                                                          `json:"challenge_appeal_id"`
	ParentChallengeAppealID         string                                                                                          `json:"parent_challenge_appeal_id,omitempty"`
	ChallengeAppealGeneration       int                                                                                             `json:"challenge_appeal_generation,omitempty"`
	ReconciliationStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	AttestationStatus               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	ChallengeStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status"`
	ChallengeRuling                 SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"challenge_ruling,omitempty"`
	ChallengeAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus         `json:"challenge_appeal_status"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                       `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                       `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                         string                                                                                          `json:"summary,omitempty"`
	Description                     string                                                                                          `json:"description,omitempty"`
	EvidenceIDs                     []string                                                                                        `json:"evidence_ids,omitempty"`
	BoardReviewThreshold            int                                                                                             `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs       []string                                                                                        `json:"eligible_board_reviewer_dids,omitempty"`
	BoardRecusalCount               int                                                                                             `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                             `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                             `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                             `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                             `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                            `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                             `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                             `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"ruling,omitempty"`
	RulingSummary                   string                                                                                          `json:"ruling_summary,omitempty"`
	RulingDescription               string                                                                                          `json:"ruling_description,omitempty"`
	RuledBy                         string                                                                                          `json:"ruled_by,omitempty"`
	RuledAt                         *time.Time                                                                                      `json:"ruled_at,omitempty"`
	EnforcementSummary              string                                                                                          `json:"enforcement_summary,omitempty"`
	EnforcementDescription          string                                                                                          `json:"enforcement_description,omitempty"`
	EnforcementAcknowledgedBy       string                                                                                          `json:"enforcement_acknowledged_by,omitempty"`
	EnforcementAcknowledgedAt       *time.Time                                                                                      `json:"enforcement_acknowledged_at,omitempty"`
	CreatedBy                       string                                                                                          `json:"created_by,omitempty"`
	CreatedAt                       time.Time                                                                                       `json:"created_at"`
	UpdatedAt                       time.Time                                                                                       `json:"updated_at"`
	ActionCount                     int                                                                                             `json:"action_count"`
	Metadata                        map[string]string                                                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter
// narrows operator views across challenge-appeal reviewer recusals.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter struct {
	CellID                  string     `json:"cell_id,omitempty"`
	OrganizationID          string     `json:"organization_id,omitempty"`
	IncidentID              string     `json:"incident_id,omitempty"`
	ResponseID              string     `json:"response_id,omitempty"`
	DirectiveID             string     `json:"directive_id,omitempty"`
	ExtensionID             string     `json:"extension_id,omitempty"`
	DisputeID               string     `json:"dispute_id,omitempty"`
	AppealID                string     `json:"appeal_id,omitempty"`
	ComparisonKey           string     `json:"comparison_key,omitempty"`
	ChallengeID             string     `json:"challenge_id,omitempty"`
	ChallengeAppealID       string     `json:"challenge_appeal_id,omitempty"`
	ParentChallengeAppealID string     `json:"parent_challenge_appeal_id,omitempty"`
	ActorDID                string     `json:"actor_did,omitempty"`
	Since                   *time.Time `json:"since,omitempty"`
	Until                   *time.Time `json:"until,omitempty"`
	Limit                   int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary
// projects one evidence-bearing reviewer recusal for a challenge-appeal board.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary struct {
	CellID                    string                                                                                  `json:"cell_id"`
	CellName                  string                                                                                  `json:"cell_name,omitempty"`
	Jurisdiction              string                                                                                  `json:"jurisdiction,omitempty"`
	CellStatus                SecureCellStatus                                                                        `json:"cell_status"`
	OrganizationID            string                                                                                  `json:"organization_id"`
	SponsorOfRecord           string                                                                                  `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                                                                  `json:"organization_name,omitempty"`
	ComparisonKey             string                                                                                  `json:"comparison_key"`
	IncidentID                string                                                                                  `json:"incident_id,omitempty"`
	ResponseID                string                                                                                  `json:"response_id,omitempty"`
	DirectiveID               string                                                                                  `json:"directive_id,omitempty"`
	DirectiveTitle            string                                                                                  `json:"directive_title,omitempty"`
	ExtensionID               string                                                                                  `json:"extension_id,omitempty"`
	DisputeID                 string                                                                                  `json:"dispute_id,omitempty"`
	AppealID                  string                                                                                  `json:"appeal_id,omitempty"`
	ChallengeID               string                                                                                  `json:"challenge_id"`
	ChallengeAppealID         string                                                                                  `json:"challenge_appeal_id"`
	ParentChallengeAppealID   string                                                                                  `json:"parent_challenge_appeal_id,omitempty"`
	ChallengeAppealGeneration int                                                                                     `json:"challenge_appeal_generation,omitempty"`
	ChallengeAppealStatus     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"challenge_appeal_status"`
	BoardParty                SecureCellFederationIncidentResponseParty                                               `json:"board_party,omitempty"`
	RecusalID                 string                                                                                  `json:"recusal_id"`
	ActorDID                  string                                                                                  `json:"actor_did"`
	Summary                   string                                                                                  `json:"summary,omitempty"`
	Description               string                                                                                  `json:"description,omitempty"`
	CreatedAt                 time.Time                                                                               `json:"created_at"`
	Metadata                  map[string]string                                                                       `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealState struct {
	summary SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary
	votes   map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling
}

func (s *Service) AppealFederationIncidentDirectiveExtensionAppealReconciliationChallenge(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	reconciliation, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	challenge := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallenge(run, comparisonKey)
	if challenge == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: no challenge board review exists for reconciliation %q", ErrFederationIncidentDirectiveNotFound, comparisonKey)
	}
	if challenge.ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified &&
		challenge.ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusOverturned {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge %q is not eligible for appeal", challenge.ChallengeID)
	}
	if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(run, challenge.ChallengeID); latest != nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge %q already has an appeal board review", challenge.ChallengeID)
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, reconciliation.ResponseID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	appealingParty, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationActorParty(run, *response, actorDID, req.AppealingParty)
	if err != nil {
		return nil, err
	}
	boardParty := secureCellFederationIncidentResponseOppositeParty(appealingParty)
	if boardParty == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: board party is required", ErrPolicyDenied)
	}
	eligibleReviewers := secureCellFederationIncidentDirectiveExtensionAppealEligibleReviewers(run, *response, boardParty, req.EligibleBoardReviewerDIDs)
	if len(eligibleReviewers) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: no eligible board reviewers are available for challenge %q", ErrPolicyDenied, challenge.ChallengeID)
	}
	boardThreshold := normalizeSecureCellThreshold(req.BoardReviewThreshold)

	now := time.Now().UTC()
	challengeAppealID := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealID(challenge.ChallengeID, actorDID, now, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealCount(run, challenge.ChallengeID))
	summaryText := firstNonEmpty(strings.TrimSpace(req.Summary), secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummaryText(*challenge))
	receipt, err := s.evaluateStage(ctx, run.request, "appeal_federation_incident_directive_extension_appeal_reconciliation_challenge", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                                     reconciliation.OrganizationID,
		"federation_incident_id":                                                                         reconciliation.IncidentID,
		"federation_incident_response_id":                                                                reconciliation.ResponseID,
		"federation_incident_directive_id":                                                               reconciliation.DirectiveID,
		"federation_incident_directive_extension_id":                                                     reconciliation.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                             reconciliation.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                              reconciliation.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                              reconciliation.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                     challenge.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                 string(challenge.ChallengeStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                 string(challenge.Ruling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":              challengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":          string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":        string(appealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":     string(boardParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":       string(appealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold": fmt.Sprintf("%d", boardThreshold),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":   strings.Join(eligibleReviewers, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":         summaryText,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":     strings.TrimSpace(req.Description),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":    strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appealed", challengeAppealID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appealed",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal",
		TargetDID:        challengeAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                                               reconciliation.OrganizationID,
			"federation_sponsor_of_record":                                                                             responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                                             reconciliation.OrganizationName,
			"federation_incident_id":                                                                                   reconciliation.IncidentID,
			"federation_incident_response_id":                                                                          reconciliation.ResponseID,
			"federation_incident_directive_id":                                                                         reconciliation.DirectiveID,
			"federation_incident_directive_title":                                                                      reconciliation.DirectiveTitle,
			"federation_incident_directive_extension_id":                                                               reconciliation.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                       reconciliation.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                        reconciliation.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                        reconciliation.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                                     string(reconciliation.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review":                                     string(reconciliation.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":                         string(reconciliation.AttestationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               challenge.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(challenge.ChallengeStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(challenge.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        challengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(appealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(boardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(appealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", boardThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":             strings.Join(eligibleReviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", len(eligibleReviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", len(eligibleReviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", boardThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": "false",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":                   summaryText,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":               strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":              strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RecuseFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReview
// records one evidence-bearing reviewer recusal for a pending challenge-appeal
// board review.
func (s *Service) RecuseFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReview(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecuseRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	challengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	if challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge appeal %q is not pending board review", challengeAppealID)
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, challengeAppeal.ResponseID)
	if err != nil {
		return nil, err
	}
	boardParty := secureCellNormalizedFederationIncidentResponseParty(req.BoardParty)
	if boardParty == "" {
		boardParty = challengeAppeal.BoardParty
	}
	if boardParty != challengeAppeal.BoardParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: challenge appeal %q must be recused by %q", ErrPolicyDenied, challengeAppealID, challengeAppeal.BoardParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, boardParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not permitted to recuse from challenge appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealHasRecusal(run, challengeAppealID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q already recused from challenge appeal %q", ErrFederationIncidentDirectiveImmutable, actorDID, challengeAppealID)
	}
	if !secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReviewerAllowed(run, *challengeAppeal, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not an eligible board reviewer for challenge appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealHasVote(run, challengeAppealID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q already voted on challenge appeal %q", ErrFederationIncidentDirectiveImmutable, actorDID, challengeAppealID)
	}
	summary := firstNonEmpty(strings.TrimSpace(req.Summary), secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary(*challengeAppeal))
	receipt, err := s.evaluateStage(ctx, run.request, "recuse_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_review", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                            challengeAppeal.OrganizationID,
		"federation_incident_id":                                                                challengeAppeal.IncidentID,
		"federation_incident_response_id":                                                       challengeAppeal.ResponseID,
		"federation_incident_directive_id":                                                      challengeAppeal.DirectiveID,
		"federation_incident_directive_extension_id":                                            challengeAppeal.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                    challengeAppeal.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                     challengeAppeal.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                     challengeAppeal.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":            challengeAppeal.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":        string(challengeAppeal.ChallengeStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":        string(challengeAppeal.ChallengeRuling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":     challengeAppeal.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status": string(challengeAppeal.ChallengeAppealStatus),
		"transition_reason": firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w", ErrPolicyDenied)
	}

	recusalID := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalID(challengeAppeal.ChallengeAppealID, actorDID, challengeAppeal.BoardRecusalCount)
	updatedReviewers := append([]string(nil), challengeAppeal.EligibleBoardReviewerDIDs...)
	if len(updatedReviewers) > 0 {
		filtered := make([]string, 0, len(updatedReviewers))
		for _, reviewer := range updatedReviewers {
			if !strings.EqualFold(strings.TrimSpace(reviewer), actorDID) {
				filtered = append(filtered, reviewer)
			}
		}
		updatedReviewers = uniqueTrimmedStrings(filtered)
	}
	committeeMemberCount := len(updatedReviewers)
	if committeeMemberCount == 0 {
		committeeMemberCount = max(challengeAppeal.BoardCommitteeMemberCount-1, challengeAppeal.BoardRecordedVoteCount)
	}
	bestVoteCount := challengeAppeal.RatifyVoteCount
	if challengeAppeal.OverturnVoteCount > bestVoteCount {
		bestVoteCount = challengeAppeal.OverturnVoteCount
	}
	missingQuorumCount := challengeAppeal.BoardReviewThreshold - bestVoteCount
	if missingQuorumCount < 0 {
		missingQuorumCount = 0
	}
	outstandingVotes := committeeMemberCount - challengeAppeal.BoardRecordedVoteCount
	if outstandingVotes < 0 {
		outstandingVotes = 0
	}
	thresholdSatisfied := bestVoteCount >= challengeAppeal.BoardReviewThreshold

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_review_recused", recusalID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_review_recused",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal",
		TargetDID:        challengeAppeal.ChallengeAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                                               challengeAppeal.OrganizationID,
			"federation_sponsor_of_record":                                                                             responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                                             challengeAppeal.OrganizationName,
			"federation_incident_id":                                                                                   challengeAppeal.IncidentID,
			"federation_incident_response_id":                                                                          challengeAppeal.ResponseID,
			"federation_incident_directive_id":                                                                         challengeAppeal.DirectiveID,
			"federation_incident_directive_title":                                                                      challengeAppeal.DirectiveTitle,
			"federation_incident_directive_extension_id":                                                               challengeAppeal.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                       challengeAppeal.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                        challengeAppeal.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                        challengeAppeal.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                                     string(challengeAppeal.ReconciliationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_review":                                     string(challengeAppeal.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":                         string(challengeAppeal.AttestationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               challengeAppeal.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(challengeAppeal.ChallengeStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(challengeAppeal.ChallengeRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        challengeAppeal.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id":                 challengeAppeal.ParentChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation":                fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealGeneration(*challengeAppeal)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(challengeAppeal.ChallengeAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(challengeAppeal.AppealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(challengeAppeal.BoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(challengeAppeal.EnforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_id":                recusalID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recused_actor":             actorDID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", challengeAppeal.BoardReviewThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":             strings.Join(updatedReviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count":       fmt.Sprintf("%d", challengeAppeal.BoardRecusalCount+1),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", committeeMemberCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", challengeAppeal.BoardRecordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", outstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", missingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", challengeAppeal.RatifyVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", challengeAppeal.OverturnVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":                    string(challengeAppeal.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":                   challengeAppeal.Summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":               challengeAppeal.Description,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":              strings.Join(challengeAppeal.EvidenceIDs, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_summary":           summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_description":       strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_evidence_ids":      strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal
// opens one governed rehearing over a previously ruled reconciliation
// challenge appeal.
func (s *Service) RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	challengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	if challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified &&
		challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned &&
		challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: challenge appeal %q is not eligible for rehearing", ErrFederationIncidentDirectiveImmutable, challengeAppealID)
	}
	if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(run, challengeAppeal.ChallengeID); latest == nil || !strings.EqualFold(strings.TrimSpace(latest.ChallengeAppealID), strings.TrimSpace(challengeAppealID)) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: challenge appeal %q is not the latest appeal for challenge %q", ErrFederationIncidentDirectiveImmutable, challengeAppealID, challengeAppeal.ChallengeID)
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, challengeAppeal.ResponseID)
	if err != nil {
		return nil, err
	}
	appealingParty := secureCellNormalizedFederationIncidentResponseParty(req.AppealingParty)
	if appealingParty == "" {
		if challengeAppeal.EnforcementAcknowledgementParty != "" {
			appealingParty = challengeAppeal.EnforcementAcknowledgementParty
		} else {
			appealingParty = challengeAppeal.AppealingParty
		}
	}
	if appealingParty != SecureCellFederationIncidentResponsePartyLocalOrg && appealingParty != SecureCellFederationIncidentResponsePartyCounterpartyOrg {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: invalid rehearing party %q", ErrPolicyDenied, appealingParty)
	}
	boardParty := secureCellFederationIncidentResponseOppositeParty(appealingParty)
	if boardParty == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: board party is required", ErrPolicyDenied)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, appealingParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not permitted to request rehearing for challenge appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	eligibleReviewers := secureCellFederationIncidentDirectiveExtensionAppealEligibleReviewers(run, *response, boardParty, req.EligibleBoardReviewerDIDs)
	if len(eligibleReviewers) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: no eligible board reviewers are available for challenge appeal %q", ErrPolicyDenied, challengeAppealID)
	}
	summary := firstNonEmpty(strings.TrimSpace(req.Summary), secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDefaultRehearingSummary(*challengeAppeal))
	now := time.Now().UTC()
	rehearingID := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealID(challengeAppeal.ChallengeID, actorDID, now, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealCount(run, challengeAppeal.ChallengeID))
	rehearingGeneration := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealGeneration(*challengeAppeal) + 1
	receipt, err := s.evaluateStage(ctx, run.request, "rehear_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                                     challengeAppeal.OrganizationID,
		"federation_incident_id":                                                                         challengeAppeal.IncidentID,
		"federation_incident_response_id":                                                                challengeAppeal.ResponseID,
		"federation_incident_directive_id":                                                               challengeAppeal.DirectiveID,
		"federation_incident_directive_extension_id":                                                     challengeAppeal.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                             challengeAppeal.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                              challengeAppeal.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                              challengeAppeal.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                     challengeAppeal.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                 string(challengeAppeal.ChallengeStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                 string(challengeAppeal.ChallengeRuling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":              rehearingID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id":       challengeAppeal.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation":      fmt.Sprintf("%d", rehearingGeneration),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":          string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":        string(appealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":     string(boardParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":       string(appealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold": fmt.Sprintf("%d", normalizeSecureCellThreshold(req.BoardReviewThreshold)),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":   strings.Join(eligibleReviewers, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":         summary,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":     strings.TrimSpace(req.Description),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":    strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason": firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_rehearing_requested", rehearingID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_rehearing_requested",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal",
		TargetDID:        rehearingID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                                               challengeAppeal.OrganizationID,
			"federation_sponsor_of_record":                                                                             responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                                             challengeAppeal.OrganizationName,
			"federation_incident_id":                                                                                   challengeAppeal.IncidentID,
			"federation_incident_response_id":                                                                          challengeAppeal.ResponseID,
			"federation_incident_directive_id":                                                                         challengeAppeal.DirectiveID,
			"federation_incident_directive_title":                                                                      challengeAppeal.DirectiveTitle,
			"federation_incident_directive_extension_id":                                                               challengeAppeal.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                       challengeAppeal.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                        challengeAppeal.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                        challengeAppeal.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                                     string(challengeAppeal.ReconciliationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_review":                                     string(challengeAppeal.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":                         string(challengeAppeal.AttestationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               challengeAppeal.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(challengeAppeal.ChallengeStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(challengeAppeal.ChallengeRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        rehearingID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id":                 challengeAppeal.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation":                fmt.Sprintf("%d", rehearingGeneration),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(appealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(boardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(appealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", normalizeSecureCellThreshold(req.BoardReviewThreshold)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":             strings.Join(eligibleReviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count":       "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", len(eligibleReviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", len(eligibleReviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", normalizeSecureCellThreshold(req.BoardReviewThreshold)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": "false",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":                   summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":               strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":              strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) RuleFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRulingRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	challengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	if challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: challenge appeal %q is not awaiting board review", challengeAppealID)
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, challengeAppeal.ResponseID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	boardParty := secureCellNormalizedFederationIncidentResponseParty(req.BoardParty)
	if boardParty == "" {
		boardParty = challengeAppeal.BoardParty
	}
	if boardParty != challengeAppeal.BoardParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: invalid board party %q", ErrPolicyDenied, boardParty)
	}
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, boardParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not permitted to rule on appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	if len(challengeAppeal.EligibleBoardReviewerDIDs) > 0 && !secureCellStringSliceContains(challengeAppeal.EligibleBoardReviewerDIDs, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not an eligible board reviewer for appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealHasVote(run, challengeAppeal.ChallengeAppealID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: actor %q already voted on appeal %q", actorDID, challengeAppealID)
	}
	ruling := secureCellNormalizedFederationIncidentDirectiveExtensionAppealRuling(req.Ruling)
	if ruling == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: ruling is required")
	}

	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealVoteCounts(run, challengeAppeal.ChallengeAppealID)
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		ratifyVotes++
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		overturnVotes++
	}
	recordedVoteCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealVoteCount(run, challengeAppeal.ChallengeAppealID) + 1
	memberCount := len(challengeAppeal.EligibleBoardReviewerDIDs)
	if memberCount == 0 {
		memberCount = recordedVoteCount
	}
	bestVoteCount := ratifyVotes
	if overturnVotes > bestVoteCount {
		bestVoteCount = overturnVotes
	}
	missingQuorumCount := challengeAppeal.BoardReviewThreshold - bestVoteCount
	if missingQuorumCount < 0 {
		missingQuorumCount = 0
	}
	outstandingVotes := memberCount - recordedVoteCount
	if outstandingVotes < 0 {
		outstandingVotes = 0
	}
	thresholdSatisfied := bestVoteCount >= challengeAppeal.BoardReviewThreshold
	appealStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview
	action := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionVoteRecorded
	if thresholdSatisfied {
		appealStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusForRuling(ruling)
		action = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled
	}

	receipt, err := s.evaluateStage(ctx, run.request, "rule_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                                               challengeAppeal.OrganizationID,
		"federation_incident_id":                                                                                   challengeAppeal.IncidentID,
		"federation_incident_response_id":                                                                          challengeAppeal.ResponseID,
		"federation_incident_directive_id":                                                                         challengeAppeal.DirectiveID,
		"federation_incident_directive_extension_id":                                                               challengeAppeal.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                                       challengeAppeal.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                                        challengeAppeal.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                                        challengeAppeal.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               challengeAppeal.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(challengeAppeal.ChallengeStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(challengeAppeal.ChallengeRuling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        challengeAppeal.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(appealStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(challengeAppeal.AppealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(challengeAppeal.BoardParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(challengeAppeal.EnforcementAcknowledgementParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", challengeAppeal.BoardReviewThreshold),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":             strings.Join(challengeAppeal.EligibleBoardReviewerDIDs, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", recordedVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", outstandingVotes),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", missingQuorumCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", ratifyVotes),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", overturnVotes),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":                    string(ruling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_summary":            strings.TrimSpace(req.RulingSummary),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_description":        strings.TrimSpace(req.RulingDescription),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_evidence_ids":       strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w", ErrPolicyDenied)
	}

	transitionSuffix := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealTransitionSuffix(action)
	transition := SecureCellTransition{
		ID:               transitionID(run.request, transitionSuffix, challengeAppeal.ChallengeAppealID),
		Action:           "secure_cell." + transitionSuffix,
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal",
		TargetDID:        challengeAppeal.ChallengeAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                                               challengeAppeal.OrganizationID,
			"federation_sponsor_of_record":                                                                             responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                                             challengeAppeal.OrganizationName,
			"federation_incident_id":                                                                                   challengeAppeal.IncidentID,
			"federation_incident_response_id":                                                                          challengeAppeal.ResponseID,
			"federation_incident_directive_id":                                                                         challengeAppeal.DirectiveID,
			"federation_incident_directive_title":                                                                      challengeAppeal.DirectiveTitle,
			"federation_incident_directive_extension_id":                                                               challengeAppeal.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                       challengeAppeal.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                        challengeAppeal.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                        challengeAppeal.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                                     string(challengeAppeal.ReconciliationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_review":                                     string(challengeAppeal.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":                         string(challengeAppeal.AttestationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               challengeAppeal.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(challengeAppeal.ChallengeStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(challengeAppeal.ChallengeRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        challengeAppeal.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(appealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(challengeAppeal.AppealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(challengeAppeal.BoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(challengeAppeal.EnforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", challengeAppeal.BoardReviewThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":             strings.Join(challengeAppeal.EligibleBoardReviewerDIDs, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", memberCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", recordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", outstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", missingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", ratifyVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", overturnVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":                    string(ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_summary":            strings.TrimSpace(req.RulingSummary),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_description":        strings.TrimSpace(req.RulingDescription),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_evidence_ids":       strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":                   challengeAppeal.Summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":               challengeAppeal.Description,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":              strings.Join(challengeAppeal.EvidenceIDs, ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealEnforcement(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	challengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	if challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified &&
		challengeAppeal.ChallengeAppealStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: appeal %q is not awaiting enforcement acknowledgement", challengeAppealID)
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, challengeAppeal.ResponseID)
	if err != nil {
		return nil, err
	}
	ackParty := secureCellNormalizedFederationIncidentResponseParty(req.AcknowledgingParty)
	if ackParty == "" {
		ackParty = challengeAppeal.EnforcementAcknowledgementParty
	}
	if ackParty != challengeAppeal.EnforcementAcknowledgementParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: appeal %q must be acknowledged by %q", ErrPolicyDenied, challengeAppealID, challengeAppeal.EnforcementAcknowledgementParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, ackParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: actor %q is not permitted to acknowledge appeal %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}
	summary := firstNonEmpty(strings.TrimSpace(req.Summary), secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealEnforcementSummary(*challengeAppeal))
	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                            challengeAppeal.OrganizationID,
		"federation_incident_id":                                                                challengeAppeal.IncidentID,
		"federation_incident_response_id":                                                       challengeAppeal.ResponseID,
		"federation_incident_directive_id":                                                      challengeAppeal.DirectiveID,
		"federation_incident_directive_extension_id":                                            challengeAppeal.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                    challengeAppeal.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                     challengeAppeal.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                     challengeAppeal.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":            challengeAppeal.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":        string(challengeAppeal.ChallengeStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":        string(challengeAppeal.ChallengeRuling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":     challengeAppeal.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status": string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling": string(challengeAppeal.Ruling),
		"transition_reason": firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged", challengeAppeal.ChallengeAppealID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal",
		TargetDID:        challengeAppeal.ChallengeAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                                               challengeAppeal.OrganizationID,
			"federation_sponsor_of_record":                                                                             responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                                             challengeAppeal.OrganizationName,
			"federation_incident_id":                                                                                   challengeAppeal.IncidentID,
			"federation_incident_response_id":                                                                          challengeAppeal.ResponseID,
			"federation_incident_directive_id":                                                                         challengeAppeal.DirectiveID,
			"federation_incident_directive_title":                                                                      challengeAppeal.DirectiveTitle,
			"federation_incident_directive_extension_id":                                                               challengeAppeal.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                                       challengeAppeal.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                                        challengeAppeal.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                                        challengeAppeal.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                                     string(challengeAppeal.ReconciliationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_review":                                     string(challengeAppeal.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":                         string(challengeAppeal.AttestationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               challengeAppeal.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(challengeAppeal.ChallengeStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(challengeAppeal.ChallengeRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        challengeAppeal.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(challengeAppeal.AppealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(challengeAppeal.BoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(challengeAppeal.EnforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           fmt.Sprintf("%d", challengeAppeal.BoardReviewThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members":             strings.Join(challengeAppeal.EligibleBoardReviewerDIDs, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", challengeAppeal.BoardCommitteeMemberCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", challengeAppeal.BoardRecordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", challengeAppeal.BoardOutstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", challengeAppeal.BoardMissingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", challengeAppeal.BoardThresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", challengeAppeal.RatifyVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", challengeAppeal.OverturnVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":                    string(challengeAppeal.Ruling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary":                   challengeAppeal.Summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description":               challengeAppeal.Description,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids":              strings.Join(challengeAppeal.EvidenceIDs, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_summary":       summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_description":   strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_evidence_ids":  strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ChallengeAppealID < items[j].ChallengeAppealID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter(record, filter) {
				continue
			}
			items = append(items, record)
		}
	}
	reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(items)
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusals(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
			if !ok || record.Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionReviewRecused {
				continue
			}
			recusal := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary{
				CellID:                    record.CellID,
				CellName:                  record.CellName,
				Jurisdiction:              record.Jurisdiction,
				CellStatus:                record.CellStatus,
				OrganizationID:            record.OrganizationID,
				SponsorOfRecord:           record.SponsorOfRecord,
				OrganizationName:          record.OrganizationName,
				ComparisonKey:             record.ComparisonKey,
				IncidentID:                record.IncidentID,
				ResponseID:                record.ResponseID,
				DirectiveID:               record.DirectiveID,
				DirectiveTitle:            record.DirectiveTitle,
				ExtensionID:               record.ExtensionID,
				DisputeID:                 record.DisputeID,
				AppealID:                  record.AppealID,
				ChallengeID:               record.ChallengeID,
				ChallengeAppealID:         record.ChallengeAppealID,
				ParentChallengeAppealID:   record.ParentChallengeAppealID,
				ChallengeAppealGeneration: max(record.ChallengeAppealGeneration, 1),
				ChallengeAppealStatus:     record.ChallengeAppealStatus,
				BoardParty:                record.BoardParty,
				RecusalID:                 record.RecusalID,
				ActorDID:                  record.ActorDID,
				Summary:                   firstNonEmpty(record.Summary, strings.TrimSpace(record.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_summary"])),
				Description:               firstNonEmpty(record.Description, strings.TrimSpace(record.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_description"])),
				CreatedAt:                 record.OccurredAt,
				Metadata:                  cloneStringMap(record.Metadata),
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter(recusal, filter) {
				continue
			}
			items = append(items, recusal)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].RecusalID < items[j].RecusalID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealID(challengeID string, actorDID string, createdAt time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(challengeID), strings.TrimSpace(actorDID), createdAt.UTC().Format(time.RFC3339Nano), ordinal+1)
	return fmt.Sprintf("%x-appeal-reconciliation-challenge-appeal-%x", sha256.Sum256([]byte(strings.TrimSpace(challengeID))), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalID(challengeAppealID string, actorDID string, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%d", strings.TrimSpace(challengeAppealID), strings.TrimSpace(actorDID), ordinal+1)
	return fmt.Sprintf("%x-appeal-reconciliation-challenge-appeal-recusal-%x", sha256.Sum256([]byte(strings.TrimSpace(challengeAppealID))), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummaryText(challenge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary) string {
	switch challenge.ChallengeStatus {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified:
		return "appeal ratified reconciliation challenge board ruling"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusOverturned:
		return "appeal overturned reconciliation challenge board ruling"
	default:
		return "appeal reconciliation challenge board ruling"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) string {
	if strings.TrimSpace(appeal.ParentChallengeAppealID) != "" {
		return "recuse from reconciliation challenge appeal rehearing board review"
	}
	return "recuse from reconciliation challenge appeal board review"
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealDefaultRehearingSummary(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) string {
	switch secureCellNormalizedFederationIncidentDirectiveExtensionAppealRuling(appeal.Ruling) {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return "request rehearing of overturned reconciliation challenge appeal ruling"
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return "request rehearing of ratified reconciliation challenge appeal ruling"
	default:
		return "request rehearing of reconciliation challenge appeal ruling"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealEnforcementSummary(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) string {
	switch appeal.ChallengeAppealStatus {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified:
		return "acknowledge enforcement of ratified reconciliation challenge appeal ruling"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned:
		return "acknowledge enforcement of overturned reconciliation challenge appeal ruling"
	default:
		return "acknowledge reconciliation challenge appeal ruling"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealGeneration(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) int {
	if appeal.ChallengeAppealGeneration > 0 {
		return appeal.ChallengeAppealGeneration
	}
	return 1
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusForRuling(ruling SecureCellFederationIncidentDirectiveExtensionAppealRuling) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus {
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appealed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionAppealed, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_rehearing_requested":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRehearingRequested, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_review_recused":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionReviewRecused, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_vote_recorded":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionVoteRecorded, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruled":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionAppealed:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appealed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRehearingRequested:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_rehearing_requested"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionReviewRecused:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_review_recused"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionVoteRecorded:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_vote_recorded"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruled"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_acknowledged"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_updated"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord{
		CellID:                          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                      safeSecureCellStatus(run),
		Jurisdiction:                    safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                  strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:                 strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:                strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:                   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:                      strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                      strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:                     strings.TrimSpace(meta["federation_incident_directive_id"]),
		DirectiveTitle:                  strings.TrimSpace(meta["federation_incident_directive_title"]),
		ExtensionID:                     strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                       strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                        strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		ChallengeID:                     strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ChallengeAppealID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
		ParentChallengeAppealID:         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id"]),
		ChallengeAppealGeneration:       secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation"),
		ReconciliationStatus:            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_status"])),
		ReviewStatus:                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review"])),
		AttestationStatus:               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_attestation_status"])),
		ChallengeStatus:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_status"])),
		ChallengeRuling:                 SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_ruling"])),
		ChallengeAppealStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])),
		Action:                          actionType,
		AppealingParty:                  SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party"])),
		BoardParty:                      SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party"])),
		EnforcementAcknowledgementParty: SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party"])),
		BoardReviewThreshold:            secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold"),
		EligibleBoardReviewerDIDs:       uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_members"]), ",")),
		BoardRecusalCount:               secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count"),
		BoardCommitteeMemberCount:       secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members"),
		BoardRecordedVoteCount:          secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes"),
		BoardOutstandingVotes:           secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes"),
		BoardMissingQuorumCount:         secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum"),
		BoardThresholdSatisfied:         secureCellMetadataBool(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied"),
		RatifyVoteCount:                 secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count"),
		OverturnVoteCount:               secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count"),
		Ruling:                          SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling"])),
		Summary:                         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_summary"]),
		Description:                     strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_description"]),
		RulingSummary:                   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_summary"]),
		RulingDescription:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_description"]),
		EnforcementSummary:              strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_summary"]),
		EnforcementDescription:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_description"]),
		EvidenceIDs:                     uniqueTrimmedStrings(strings.Split(firstNonEmpty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_evidence_ids"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_enforcement_evidence_ids"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling_evidence_ids"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_evidence_ids"])), ",")),
		RecusalID:                       strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_recusal_id"]),
		TransitionID:                    strings.TrimSpace(transition.ID),
		ActorDID:                        strings.TrimSpace(transition.Actor),
		Reason:                          firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Metadata:                        meta,
		OccurredAt:                      transition.OccurredAt.UTC(),
	}
	record.BoardCommitteeMemberCount = max(record.BoardCommitteeMemberCount, len(record.EligibleBoardReviewerDIDs))
	record.BoardRecordedVoteCount = max(record.BoardRecordedVoteCount, record.RatifyVoteCount+record.OverturnVoteCount)
	if record.BoardCommitteeMemberCount == 0 {
		record.BoardCommitteeMemberCount = record.BoardRecordedVoteCount
	}
	record.BoardOutstandingVotes = record.BoardCommitteeMemberCount - record.BoardRecordedVoteCount
	if record.BoardOutstandingVotes < 0 {
		record.BoardOutstandingVotes = 0
	}
	bestVoteCount := record.RatifyVoteCount
	if record.OverturnVoteCount > bestVoteCount {
		bestVoteCount = record.OverturnVoteCount
	}
	record.BoardMissingQuorumCount = record.BoardReviewThreshold - bestVoteCount
	if record.BoardMissingQuorumCount < 0 {
		record.BoardMissingQuorumCount = 0
	}
	record.BoardThresholdSatisfied = bestVoteCount >= record.BoardReviewThreshold
	switch record.Action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled:
		record.ChallengeAppealStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusForRuling(record.Ruling)
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged:
		record.ChallengeAppealStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run *secureCellRun) []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary {
	if run == nil || run.result == nil {
		return nil
	}
	records := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord, 0)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
		if !ok {
			continue
		}
		records = append(records, record)
	}
	states := make(map[string]*secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealState)
	order := make([]string, 0)
	for _, record := range records {
		challengeAppealID := strings.TrimSpace(record.ChallengeAppealID)
		if challengeAppealID == "" {
			continue
		}
		state := states[challengeAppealID]
		if state == nil {
			state = &secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealState{
				summary: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary{
					CellID:                          record.CellID,
					CellName:                        record.CellName,
					Jurisdiction:                    record.Jurisdiction,
					CellStatus:                      record.CellStatus,
					OrganizationID:                  record.OrganizationID,
					SponsorOfRecord:                 record.SponsorOfRecord,
					OrganizationName:                record.OrganizationName,
					ComparisonKey:                   record.ComparisonKey,
					IncidentID:                      record.IncidentID,
					ResponseID:                      record.ResponseID,
					DirectiveID:                     record.DirectiveID,
					DirectiveTitle:                  record.DirectiveTitle,
					ExtensionID:                     record.ExtensionID,
					DisputeID:                       record.DisputeID,
					AppealID:                        record.AppealID,
					ChallengeID:                     record.ChallengeID,
					ChallengeAppealID:               challengeAppealID,
					ParentChallengeAppealID:         record.ParentChallengeAppealID,
					ChallengeAppealGeneration:       max(record.ChallengeAppealGeneration, 1),
					ReconciliationStatus:            record.ReconciliationStatus,
					ReviewStatus:                    record.ReviewStatus,
					AttestationStatus:               record.AttestationStatus,
					ChallengeStatus:                 record.ChallengeStatus,
					ChallengeRuling:                 record.ChallengeRuling,
					ChallengeAppealStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview,
					AppealingParty:                  record.AppealingParty,
					BoardParty:                      record.BoardParty,
					EnforcementAcknowledgementParty: record.EnforcementAcknowledgementParty,
					Summary:                         record.Summary,
					Description:                     record.Description,
					EvidenceIDs:                     append([]string(nil), record.EvidenceIDs...),
					BoardReviewThreshold:            normalizeSecureCellThreshold(record.BoardReviewThreshold),
					EligibleBoardReviewerDIDs:       append([]string(nil), record.EligibleBoardReviewerDIDs...),
					BoardRecusalCount:               record.BoardRecusalCount,
					CreatedBy:                       record.ActorDID,
					CreatedAt:                       record.OccurredAt,
					UpdatedAt:                       record.OccurredAt,
					Metadata:                        cloneStringMap(record.Metadata),
				},
				votes: make(map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling),
			}
			states[challengeAppealID] = state
			order = append(order, challengeAppealID)
		}
		state.summary.ReconciliationStatus = record.ReconciliationStatus
		state.summary.ReviewStatus = record.ReviewStatus
		state.summary.AttestationStatus = record.AttestationStatus
		state.summary.ChallengeStatus = record.ChallengeStatus
		state.summary.ChallengeRuling = record.ChallengeRuling
		if strings.TrimSpace(record.ParentChallengeAppealID) != "" {
			state.summary.ParentChallengeAppealID = record.ParentChallengeAppealID
		}
		if record.ChallengeAppealGeneration > 0 {
			state.summary.ChallengeAppealGeneration = record.ChallengeAppealGeneration
		}
		if reviewers := uniqueTrimmedStrings(record.EligibleBoardReviewerDIDs); len(reviewers) > 0 {
			state.summary.EligibleBoardReviewerDIDs = reviewers
		}
		if threshold := normalizeSecureCellThreshold(record.BoardReviewThreshold); threshold > 0 {
			state.summary.BoardReviewThreshold = threshold
		}
		if record.Summary != "" {
			state.summary.Summary = record.Summary
		}
		if record.Description != "" {
			state.summary.Description = record.Description
		}
		if len(record.EvidenceIDs) > 0 {
			state.summary.EvidenceIDs = append([]string(nil), record.EvidenceIDs...)
		}
		state.summary.Metadata = mergeStringMaps(state.summary.Metadata, record.Metadata)
		state.summary.ActionCount++
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionAppealed ||
			record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRehearingRequested {
			state.summary.ChallengeAppealStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview
		}
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionReviewRecused {
			state.summary.BoardRecusalCount = max(state.summary.BoardRecusalCount, record.BoardRecusalCount)
		}
		if record.Ruling != "" && strings.TrimSpace(record.ActorDID) != "" && record.Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged {
			state.votes[strings.TrimSpace(record.ActorDID)] = record.Ruling
		}
		ratifyVotes := 0
		overturnVotes := 0
		for _, vote := range state.votes {
			switch vote {
			case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
				ratifyVotes++
			case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
				overturnVotes++
			}
		}
		state.summary.RatifyVoteCount = ratifyVotes
		state.summary.OverturnVoteCount = overturnVotes
		state.summary.BoardRecordedVoteCount = len(state.votes)
		state.summary.BoardCommitteeMemberCount = len(state.summary.EligibleBoardReviewerDIDs)
		if state.summary.BoardCommitteeMemberCount == 0 {
			state.summary.BoardCommitteeMemberCount = state.summary.BoardRecordedVoteCount
		}
		state.summary.BoardOutstandingVotes = state.summary.BoardCommitteeMemberCount - state.summary.BoardRecordedVoteCount
		if state.summary.BoardOutstandingVotes < 0 {
			state.summary.BoardOutstandingVotes = 0
		}
		bestVoteCount := state.summary.RatifyVoteCount
		if state.summary.OverturnVoteCount > bestVoteCount {
			bestVoteCount = state.summary.OverturnVoteCount
		}
		state.summary.BoardMissingQuorumCount = state.summary.BoardReviewThreshold - bestVoteCount
		if state.summary.BoardMissingQuorumCount < 0 {
			state.summary.BoardMissingQuorumCount = 0
		}
		state.summary.BoardThresholdSatisfied = bestVoteCount >= state.summary.BoardReviewThreshold
		if state.summary.EnforcementAcknowledgedAt != nil {
			state.summary.ChallengeAppealStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged
		} else if state.summary.Ruling != "" && state.summary.BoardThresholdSatisfied && state.summary.ChallengeAppealStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview {
			state.summary.ChallengeAppealStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusForRuling(state.summary.Ruling)
		}
		state.summary.UpdatedAt = record.OccurredAt
		switch record.Action {
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled:
			state.summary.ChallengeAppealStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusForRuling(record.Ruling)
			state.summary.Ruling = record.Ruling
			state.summary.RulingSummary = record.RulingSummary
			state.summary.RulingDescription = record.RulingDescription
			state.summary.RuledBy = record.ActorDID
			ruledAt := record.OccurredAt.UTC()
			state.summary.RuledAt = &ruledAt
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionEnforcementAcknowledged:
			state.summary.ChallengeAppealStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusEnforcementAcknowledged
			state.summary.EnforcementSummary = record.EnforcementSummary
			state.summary.EnforcementDescription = record.EnforcementDescription
			state.summary.EnforcementAcknowledgedBy = record.ActorDID
			ackAt := record.OccurredAt.UTC()
			state.summary.EnforcementAcknowledgedAt = &ackAt
		}
		state.summary.Metadata = mergeStringMaps(state.summary.Metadata, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(state.summary.ChallengeAppealStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_parent_id":                 state.summary.ParentChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_generation":                fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealGeneration(state.summary)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recusal_count":       fmt.Sprintf("%d", state.summary.BoardRecusalCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   fmt.Sprintf("%d", state.summary.BoardCommitteeMemberCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      fmt.Sprintf("%d", state.summary.BoardRecordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   fmt.Sprintf("%d", state.summary.BoardOutstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      fmt.Sprintf("%d", state.summary.BoardMissingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": fmt.Sprintf("%t", state.summary.BoardThresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         fmt.Sprintf("%d", state.summary.RatifyVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       fmt.Sprintf("%d", state.summary.OverturnVoteCount),
		})
	}
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		state := states[order[i]]
		if state == nil {
			continue
		}
		items = append(items, state.summary)
	}
	return items
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal(run *secureCellRun, challengeID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary {
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		return nil
	}
	items := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run)
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeID), challengeID) {
			candidate := item
			return &candidate
		}
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run *secureCellRun, challengeAppealID string) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, error) {
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	if challengeAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: challenge appeal ID is required", ErrFederationIncidentDirectiveNotFound)
	}
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), challengeAppealID) {
			candidate := item
			return &candidate, nil
		}
	}
	return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal: %w: %q", ErrFederationIncidentDirectiveNotFound, challengeAppealID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionsForComparisonKey(run *secureCellRun, comparisonKey string) []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord {
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord, 0)
	comparisonKey = strings.TrimSpace(comparisonKey)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if comparisonKey != "" && !strings.EqualFold(strings.TrimSpace(record.ComparisonKey), comparisonKey) {
			continue
		}
		items = append(items, record)
	}
	reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(items)
	return items
}

func reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActions(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealCount(run *secureCellRun, challengeID string) int {
	count := 0
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(challengeID)) {
			count++
		}
	}
	return count
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealVoteCounts(run *secureCellRun, challengeAppealID string) (ratifyVotes, overturnVotes int) {
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
		if !ok || !strings.EqualFold(strings.TrimSpace(record.ChallengeAppealID), strings.TrimSpace(challengeAppealID)) {
			continue
		}
		switch record.Action {
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionVoteRecorded, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled:
			switch record.Ruling {
			case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
				ratifyVotes++
			case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
				overturnVotes++
			}
		}
	}
	return ratifyVotes, overturnVotes
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealVoteCount(run *secureCellRun, challengeAppealID string) int {
	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealVoteCounts(run, challengeAppealID)
	return ratifyVotes + overturnVotes
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusedReviewerDIDs(run *secureCellRun, challengeAppealID string) []string {
	items := make([]string, 0)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
		if !ok || record.Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionReviewRecused {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ChallengeAppealID), strings.TrimSpace(challengeAppealID)) {
			continue
		}
		if actor := strings.TrimSpace(record.ActorDID); actor != "" {
			items = append(items, actor)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealHasRecusal(run *secureCellRun, challengeAppealID string, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, candidate := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusedReviewerDIDs(run, challengeAppealID) {
		if strings.EqualFold(strings.TrimSpace(candidate), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealHasVote(run *secureCellRun, challengeAppealID string, actorDID string) bool {
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ChallengeAppealID), strings.TrimSpace(challengeAppealID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ActorDID), strings.TrimSpace(actorDID)) {
			continue
		}
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionVoteRecorded || record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRuled {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReviewerAllowed(run *secureCellRun, challengeAppeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, actorDID string) bool {
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealHasRecusal(run, challengeAppeal.ChallengeAppealID, actorDID) {
		return false
	}
	if len(challengeAppeal.EligibleBoardReviewerDIDs) == 0 {
		return true
	}
	return secureCellStringSliceContains(challengeAppeal.EligibleBoardReviewerDIDs, actorDID)
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter) bool {
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
	if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(item.ComparisonKey), strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ParentChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ParentChallengeAppealID), strings.TrimSpace(filter.ParentChallengeAppealID)) {
		return false
	}
	if filter.Status != "" && item.ChallengeAppealStatus != filter.Status {
		return false
	}
	if filter.Since != nil && item.UpdatedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && item.CreatedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealActionFilter) bool {
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
	if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(item.ComparisonKey), strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.Status != "" && item.ChallengeAppealStatus != filter.Status {
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

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalFilter) bool {
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
	if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(item.ComparisonKey), strings.TrimSpace(filter.ComparisonKey)) {
		return false
	}
	if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(filter.ChallengeID)) {
		return false
	}
	if filter.ChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(filter.ChallengeAppealID)) {
		return false
	}
	if filter.ParentChallengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ParentChallengeAppealID), strings.TrimSpace(filter.ParentChallengeAppealID)) {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	if filter.Since != nil && item.CreatedAt.Before(filter.Since.UTC()) {
		return false
	}
	if filter.Until != nil && item.CreatedAt.After(filter.Until.UTC()) {
		return false
	}
	return true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus) int {
	total := 0
	for _, item := range items {
		if item.ChallengeAppealStatus == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusalCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) int {
	total := 0
	for _, item := range items {
		total += item.BoardRecusalCount
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRehearingCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) int {
	total := 0
	for _, item := range items {
		if strings.TrimSpace(item.ParentChallengeAppealID) != "" {
			total++
		}
	}
	return total
}
