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

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus
// tracks one governed correction-board appeal over a bilateral alignment-response trail.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus = "pending_correction_board_review"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusUpheld                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus = "upheld"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusReversed                     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus = "reversed"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus = "enforcement_acknowledged"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType
// captures one evidence-bearing transition inside correction-board governance.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionAppealed                SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "appeal"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewDelegated         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "review_delegated"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRehearingRequested      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "rehearing_requested"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "recuse_review"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionVoteRecorded            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "vote_recorded"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled                   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "ruled"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType = "acknowledge_enforcement"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest
// opens one governed correction-board appeal over the latest bilateral alignment response.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest struct {
	ActorDID                            string                                    `json:"actor_did,omitempty"`
	AppealingParty                      SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	CorrectionBoardParty                SecureCellFederationIncidentResponseParty `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty     SecureCellFederationIncidentResponseParty `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                             string                                    `json:"summary,omitempty"`
	Description                         string                                    `json:"description,omitempty"`
	EvidenceIDs                         []string                                  `json:"evidence_ids,omitempty"`
	CorrectionBoardReviewThreshold      int                                       `json:"correction_board_review_threshold,omitempty"`
	EligibleCorrectionBoardReviewerDIDs []string                                  `json:"eligible_correction_board_reviewer_dids,omitempty"`
	Reason                              string                                    `json:"reason,omitempty"`
	Metadata                            map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest
// opens one governed rehearing over a previously ruled correction-board
// response appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest struct {
	ActorDID                            string                                    `json:"actor_did,omitempty"`
	AppealingParty                      SecureCellFederationIncidentResponseParty `json:"appealing_party,omitempty"`
	CorrectionBoardParty                SecureCellFederationIncidentResponseParty `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty     SecureCellFederationIncidentResponseParty `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                             string                                    `json:"summary,omitempty"`
	Description                         string                                    `json:"description,omitempty"`
	EvidenceIDs                         []string                                  `json:"evidence_ids,omitempty"`
	CorrectionBoardReviewThreshold      int                                       `json:"correction_board_review_threshold,omitempty"`
	EligibleCorrectionBoardReviewerDIDs []string                                  `json:"eligible_correction_board_reviewer_dids,omitempty"`
	Reason                              string                                    `json:"reason,omitempty"`
	Metadata                            map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest
// records one vote or final correction-board ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest struct {
	ActorDID             string                                                     `json:"actor_did,omitempty"`
	CorrectionBoardParty SecureCellFederationIncidentResponseParty                  `json:"correction_board_party,omitempty"`
	Ruling               SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary        string                                                     `json:"ruling_summary,omitempty"`
	RulingDescription    string                                                     `json:"ruling_description,omitempty"`
	EvidenceIDs          []string                                                   `json:"evidence_ids,omitempty"`
	Reason               string                                                     `json:"reason,omitempty"`
	Metadata             map[string]string                                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest
// records reciprocal acknowledgement that the correction-board ruling will be enforced.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest struct {
	ActorDID           string                                    `json:"actor_did,omitempty"`
	AcknowledgingParty SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Summary            string                                    `json:"summary,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	EvidenceIDs        []string                                  `json:"evidence_ids,omitempty"`
	Reason             string                                    `json:"reason,omitempty"`
	Metadata           map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest
// records one reviewer recusal for a pending correction-board response appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest struct {
	ActorDID             string                                    `json:"actor_did,omitempty"`
	CorrectionBoardParty SecureCellFederationIncidentResponseParty `json:"correction_board_party,omitempty"`
	Summary              string                                    `json:"summary,omitempty"`
	Description          string                                    `json:"description,omitempty"`
	EvidenceIDs          []string                                  `json:"evidence_ids,omitempty"`
	Reason               string                                    `json:"reason,omitempty"`
	Metadata             map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter
// narrows operator views across correction-board appeals.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter struct {
	CellID                 string                                                                                                         `json:"cell_id,omitempty"`
	OrganizationID         string                                                                                                         `json:"organization_id,omitempty"`
	IncidentID             string                                                                                                         `json:"incident_id,omitempty"`
	ResponseID             string                                                                                                         `json:"response_id,omitempty"`
	DirectiveID            string                                                                                                         `json:"directive_id,omitempty"`
	ExtensionID            string                                                                                                         `json:"extension_id,omitempty"`
	DisputeID              string                                                                                                         `json:"dispute_id,omitempty"`
	AppealID               string                                                                                                         `json:"appeal_id,omitempty"`
	ChallengeID            string                                                                                                         `json:"challenge_id,omitempty"`
	ChallengeAppealID      string                                                                                                         `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID       string                                                                                                         `json:"response_appeal_id,omitempty"`
	ParentResponseAppealID string                                                                                                         `json:"parent_response_appeal_id,omitempty"`
	ResponseStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus       `json:"response_status,omitempty"`
	Status                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus `json:"status,omitempty"`
	Limit                  int                                                                                                            `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter
// narrows operator views across correction-board action trails.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter struct {
	CellID                 string                                                                                                             `json:"cell_id,omitempty"`
	OrganizationID         string                                                                                                             `json:"organization_id,omitempty"`
	IncidentID             string                                                                                                             `json:"incident_id,omitempty"`
	ResponseID             string                                                                                                             `json:"response_id,omitempty"`
	DirectiveID            string                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID            string                                                                                                             `json:"extension_id,omitempty"`
	DisputeID              string                                                                                                             `json:"dispute_id,omitempty"`
	AppealID               string                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID            string                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID      string                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID       string                                                                                                             `json:"response_appeal_id,omitempty"`
	ParentResponseAppealID string                                                                                                             `json:"parent_response_appeal_id,omitempty"`
	ResponseStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus           `json:"response_status,omitempty"`
	Status                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus     `json:"status,omitempty"`
	Action                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType `json:"action,omitempty"`
	ActorDID               string                                                                                                             `json:"actor_did,omitempty"`
	Limit                  int                                                                                                                `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter
// narrows operator views across correction-board reviewer recusals.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter struct {
	CellID                 string     `json:"cell_id,omitempty"`
	OrganizationID         string     `json:"organization_id,omitempty"`
	IncidentID             string     `json:"incident_id,omitempty"`
	ResponseID             string     `json:"response_id,omitempty"`
	DirectiveID            string     `json:"directive_id,omitempty"`
	ExtensionID            string     `json:"extension_id,omitempty"`
	DisputeID              string     `json:"dispute_id,omitempty"`
	AppealID               string     `json:"appeal_id,omitempty"`
	ChallengeID            string     `json:"challenge_id,omitempty"`
	ChallengeAppealID      string     `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID       string     `json:"response_appeal_id,omitempty"`
	ParentResponseAppealID string     `json:"parent_response_appeal_id,omitempty"`
	ActorDID               string     `json:"actor_did,omitempty"`
	Since                  *time.Time `json:"since,omitempty"`
	Until                  *time.Time `json:"until,omitempty"`
	Limit                  int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary
// projects one evidence-bearing reviewer recusal for a correction-board
// response appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary struct {
	CellID                   string                                                                                                         `json:"cell_id"`
	CellName                 string                                                                                                         `json:"cell_name,omitempty"`
	CellStatus               SecureCellStatus                                                                                               `json:"cell_status"`
	Jurisdiction             string                                                                                                         `json:"jurisdiction,omitempty"`
	OrganizationID           string                                                                                                         `json:"organization_id"`
	SponsorOfRecord          string                                                                                                         `json:"sponsor_of_record,omitempty"`
	OrganizationName         string                                                                                                         `json:"organization_name,omitempty"`
	IncidentID               string                                                                                                         `json:"incident_id,omitempty"`
	ResponseID               string                                                                                                         `json:"response_id,omitempty"`
	DirectiveID              string                                                                                                         `json:"directive_id,omitempty"`
	ExtensionID              string                                                                                                         `json:"extension_id,omitempty"`
	DisputeID                string                                                                                                         `json:"dispute_id,omitempty"`
	AppealID                 string                                                                                                         `json:"appeal_id,omitempty"`
	ChallengeID              string                                                                                                         `json:"challenge_id,omitempty"`
	ChallengeAppealID        string                                                                                                         `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID         string                                                                                                         `json:"response_appeal_id"`
	ParentResponseAppealID   string                                                                                                         `json:"parent_response_appeal_id,omitempty"`
	ResponseAppealGeneration int                                                                                                            `json:"response_appeal_generation,omitempty"`
	ResponseStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus       `json:"response_status"`
	ResponseAppealStatus     SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus `json:"response_appeal_status"`
	CorrectionBoardParty     SecureCellFederationIncidentResponseParty                                                                      `json:"correction_board_party,omitempty"`
	RecusalID                string                                                                                                         `json:"recusal_id"`
	ActorDID                 string                                                                                                         `json:"actor_did"`
	Summary                  string                                                                                                         `json:"summary,omitempty"`
	Description              string                                                                                                         `json:"description,omitempty"`
	CreatedAt                time.Time                                                                                                      `json:"created_at"`
	Metadata                 map[string]string                                                                                              `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
// projects one governed correction-board appeal over a bilateral alignment response.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary struct {
	CellID                          string                                                                                                         `json:"cell_id"`
	CellName                        string                                                                                                         `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                               `json:"cell_status"`
	Jurisdiction                    string                                                                                                         `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                                         `json:"organization_id"`
	SponsorOfRecord                 string                                                                                                         `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                                         `json:"organization_name,omitempty"`
	IncidentID                      string                                                                                                         `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                                         `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                                         `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                                                         `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                                         `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                                         `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                                         `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                                         `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                string                                                                                                         `json:"response_appeal_id"`
	ParentResponseAppealID          string                                                                                                         `json:"parent_response_appeal_id,omitempty"`
	ResponseAppealGeneration        int                                                                                                            `json:"response_appeal_generation,omitempty"`
	ResponseStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus       `json:"response_status"`
	ResponseAction                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType   `json:"response_action"`
	ResponseTransitionID            string                                                                                                         `json:"response_transition_id,omitempty"`
	ResponseCounterpartyReference   string                                                                                                         `json:"response_counterparty_reference,omitempty"`
	ResponseCounterpartySnapshotID  string                                                                                                         `json:"response_counterparty_snapshot_id,omitempty"`
	Status                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus `json:"status"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                                      `json:"appealing_party,omitempty"`
	CorrectionBoardParty            SecureCellFederationIncidentResponseParty                                                                      `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                                      `json:"enforcement_acknowledgement_party,omitempty"`
	Summary                         string                                                                                                         `json:"summary,omitempty"`
	Description                     string                                                                                                         `json:"description,omitempty"`
	EvidenceIDs                     []string                                                                                                       `json:"evidence_ids,omitempty"`
	BoardReviewThreshold            int                                                                                                            `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs       []string                                                                                                       `json:"eligible_board_reviewer_dids,omitempty"`
	BoardDelegationCount            int                                                                                                            `json:"board_delegation_count,omitempty"`
	BoardRecusalCount               int                                                                                                            `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                                            `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                                            `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                                            `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                                            `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                                           `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                                            `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                                            `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                     `json:"ruling,omitempty"`
	RulingSummary                   string                                                                                                         `json:"ruling_summary,omitempty"`
	RulingDescription               string                                                                                                         `json:"ruling_description,omitempty"`
	RuledBy                         string                                                                                                         `json:"ruled_by,omitempty"`
	RuledAt                         *time.Time                                                                                                     `json:"ruled_at,omitempty"`
	EnforcementSummary              string                                                                                                         `json:"enforcement_summary,omitempty"`
	EnforcementDescription          string                                                                                                         `json:"enforcement_description,omitempty"`
	EnforcementAcknowledgedBy       string                                                                                                         `json:"enforcement_acknowledged_by,omitempty"`
	EnforcementAcknowledgedAt       *time.Time                                                                                                     `json:"enforcement_acknowledged_at,omitempty"`
	ActionCount                     int                                                                                                            `json:"action_count,omitempty"`
	CreatedBy                       string                                                                                                         `json:"created_by,omitempty"`
	CreatedAt                       time.Time                                                                                                      `json:"created_at"`
	UpdatedAt                       time.Time                                                                                                      `json:"updated_at"`
	Metadata                        map[string]string                                                                                              `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord
// projects one correction-board transition for operator and auditor use.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord struct {
	CellID                          string                                                                                                             `json:"cell_id"`
	CellName                        string                                                                                                             `json:"cell_name,omitempty"`
	CellStatus                      SecureCellStatus                                                                                                   `json:"cell_status"`
	Jurisdiction                    string                                                                                                             `json:"jurisdiction,omitempty"`
	OrganizationID                  string                                                                                                             `json:"organization_id"`
	SponsorOfRecord                 string                                                                                                             `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                                             `json:"organization_name,omitempty"`
	IncidentID                      string                                                                                                             `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                                             `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                                             `json:"directive_id,omitempty"`
	ExtensionID                     string                                                                                                             `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                                             `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                                             `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                                             `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                                             `json:"challenge_appeal_id,omitempty"`
	ResponseAppealID                string                                                                                                             `json:"response_appeal_id"`
	ParentResponseAppealID          string                                                                                                             `json:"parent_response_appeal_id,omitempty"`
	ResponseAppealGeneration        int                                                                                                                `json:"response_appeal_generation,omitempty"`
	ResponseStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus           `json:"response_status"`
	ResponseAction                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType       `json:"response_action"`
	ResponseTransitionID            string                                                                                                             `json:"response_transition_id,omitempty"`
	ResponseCounterpartyReference   string                                                                                                             `json:"response_counterparty_reference,omitempty"`
	ResponseCounterpartySnapshotID  string                                                                                                             `json:"response_counterparty_snapshot_id,omitempty"`
	Status                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus     `json:"status"`
	Action                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType `json:"action"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                                                          `json:"appealing_party,omitempty"`
	CorrectionBoardParty            SecureCellFederationIncidentResponseParty                                                                          `json:"correction_board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                                                          `json:"enforcement_acknowledgement_party,omitempty"`
	BoardReviewThreshold            int                                                                                                                `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs       []string                                                                                                           `json:"eligible_board_reviewer_dids,omitempty"`
	BoardDelegationCount            int                                                                                                                `json:"board_delegation_count,omitempty"`
	BoardRecusalCount               int                                                                                                                `json:"board_recusal_count,omitempty"`
	BoardCommitteeMemberCount       int                                                                                                                `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                                                `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                                                `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                                                `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                                               `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                                                `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                                                `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                                                         `json:"ruling,omitempty"`
	Summary                         string                                                                                                             `json:"summary,omitempty"`
	Description                     string                                                                                                             `json:"description,omitempty"`
	RulingSummary                   string                                                                                                             `json:"ruling_summary,omitempty"`
	RulingDescription               string                                                                                                             `json:"ruling_description,omitempty"`
	EnforcementSummary              string                                                                                                             `json:"enforcement_summary,omitempty"`
	EnforcementDescription          string                                                                                                             `json:"enforcement_description,omitempty"`
	EvidenceIDs                     []string                                                                                                           `json:"evidence_ids,omitempty"`
	DelegatedToDID                  string                                                                                                             `json:"delegated_to_did,omitempty"`
	RecusalID                       string                                                                                                             `json:"recusal_id,omitempty"`
	TransitionID                    string                                                                                                             `json:"transition_id,omitempty"`
	PolicyReceiptID                 string                                                                                                             `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash               string                                                                                                             `json:"policy_receipt_hash,omitempty"`
	SealID                          string                                                                                                             `json:"seal_id,omitempty"`
	TraceLinkID                     string                                                                                                             `json:"trace_link_id,omitempty"`
	ActorDID                        string                                                                                                             `json:"actor_did,omitempty"`
	Reason                          string                                                                                                             `json:"reason,omitempty"`
	Metadata                        map[string]string                                                                                                  `json:"metadata,omitempty"`
	OccurredAt                      time.Time                                                                                                          `json:"occurred_at"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealState struct {
	summary SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary
	votes   map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling
}

func (s *Service) AppealFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponse(ctx context.Context, cellID string, challengeAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	localChallengeAppeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealByID(run, challengeAppealID)
	if err != nil {
		return nil, err
	}
	latestResponse := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAction(run, challengeAppealID)
	if latestResponse == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: alignment response evidence is required before appeal for %q", challengeAppealID)
	}
	latestAppeal := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealForChallengeAppeal(run, challengeAppealID)
	if latestAppeal != nil && strings.EqualFold(strings.TrimSpace(latestAppeal.ResponseTransitionID), strings.TrimSpace(latestResponse.TransitionID)) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: response transition %q is already under correction-board appeal", latestResponse.TransitionID)
	}

	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is not permitted to appeal alignment response %q", ErrPolicyDenied, actorDID, challengeAppealID)
	}

	responseAppealID := secureCellNextFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealID(run, challengeAppealID)
	reviewers := uniqueTrimmedStrings(req.EligibleCorrectionBoardReviewerDIDs)
	if len(reviewers) == 0 {
		reviewers = []string{actorDID}
	}
	threshold := normalizeSecureCellThreshold(req.CorrectionBoardReviewThreshold)
	appealingParty := req.AppealingParty
	if appealingParty == "" {
		appealingParty = SecureCellFederationIncidentResponsePartyLocalOrg
	}
	correctionBoardParty := req.CorrectionBoardParty
	if correctionBoardParty == "" {
		correctionBoardParty = localChallengeAppeal.BoardParty
	}
	enforcementAcknowledgementParty := req.EnforcementAcknowledgementParty
	if enforcementAcknowledgementParty == "" {
		enforcementAcknowledgementParty = appealingParty
	}

	receipt, err := s.evaluateStage(ctx, run.request, "appeal_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response", lastReceiptHash(run.result), map[string]string{
		"federation_incident_id":                                                                                                              latestResponse.IncidentID,
		"federation_incident_response_id":                                                                                                     latestResponse.ResponseID,
		"federation_incident_directive_id":                                                                                                    latestResponse.DirectiveID,
		"federation_incident_directive_extension_id":                                                                                          latestResponse.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                                                                  latestResponse.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                                                                   latestResponse.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                                                          latestResponse.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                                   latestResponse.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                         responseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                            string(latestResponse.ResponseStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action":                            string(latestResponse.Action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id":                     latestResponse.TransitionID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealing_party":                   string(appealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party":            string(correctionBoardParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_acknowledgement_party": string(enforcementAcknowledgementParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold":        fmt.Sprintf("%d", threshold),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers":        strings.Join(reviewers, ","),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionAppealed), responseAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionAppealed),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal",
		TargetDID:        responseAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                        latestResponse.OrganizationID,
			"federation_sponsor_of_record":                                                      latestResponse.SponsorOfRecord,
			"federation_organization_name":                                                      latestResponse.OrganizationName,
			"federation_incident_id":                                                            latestResponse.IncidentID,
			"federation_incident_response_id":                                                   latestResponse.ResponseID,
			"federation_incident_directive_id":                                                  latestResponse.DirectiveID,
			"federation_incident_directive_extension_id":                                        latestResponse.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                latestResponse.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                 latestResponse.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        latestResponse.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": latestResponse.ChallengeAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                            responseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                               string(latestResponse.ResponseStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action":                               string(latestResponse.Action),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id":                        latestResponse.TransitionID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_reference":               latestResponse.CounterpartyReference,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_snapshot_id":             latestResponse.CounterpartySnapshotID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealing_party":                      string(appealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party":               string(correctionBoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_acknowledgement_party":    string(enforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_summary":                              strings.TrimSpace(req.Summary),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_description":                          strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_evidence_ids":                         strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_created_by":                           actorDID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_created_at":                           receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold":           fmt.Sprintf("%d", threshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers":           strings.Join(reviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_delegations":         "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", len(reviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", len(reviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", threshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": "false",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ratify_vote_count":                    "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_overturn_vote_count":                  "0",
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RecuseFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReview
// records one reviewer recusal for a pending correction-board response appeal.
func (s *Service) RecuseFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReview(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecuseRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, responseAppealID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: response appeal %q is not pending correction-board review", responseAppealID)
	}
	correctionBoardParty := firstNonEmptyResponseParty(req.CorrectionBoardParty, appeal.CorrectionBoardParty)
	if correctionBoardParty != appeal.CorrectionBoardParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: response appeal %q must be recused by %q", ErrPolicyDenied, responseAppealID, appeal.CorrectionBoardParty)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is not permitted to recuse from response appeal %q", ErrPolicyDenied, actorDID, responseAppealID)
	}
	if !secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReviewerAllowed(run, *appeal, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is not an eligible correction-board reviewer for response appeal %q", ErrPolicyDenied, actorDID, responseAppealID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasVote(run, responseAppealID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q already voted on response appeal %q", ErrFederationIncidentDirectiveImmutable, actorDID, responseAppealID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasRecusal(run, responseAppealID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q already recused from response appeal %q", ErrFederationIncidentDirectiveImmutable, actorDID, responseAppealID)
	}

	summary := firstNonEmpty(strings.TrimSpace(req.Summary), secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummaryText(*appeal))
	receipt, err := s.evaluateStage(ctx, run.request, "recuse_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_review", lastReceiptHash(run.result), map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":     responseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status": string(appeal.Status),
		"transition_reason": firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w", ErrPolicyDenied)
	}

	recusalID := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalID(responseAppealID, actorDID, appeal.BoardRecusalCount)
	updatedReviewers := append([]string(nil), appeal.EligibleBoardReviewerDIDs...)
	if len(updatedReviewers) > 0 {
		filtered := make([]string, 0, len(updatedReviewers))
		for _, reviewer := range updatedReviewers {
			if !strings.EqualFold(strings.TrimSpace(reviewer), actorDID) {
				filtered = append(filtered, reviewer)
			}
		}
		updatedReviewers = uniqueTrimmedStrings(filtered)
	}
	committeeMembers := len(updatedReviewers)
	if committeeMembers == 0 {
		committeeMembers = max(appeal.BoardCommitteeMemberCount-1, appeal.BoardRecordedVoteCount)
	}
	bestVoteCount := appeal.RatifyVoteCount
	if appeal.OverturnVoteCount > bestVoteCount {
		bestVoteCount = appeal.OverturnVoteCount
	}
	outstandingVotes := committeeMembers - appeal.BoardRecordedVoteCount
	if outstandingVotes < 0 {
		outstandingVotes = 0
	}
	missingQuorum := appeal.BoardReviewThreshold - bestVoteCount
	if missingQuorum < 0 {
		missingQuorum = 0
	}
	thresholdSatisfied := bestVoteCount >= appeal.BoardReviewThreshold

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused), recusalID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal",
		TargetDID:        responseAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealMetadata(appeal, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(appeal.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_id":                    recusalID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recused_actor":                 actorDID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party":               string(correctionBoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers":           strings.Join(updatedReviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recusals":            fmt.Sprintf("%d", appeal.BoardRecusalCount+1),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", committeeMembers),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      fmt.Sprintf("%d", appeal.BoardRecordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", outstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", missingQuorum),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_summary":               summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_description":           strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_evidence_ids":          strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		})),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal
// opens one governed rehearing over a previously ruled correction-board
// response appeal.
func (s *Service) RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, responseAppealID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusUpheld &&
		appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusReversed &&
		appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: response appeal %q is not eligible for rehearing", ErrFederationIncidentDirectiveImmutable, responseAppealID)
	}
	if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealForChallengeAppeal(run, appeal.ChallengeAppealID); latest == nil || !strings.EqualFold(strings.TrimSpace(latest.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: response appeal %q is not the latest appeal for challenge appeal %q", ErrFederationIncidentDirectiveImmutable, responseAppealID, appeal.ChallengeAppealID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is not permitted to request rehearing for response appeal %q", ErrPolicyDenied, actorDID, responseAppealID)
	}

	rehearingID := secureCellNextFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealID(run, appeal.ChallengeAppealID)
	generation := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(*appeal) + 1
	appealingParty := firstNonEmptyResponseParty(req.AppealingParty, appeal.EnforcementAcknowledgementParty, appeal.AppealingParty)
	if appealingParty == "" {
		appealingParty = SecureCellFederationIncidentResponsePartyLocalOrg
	}
	correctionBoardParty := firstNonEmptyResponseParty(req.CorrectionBoardParty, appeal.CorrectionBoardParty)
	enforcementAcknowledgementParty := firstNonEmptyResponseParty(req.EnforcementAcknowledgementParty, req.AppealingParty, appealingParty)
	reviewers := uniqueTrimmedStrings(req.EligibleCorrectionBoardReviewerDIDs)
	if len(reviewers) == 0 {
		reviewers = uniqueTrimmedStrings(appeal.EligibleBoardReviewerDIDs)
	}
	if len(reviewers) == 0 {
		reviewers = []string{actorDID}
	}
	threshold := normalizeSecureCellThreshold(req.CorrectionBoardReviewThreshold)
	if threshold == 0 {
		threshold = normalizeSecureCellThreshold(appeal.BoardReviewThreshold)
	}
	summary := firstNonEmpty(strings.TrimSpace(req.Summary), secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDefaultRehearingSummary(*appeal))
	receipt, err := s.evaluateStage(ctx, run.request, "rehear_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal", lastReceiptHash(run.result), map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                                            appeal.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                  rehearingID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_parent_id":           appeal.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_generation":          fmt.Sprintf("%d", generation),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":              string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold": fmt.Sprintf("%d", threshold),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers": strings.Join(reviewers, ","),
		"transition_reason": firstNonEmpty(strings.TrimSpace(req.Reason), summary),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRehearingRequested), rehearingID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRehearingRequested),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal",
		TargetDID:        rehearingID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           firstNonEmpty(strings.TrimSpace(req.Reason), summary),
		Metadata: mergeStringMaps(req.Metadata, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealMetadata(appeal, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                            rehearingID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_parent_id":                     appeal.ResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_generation":                    fmt.Sprintf("%d", generation),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealing_party":                      string(appealingParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party":               string(correctionBoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_acknowledgement_party":    string(enforcementAcknowledgementParty),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_summary":                              summary,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_description":                          strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_evidence_ids":                         strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_created_by":                           actorDID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_created_at":                           receipt.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold":           fmt.Sprintf("%d", threshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers":           strings.Join(reviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_delegations":         "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recusals":            "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", len(reviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", len(reviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", threshold),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": "false",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ratify_vote_count":                    "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_overturn_vote_count":                  "0",
		})),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

// EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDispute
// opens a fresh rehearing generation after a disputed imported counterparty
// correction-board ruling, preserving a direct evidence link back to the exact
// counterparty snapshot, ruling, and dispute action that triggered escalation.
func (s *Service) EscalateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDispute(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyDisputeEscalationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
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
	if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealForChallengeAppeal(run, localAppeal.ChallengeAppealID); latest == nil || !strings.EqualFold(strings.TrimSpace(latest.ResponseAppealID), strings.TrimSpace(localAppeal.ResponseAppealID)) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: response appeal %q is not the latest appeal for challenge appeal %q", ErrFederationIncidentDirectiveImmutable, responseAppealID, localAppeal.ChallengeAppealID)
	}
	counterpartySummary, err := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummaryBySnapshotAndAppeal(run, strings.TrimSpace(req.CounterpartySnapshotID), strings.TrimSpace(req.CounterpartyResponseAppealID))
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(counterpartySummary.ChallengeAppealID), strings.TrimSpace(localAppeal.ChallengeAppealID)) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: counterparty ruling %q does not belong to challenge appeal %q", counterpartySummary.ResponseAppealID, localAppeal.ChallengeAppealID)
	}
	latestReview := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewAction(run, responseAppealID, counterpartySummary.SnapshotID, counterpartySummary.ResponseAppealID)
	if latestReview == nil || latestReview.ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealCounterpartyReviewStatusDisputed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: disputed counterparty ruling review is required before escalation for response appeal %q", ErrFederationIncidentDirectiveImmutable, responseAppealID)
	}
	divergences := uniqueTrimmedStrings(append(append([]string(nil), latestReview.Divergences...), req.Divergences...))
	summary := firstNonEmpty(strings.TrimSpace(req.Summary), fmt.Sprintf("Escalate disputed counterparty correction-board ruling %s into governed rehearing", counterpartySummary.ResponseAppealID))
	description := firstNonEmpty(strings.TrimSpace(req.Description), "The local organization escalated the disputed imported counterparty correction-board ruling into a fresh signed rehearing generation.")
	reason := firstNonEmpty(strings.TrimSpace(req.Reason), "escalate disputed counterparty correction-board ruling into rehearing")
	metadata := mergeStringMaps(req.Metadata, map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_escalated":          "true",
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_snapshot_id":        counterpartySummary.SnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_bundle_id":          counterpartySummary.BundleID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_response_appeal_id": counterpartySummary.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_transition_id":      latestReview.TransitionID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_reference":          firstNonEmpty(strings.TrimSpace(req.CounterpartyReference), strings.TrimSpace(latestReview.CounterpartyReference)),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_status":             string(latestReview.ReviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_action":             string(latestReview.Action),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_review_divergences":        strings.Join(divergences, ","),
	})
	return s.RehearFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(ctx, cellID, responseAppealID, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRehearingRequest{
		ActorDID:                            req.ActorDID,
		AppealingParty:                      req.AppealingParty,
		CorrectionBoardParty:                req.CorrectionBoardParty,
		EnforcementAcknowledgementParty:     req.EnforcementAcknowledgementParty,
		Summary:                             summary,
		Description:                         description,
		EvidenceIDs:                         uniqueTrimmedStrings(append(append([]string(nil), req.EvidenceIDs...), localAppeal.ResponseAppealID, counterpartySummary.ResponseAppealID, counterpartySummary.SnapshotID)),
		CorrectionBoardReviewThreshold:      req.CorrectionBoardReviewThreshold,
		EligibleCorrectionBoardReviewerDIDs: append([]string(nil), req.EligibleCorrectionBoardReviewerDIDs...),
		Reason:                              reason,
		Metadata:                            metadata,
	})
}

func (s *Service) DelegateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReview(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionDelegationRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, responseAppealID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: response appeal %q is not pending correction-board review", responseAppealID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	targetDID := strings.TrimSpace(req.TargetDID)
	if targetDID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: delegate target DID is required")
	}
	if !secureCellActorAllowed(run, actorDID, true) || !secureCellActorAllowed(run, targetDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: delegated correction-board reviewers must be admitted participants", ErrPolicyDenied)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasRecusal(run, responseAppealID, targetDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is already recused from response appeal %q", ErrFederationIncidentDirectiveImmutable, targetDID, responseAppealID)
	}
	reviewers := uniqueTrimmedStrings(append(appeal.EligibleBoardReviewerDIDs, targetDID))
	if len(reviewers) == len(appeal.EligibleBoardReviewerDIDs) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: actor %q is already an eligible correction-board reviewer", targetDID)
	}
	committeeMembers := len(reviewers)
	recordedVotes := appeal.BoardRecordedVoteCount
	outstandingVotes := committeeMembers - recordedVotes
	if outstandingVotes < 0 {
		outstandingVotes = 0
	}
	bestVoteCount := appeal.RatifyVoteCount
	if appeal.OverturnVoteCount > bestVoteCount {
		bestVoteCount = appeal.OverturnVoteCount
	}
	missingQuorum := appeal.BoardReviewThreshold - bestVoteCount
	if missingQuorum < 0 {
		missingQuorum = 0
	}
	receipt, err := s.evaluateStage(ctx, run.request, "delegate_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_review", lastReceiptHash(run.result), map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                  responseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers": strings.Join(reviewers, ","),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w", ErrPolicyDenied)
	}
	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewDelegated), responseAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewDelegated),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal",
		TargetDID:        responseAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealMetadata(appeal, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(appeal.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers":           strings.Join(reviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_delegations":         fmt.Sprintf("%d", appeal.BoardDelegationCount+1),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recusals":            fmt.Sprintf("%d", appeal.BoardRecusalCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", committeeMembers),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      fmt.Sprintf("%d", recordedVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", outstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", missingQuorum),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": fmt.Sprintf("%t", appeal.BoardThresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_delegated_to":                         targetDID,
		})),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) RuleFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeal(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRulingRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, responseAppealID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: response appeal %q is not pending correction-board review", responseAppealID)
	}
	if req.Ruling != SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify && req.Ruling != SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: ruling must be ratify or overturn")
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is not permitted to rule appeal %q", ErrPolicyDenied, actorDID, responseAppealID)
	}
	if len(appeal.EligibleBoardReviewerDIDs) > 0 && !containsStringFoldSecureCell(appeal.EligibleBoardReviewerDIDs, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: actor %q is not an eligible correction-board reviewer", actorDID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasRecusal(run, responseAppealID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is recused from response appeal %q", ErrFederationIncidentDirectiveImmutable, actorDID, responseAppealID)
	}

	votes := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealVotes(run, responseAppealID)
	votes[actorDID] = req.Ruling
	ratifyVotes := 0
	overturnVotes := 0
	for _, vote := range votes {
		switch vote {
		case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
			ratifyVotes++
		case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
			overturnVotes++
		}
	}
	boardCommitteeMembers := len(appeal.EligibleBoardReviewerDIDs)
	if boardCommitteeMembers == 0 {
		boardCommitteeMembers = len(votes)
	}
	recordedVotes := len(votes)
	outstandingVotes := boardCommitteeMembers - recordedVotes
	if outstandingVotes < 0 {
		outstandingVotes = 0
	}
	bestVoteCount := ratifyVotes
	winningRuling := SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify
	if overturnVotes > bestVoteCount {
		bestVoteCount = overturnVotes
		winningRuling = SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn
	}
	missingQuorum := appeal.BoardReviewThreshold - bestVoteCount
	if missingQuorum < 0 {
		missingQuorum = 0
	}
	thresholdSatisfied := bestVoteCount >= appeal.BoardReviewThreshold
	action := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionVoteRecorded
	status := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview
	recordRuling := req.Ruling
	if thresholdSatisfied {
		action = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled
		status = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusForRuling(winningRuling)
		recordRuling = winningRuling
	}
	receipt, err := s.evaluateStage(ctx, run.request, "rule_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal", lastReceiptHash(run.result), map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                            responseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(status),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling":                        string(recordRuling),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      fmt.Sprintf("%d", recordedVotes),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w", ErrPolicyDenied)
	}
	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(action), responseAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(action),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal",
		TargetDID:        responseAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealMetadata(appeal, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party":               string(firstNonEmptyResponseParty(req.CorrectionBoardParty, appeal.CorrectionBoardParty)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      fmt.Sprintf("%d", recordedVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", boardCommitteeMembers),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", outstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", missingQuorum),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": fmt.Sprintf("%t", thresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ratify_vote_count":                    fmt.Sprintf("%d", ratifyVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_overturn_vote_count":                  fmt.Sprintf("%d", overturnVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling":                        string(recordRuling),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling_summary":                strings.TrimSpace(req.RulingSummary),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling_description":            strings.TrimSpace(req.RulingDescription),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_evidence_ids":                         strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		})),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) AcknowledgeFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealEnforcement(ctx context.Context, cellID string, responseAppealID string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealAcknowledgeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: service is required")
	}
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	appeal, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run, responseAppealID)
	if err != nil {
		return nil, err
	}
	if appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusUpheld &&
		appeal.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusReversed {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: response appeal %q is not yet ruled", responseAppealID)
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: actor %q is not permitted to acknowledge appeal enforcement", ErrPolicyDenied, actorDID)
	}
	receipt, err := s.evaluateStage(ctx, run.request, "acknowledge_federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_enforcement", lastReceiptHash(run.result), map[string]string{
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":     responseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status": string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w", ErrPolicyDenied)
	}
	transition := SecureCellTransition{
		ID:               transitionID(run.request, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged), responseAppealID),
		Action:           "secure_cell." + secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged),
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal",
		TargetDID:        responseAppealID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealMetadata(appeal, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                     string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_acknowledgement_party": string(firstNonEmptyResponseParty(req.AcknowledgingParty, appeal.EnforcementAcknowledgementParty)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_summary":               strings.TrimSpace(req.Summary),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_description":           strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_evidence_ids":                      strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		})),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusals(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run, transition)
			if !ok || record.Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused {
				continue
			}
			recusal := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary{
				CellID:                   record.CellID,
				CellName:                 record.CellName,
				CellStatus:               record.CellStatus,
				Jurisdiction:             record.Jurisdiction,
				OrganizationID:           record.OrganizationID,
				SponsorOfRecord:          record.SponsorOfRecord,
				OrganizationName:         record.OrganizationName,
				IncidentID:               record.IncidentID,
				ResponseID:               record.ResponseID,
				DirectiveID:              record.DirectiveID,
				ExtensionID:              record.ExtensionID,
				DisputeID:                record.DisputeID,
				AppealID:                 record.AppealID,
				ChallengeID:              record.ChallengeID,
				ChallengeAppealID:        record.ChallengeAppealID,
				ResponseAppealID:         record.ResponseAppealID,
				ParentResponseAppealID:   record.ParentResponseAppealID,
				ResponseAppealGeneration: max(record.ResponseAppealGeneration, 1),
				ResponseStatus:           record.ResponseStatus,
				ResponseAppealStatus:     record.Status,
				CorrectionBoardParty:     record.CorrectionBoardParty,
				RecusalID:                record.RecusalID,
				ActorDID:                 record.ActorDID,
				Summary:                  firstNonEmpty(record.Summary, strings.TrimSpace(record.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_summary"])),
				Description:              firstNonEmpty(record.Description, strings.TrimSpace(record.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_description"])),
				CreatedAt:                record.OccurredAt,
				Metadata:                 cloneStringMap(record.Metadata),
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter(recusal, filter) {
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

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppeals(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ResponseAppealID > items[j].ResponseAppealID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter(record, filter) {
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run *secureCellRun) []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary {
	if run == nil || run.result == nil {
		return nil
	}
	states := make(map[string]*secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealState)
	order := make([]string, 0)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run, transition)
		if !ok {
			continue
		}
		responseAppealID := strings.TrimSpace(record.ResponseAppealID)
		if responseAppealID == "" {
			continue
		}
		state := states[responseAppealID]
		if state == nil {
			state = &secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealState{
				summary: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary{
					CellID:                          record.CellID,
					CellName:                        record.CellName,
					CellStatus:                      record.CellStatus,
					Jurisdiction:                    record.Jurisdiction,
					OrganizationID:                  record.OrganizationID,
					SponsorOfRecord:                 record.SponsorOfRecord,
					OrganizationName:                record.OrganizationName,
					IncidentID:                      record.IncidentID,
					ResponseID:                      record.ResponseID,
					DirectiveID:                     record.DirectiveID,
					ExtensionID:                     record.ExtensionID,
					DisputeID:                       record.DisputeID,
					AppealID:                        record.AppealID,
					ChallengeID:                     record.ChallengeID,
					ChallengeAppealID:               record.ChallengeAppealID,
					ResponseAppealID:                responseAppealID,
					ParentResponseAppealID:          record.ParentResponseAppealID,
					ResponseAppealGeneration:        max(record.ResponseAppealGeneration, 1),
					ResponseStatus:                  record.ResponseStatus,
					ResponseAction:                  record.ResponseAction,
					ResponseTransitionID:            record.ResponseTransitionID,
					ResponseCounterpartyReference:   record.ResponseCounterpartyReference,
					ResponseCounterpartySnapshotID:  record.ResponseCounterpartySnapshotID,
					Status:                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview,
					AppealingParty:                  record.AppealingParty,
					CorrectionBoardParty:            record.CorrectionBoardParty,
					EnforcementAcknowledgementParty: record.EnforcementAcknowledgementParty,
					Summary:                         record.Summary,
					Description:                     record.Description,
					EvidenceIDs:                     append([]string(nil), record.EvidenceIDs...),
					BoardReviewThreshold:            normalizeSecureCellThreshold(record.BoardReviewThreshold),
					EligibleBoardReviewerDIDs:       append([]string(nil), record.EligibleBoardReviewerDIDs...),
					BoardDelegationCount:            record.BoardDelegationCount,
					BoardRecusalCount:               record.BoardRecusalCount,
					CreatedBy:                       record.ActorDID,
					CreatedAt:                       record.OccurredAt,
					UpdatedAt:                       record.OccurredAt,
					Metadata:                        cloneStringMap(record.Metadata),
				},
				votes: make(map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling),
			}
			states[responseAppealID] = state
			order = append(order, responseAppealID)
		}
		state.summary.CellStatus = record.CellStatus
		state.summary.ResponseStatus = record.ResponseStatus
		state.summary.ResponseAction = record.ResponseAction
		state.summary.ResponseTransitionID = firstNonEmpty(record.ResponseTransitionID, state.summary.ResponseTransitionID)
		state.summary.ResponseCounterpartyReference = firstNonEmpty(record.ResponseCounterpartyReference, state.summary.ResponseCounterpartyReference)
		state.summary.ResponseCounterpartySnapshotID = firstNonEmpty(record.ResponseCounterpartySnapshotID, state.summary.ResponseCounterpartySnapshotID)
		if strings.TrimSpace(record.ParentResponseAppealID) != "" {
			state.summary.ParentResponseAppealID = record.ParentResponseAppealID
		}
		if record.ResponseAppealGeneration > 0 {
			state.summary.ResponseAppealGeneration = record.ResponseAppealGeneration
		}
		state.summary.Status = record.Status
		state.summary.AppealingParty = firstNonEmptyResponseParty(record.AppealingParty, state.summary.AppealingParty)
		state.summary.CorrectionBoardParty = firstNonEmptyResponseParty(record.CorrectionBoardParty, state.summary.CorrectionBoardParty)
		state.summary.EnforcementAcknowledgementParty = firstNonEmptyResponseParty(record.EnforcementAcknowledgementParty, state.summary.EnforcementAcknowledgementParty)
		if record.Summary != "" {
			state.summary.Summary = record.Summary
		}
		if record.Description != "" {
			state.summary.Description = record.Description
		}
		if len(record.EvidenceIDs) > 0 {
			state.summary.EvidenceIDs = append([]string(nil), record.EvidenceIDs...)
		}
		if threshold := normalizeSecureCellThreshold(record.BoardReviewThreshold); threshold > 0 {
			state.summary.BoardReviewThreshold = threshold
		}
		if reviewers := uniqueTrimmedStrings(record.EligibleBoardReviewerDIDs); len(reviewers) > 0 {
			state.summary.EligibleBoardReviewerDIDs = reviewers
		}
		state.summary.BoardDelegationCount = max(state.summary.BoardDelegationCount, record.BoardDelegationCount)
		state.summary.BoardRecusalCount = max(state.summary.BoardRecusalCount, record.BoardRecusalCount)
		state.summary.Metadata = mergeStringMaps(state.summary.Metadata, record.Metadata)
		state.summary.ActionCount++
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionAppealed ||
			record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRehearingRequested {
			state.summary.Status = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview
		}
		if record.Ruling != "" && strings.TrimSpace(record.ActorDID) != "" && record.Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged {
			state.votes[strings.TrimSpace(record.ActorDID)] = record.Ruling
		}
		state.summary.RatifyVoteCount = 0
		state.summary.OverturnVoteCount = 0
		for _, vote := range state.votes {
			switch vote {
			case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
				state.summary.RatifyVoteCount++
			case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
				state.summary.OverturnVoteCount++
			}
		}
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
		state.summary.UpdatedAt = record.OccurredAt
		if state.summary.EnforcementAcknowledgedAt != nil {
			state.summary.Status = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged
		} else if state.summary.Ruling != "" && state.summary.BoardThresholdSatisfied && state.summary.Status == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusPendingCorrectionBoardReview {
			state.summary.Status = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusForRuling(state.summary.Ruling)
		}
		switch record.Action {
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled:
			state.summary.Status = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusForRuling(record.Ruling)
			state.summary.Ruling = record.Ruling
			state.summary.RulingSummary = record.RulingSummary
			state.summary.RulingDescription = record.RulingDescription
			state.summary.RuledBy = record.ActorDID
			ruledAt := record.OccurredAt.UTC()
			state.summary.RuledAt = &ruledAt
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged:
			state.summary.Status = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged
			state.summary.EnforcementSummary = record.EnforcementSummary
			state.summary.EnforcementDescription = record.EnforcementDescription
			state.summary.EnforcementAcknowledgedBy = record.ActorDID
			ackAt := record.OccurredAt.UTC()
			state.summary.EnforcementAcknowledgedAt = &ackAt
		}
		state.summary.Metadata = mergeStringMaps(state.summary.Metadata, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status":                        string(state.summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_parent_id":                     state.summary.ParentResponseAppealID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_generation":                    fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(state.summary)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_delegations":         fmt.Sprintf("%d", state.summary.BoardDelegationCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recusals":            fmt.Sprintf("%d", state.summary.BoardRecusalCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", state.summary.BoardCommitteeMemberCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      fmt.Sprintf("%d", state.summary.BoardRecordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", state.summary.BoardOutstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", state.summary.BoardMissingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": fmt.Sprintf("%t", state.summary.BoardThresholdSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ratify_vote_count":                    fmt.Sprintf("%d", state.summary.RatifyVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_overturn_vote_count":                  fmt.Sprintf("%d", state.summary.OverturnVoteCount),
		})
	}
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		if state := states[order[i]]; state != nil {
			items = append(items, state.summary)
		}
	}
	return items
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealByID(run *secureCellRun, responseAppealID string) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, error) {
	responseAppealID = strings.TrimSpace(responseAppealID)
	if responseAppealID == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: response appeal ID is required")
	}
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ResponseAppealID), responseAppealID) {
			copy := item
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-response-appeal: %w: response appeal %q", ErrFederationIncidentDirectiveNotFound, responseAppealID)
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealForChallengeAppeal(run *secureCellRun, challengeAppealID string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary {
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	if challengeAppealID == "" {
		return nil
	}
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), challengeAppealID) {
			copy := item
			return &copy
		}
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealVotes(run *secureCellRun, responseAppealID string) map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling {
	votes := make(map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling)
	if run == nil || run.result == nil {
		return votes
	}
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run, transition)
		if !ok || !strings.EqualFold(strings.TrimSpace(record.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
			continue
		}
		if record.Ruling == "" || strings.TrimSpace(record.ActorDID) == "" || record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged {
			continue
		}
		votes[strings.TrimSpace(record.ActorDID)] = record.Ruling
	}
	return votes
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord{
		CellID:                          safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                        safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                      safeSecureCellStatus(run),
		Jurisdiction:                    safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:                  strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:                 strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:                strings.TrimSpace(meta["federation_organization_name"]),
		IncidentID:                      strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                      strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:                     strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:                     strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                       strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                        strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		ChallengeID:                     strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ChallengeAppealID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
		ResponseAppealID:                strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id"]),
		ParentResponseAppealID:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_parent_id"]),
		ResponseAppealGeneration:        secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_generation"),
		ResponseStatus:                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status"])),
		ResponseAction:                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseActionType(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action"])),
		ResponseTransitionID:            strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id"]),
		ResponseCounterpartyReference:   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_reference"]),
		ResponseCounterpartySnapshotID:  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_snapshot_id"]),
		Status:                          SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_status"])),
		Action:                          actionType,
		AppealingParty:                  SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealing_party"])),
		CorrectionBoardParty:            SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party"])),
		EnforcementAcknowledgementParty: SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_acknowledgement_party"])),
		BoardReviewThreshold:            secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold"),
		EligibleBoardReviewerDIDs:       uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers"]), ",")),
		BoardDelegationCount:            secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_delegations"),
		BoardRecusalCount:               secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recusals"),
		BoardCommitteeMemberCount:       secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members"),
		BoardRecordedVoteCount:          secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes"),
		BoardOutstandingVotes:           secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes"),
		BoardMissingQuorumCount:         secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum"),
		BoardThresholdSatisfied:         secureCellMetadataBool(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied"),
		RatifyVoteCount:                 secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ratify_vote_count"),
		OverturnVoteCount:               secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_overturn_vote_count"),
		Ruling:                          SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling"])),
		Summary:                         firstNonEmpty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_summary"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_summary"])),
		Description:                     firstNonEmpty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_description"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_description"])),
		RulingSummary:                   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling_summary"]),
		RulingDescription:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling_description"]),
		EnforcementSummary:              strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_summary"]),
		EnforcementDescription:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_description"]),
		EvidenceIDs:                     uniqueTrimmedStrings(strings.Split(firstNonEmpty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_evidence_ids"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_evidence_ids"])), ",")),
		DelegatedToDID:                  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_delegated_to"]),
		RecusalID:                       strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_recusal_id"]),
		TransitionID:                    strings.TrimSpace(transition.ID),
		ActorDID:                        strings.TrimSpace(transition.Actor),
		Reason:                          firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Metadata:                        meta,
		OccurredAt:                      transition.OccurredAt.UTC(),
	}
	record.ResponseAppealGeneration = max(record.ResponseAppealGeneration, 1)
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
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled:
		record.Status = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusForRuling(record.Ruling)
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged:
		record.Status = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusEnforcementAcknowledged
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealed":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionAppealed, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_review_delegated":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewDelegated, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_rehearing_requested":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRehearingRequested, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_review_recused":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_vote_recorded":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionVoteRecorded, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruled":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_enforcement_acknowledged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionAppealed:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealed"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewDelegated:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_review_delegated"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRehearingRequested:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_rehearing_requested"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_review_recused"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionVoteRecorded:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_vote_recorded"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruled"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionEnforcementAcknowledged:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_enforcement_acknowledged"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_reviewed"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealMetadata(appeal *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, extra map[string]string) map[string]string {
	if appeal == nil {
		return cloneStringMap(extra)
	}
	defaults := map[string]string{
		"federation_organization_id":                                                        appeal.OrganizationID,
		"federation_sponsor_of_record":                                                      appeal.SponsorOfRecord,
		"federation_organization_name":                                                      appeal.OrganizationName,
		"federation_incident_id":                                                            appeal.IncidentID,
		"federation_incident_response_id":                                                   appeal.ResponseID,
		"federation_incident_directive_id":                                                  appeal.DirectiveID,
		"federation_incident_directive_extension_id":                                        appeal.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                appeal.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                 appeal.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":        appeal.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id": appeal.ChallengeAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_id":                            appeal.ResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_parent_id":                     appeal.ParentResponseAppealID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_generation":                    fmt.Sprintf("%d", secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(*appeal)),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_status":                               string(appeal.ResponseStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_action":                               string(appeal.ResponseAction),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_transition_id":                        appeal.ResponseTransitionID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_reference":               appeal.ResponseCounterpartyReference,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_counterparty_snapshot_id":             appeal.ResponseCounterpartySnapshotID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appealing_party":                      string(appeal.AppealingParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_party":               string(appeal.CorrectionBoardParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_enforcement_acknowledgement_party":    string(appeal.EnforcementAcknowledgementParty),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_summary":                              appeal.Summary,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_description":                          appeal.Description,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_evidence_ids":                         strings.Join(appeal.EvidenceIDs, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_created_by":                           appeal.CreatedBy,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold":           fmt.Sprintf("%d", appeal.BoardReviewThreshold),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_reviewers":           strings.Join(appeal.EligibleBoardReviewerDIDs, ","),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_delegations":         fmt.Sprintf("%d", appeal.BoardDelegationCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recusals":            fmt.Sprintf("%d", appeal.BoardRecusalCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_committee_members":   fmt.Sprintf("%d", appeal.BoardCommitteeMemberCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_recorded_votes":      fmt.Sprintf("%d", appeal.BoardRecordedVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_outstanding_votes":   fmt.Sprintf("%d", appeal.BoardOutstandingVotes),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_missing_quorum":      fmt.Sprintf("%d", appeal.BoardMissingQuorumCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_correction_board_threshold_satisfied": fmt.Sprintf("%t", appeal.BoardThresholdSatisfied),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_ratify_vote_count":                    fmt.Sprintf("%d", appeal.RatifyVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_overturn_vote_count":                  fmt.Sprintf("%d", appeal.OverturnVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_response_appeal_ruling":                        string(appeal.Ruling),
	}
	return mergeStringMaps(cloneStringMap(appeal.Metadata), mergeStringMaps(defaults, extra))
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealFilter) bool {
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
	if filter.ParentResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ParentResponseAppealID), strings.TrimSpace(filter.ParentResponseAppealID)) {
		return false
	}
	if filter.ResponseStatus != "" && item.ResponseStatus != filter.ResponseStatus {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
		return false
	}
	return true
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFilter) bool {
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
	if filter.ParentResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ParentResponseAppealID), strings.TrimSpace(filter.ParentResponseAppealID)) {
		return false
	}
	if filter.ResponseStatus != "" && item.ResponseStatus != filter.ResponseStatus {
		return false
	}
	if filter.Status != "" && item.Status != filter.Status {
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

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalFilter) bool {
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
	if filter.ParentResponseAppealID != "" && !strings.EqualFold(strings.TrimSpace(item.ParentResponseAppealID), strings.TrimSpace(filter.ParentResponseAppealID)) {
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusForRuling(ruling SecureCellFederationIncidentDirectiveExtensionAppealRuling) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus {
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusReversed
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusUpheld
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatusCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealStatus) int {
	total := 0
	for _, item := range items {
		if item.Status == status {
			total++
		}
	}
	return total
}

func secureCellNextFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealID(run *secureCellRun, challengeAppealID string) string {
	generation := 1
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealsFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeAppealID), strings.TrimSpace(challengeAppealID)) {
			generation++
		}
	}
	return fmt.Sprintf("%s-alignment-response-appeal-%02d", strings.TrimSpace(challengeAppealID), generation)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalID(responseAppealID string, actorDID string, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%d", strings.TrimSpace(responseAppealID), strings.TrimSpace(actorDID), ordinal+1)
	return fmt.Sprintf("%x-alignment-response-appeal-recusal-%x", sha256.Sum256([]byte(strings.TrimSpace(responseAppealID))), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusalSummaryText(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) string {
	if strings.TrimSpace(appeal.ParentResponseAppealID) != "" {
		return "recuse from response appeal rehearing correction-board review"
	}
	return "recuse from response appeal correction-board review"
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealDefaultRehearingSummary(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) string {
	switch secureCellNormalizedFederationIncidentDirectiveExtensionAppealRuling(appeal.Ruling) {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return "request rehearing of reversed alignment response appeal ruling"
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return "request rehearing of upheld alignment response appeal ruling"
	default:
		return "request rehearing of alignment response appeal ruling"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealGeneration(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary) int {
	if appeal.ResponseAppealGeneration > 0 {
		return appeal.ResponseAppealGeneration
	}
	return 1
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusedReviewerDIDs(run *secureCellRun, responseAppealID string) []string {
	items := make([]string, 0)
	if run == nil || run.result == nil {
		return items
	}
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run, transition)
		if !ok || record.Action != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionReviewRecused {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
			continue
		}
		if actor := strings.TrimSpace(record.ActorDID); actor != "" {
			items = append(items, actor)
		}
	}
	return uniqueTrimmedStrings(items)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasRecusal(run *secureCellRun, responseAppealID string, actorDID string) bool {
	actorDID = strings.TrimSpace(actorDID)
	if actorDID == "" {
		return false
	}
	for _, candidate := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealRecusedReviewerDIDs(run, responseAppealID) {
		if strings.EqualFold(strings.TrimSpace(candidate), actorDID) {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasVote(run *secureCellRun, responseAppealID string, actorDID string) bool {
	if run == nil || run.result == nil {
		return false
	}
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionFromTransition(run, transition)
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ResponseAppealID), strings.TrimSpace(responseAppealID)) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(record.ActorDID), strings.TrimSpace(actorDID)) {
			continue
		}
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionVoteRecorded || record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealActionRuled {
			return true
		}
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealReviewerAllowed(run *secureCellRun, appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealSummary, actorDID string) bool {
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentResponseAppealHasRecusal(run, appeal.ResponseAppealID, actorDID) {
		return false
	}
	if len(appeal.EligibleBoardReviewerDIDs) == 0 {
		return true
	}
	return secureCellStringSliceContains(appeal.EligibleBoardReviewerDIDs, actorDID)
}

func firstNonEmptyResponseParty(values ...SecureCellFederationIncidentResponseParty) SecureCellFederationIncidentResponseParty {
	for _, value := range values {
		if strings.TrimSpace(string(value)) != "" {
			return value
		}
	}
	return ""
}

func containsStringFoldSecureCell(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}
