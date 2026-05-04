package securecells

import "time"

type SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealVoteChoiceRatify   SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice = "ratify"
	SecureCellFederationIncidentDirectiveExtensionAppealVoteChoiceOverturn SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice = "overturn"
)

// SecureCellFederationIncidentDirectiveExtensionAppealVote captures one
// evidence-bearing vote inside an appeal-board review.
type SecureCellFederationIncidentDirectiveExtensionAppealVote struct {
	ID                string                                                         `json:"id"`
	AppealID          string                                                         `json:"appeal_id"`
	ActorDID          string                                                         `json:"actor_did"`
	Choice            SecureCellFederationIncidentDirectiveExtensionAppealVoteChoice `json:"choice"`
	Reason            string                                                         `json:"reason,omitempty"`
	PolicyReceiptID   string                                                         `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                                         `json:"policy_receipt_hash,omitempty"`
	CreatedAt         time.Time                                                      `json:"created_at"`
	Metadata          map[string]string                                              `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealRecusal captures one
// reviewer-conflict recusal inside a bilateral appeal-board review.
type SecureCellFederationIncidentDirectiveExtensionAppealRecusal struct {
	ID                string                                    `json:"id"`
	AppealID          string                                    `json:"appeal_id"`
	ActorDID          string                                    `json:"actor_did"`
	BoardParty        SecureCellFederationIncidentResponseParty `json:"board_party"`
	Summary           string                                    `json:"summary,omitempty"`
	Description       string                                    `json:"description,omitempty"`
	EvidenceIDs       []string                                  `json:"evidence_ids,omitempty"`
	PolicyReceiptID   string                                    `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash string                                    `json:"policy_receipt_hash,omitempty"`
	CreatedAt         time.Time                                 `json:"created_at"`
	Metadata          map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealStatus captures the
// lifecycle of one bilateral appeal-board review over a dispute ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview      SecureCellFederationIncidentDirectiveExtensionAppealStatus = "pending_board_review"
	SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified                SecureCellFederationIncidentDirectiveExtensionAppealStatus = "ratified"
	SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned              SecureCellFederationIncidentDirectiveExtensionAppealStatus = "overturned"
	SecureCellFederationIncidentDirectiveExtensionAppealStatusEnforcementAcknowledged SecureCellFederationIncidentDirectiveExtensionAppealStatus = "enforcement_acknowledged"
)

// SecureCellFederationIncidentDirectiveExtensionAppealRuling captures the
// board's final disposition over an appealed dispute ruling.
type SecureCellFederationIncidentDirectiveExtensionAppealRuling string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify   SecureCellFederationIncidentDirectiveExtensionAppealRuling = "ratify"
	SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn SecureCellFederationIncidentDirectiveExtensionAppealRuling = "overturn"
)

// SecureCellFederationIncidentDirectiveExtensionAppeal preserves one
// evidence-bearing cross-organization appeal-board review over a resolved
// directive deadline exception dispute.
type SecureCellFederationIncidentDirectiveExtensionAppeal struct {
	ID                                    string                                                          `json:"id"`
	ResponseID                            string                                                          `json:"response_id"`
	DirectiveID                           string                                                          `json:"directive_id"`
	ExtensionID                           string                                                          `json:"extension_id"`
	DisputeID                             string                                                          `json:"dispute_id"`
	OrganizationID                        string                                                          `json:"organization_id"`
	SponsorOfRecord                       string                                                          `json:"sponsor_of_record,omitempty"`
	IncidentID                            string                                                          `json:"incident_id"`
	ParentAppealID                        string                                                          `json:"parent_appeal_id,omitempty"`
	AppealGeneration                      int                                                             `json:"appeal_generation,omitempty"`
	AppealingParty                        SecureCellFederationIncidentResponseParty                       `json:"appealing_party"`
	BoardParty                            SecureCellFederationIncidentResponseParty                       `json:"board_party"`
	EnforcementAcknowledgementParty       SecureCellFederationIncidentResponseParty                       `json:"enforcement_acknowledgement_party"`
	ChallengedDisputeStatus               SecureCellFederationIncidentDirectiveExtensionDisputeStatus     `json:"challenged_dispute_status"`
	ChallengedResolution                  SecureCellFederationIncidentDirectiveExtensionDisputeResolution `json:"challenged_resolution"`
	ChallengedExtensionStatus             SecureCellFederationIncidentDirectiveExtensionStatus            `json:"challenged_extension_status"`
	AppealedBy                            string                                                          `json:"appealed_by,omitempty"`
	Summary                               string                                                          `json:"summary"`
	Description                           string                                                          `json:"description,omitempty"`
	EvidenceIDs                           []string                                                        `json:"evidence_ids,omitempty"`
	BoardReviewThreshold                  int                                                             `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs             []string                                                        `json:"eligible_board_reviewer_dids,omitempty"`
	BoardVotes                            []SecureCellFederationIncidentDirectiveExtensionAppealVote      `json:"board_votes,omitempty"`
	BoardDelegations                      []SecureCellFederationIncidentDirectiveExtensionDelegation      `json:"board_delegations,omitempty"`
	BoardRecusals                         []SecureCellFederationIncidentDirectiveExtensionAppealRecusal   `json:"board_recusals,omitempty"`
	Status                                SecureCellFederationIncidentDirectiveExtensionAppealStatus      `json:"status"`
	RequestReceiptID                      string                                                          `json:"request_receipt_id,omitempty"`
	RequestReceiptHash                    string                                                          `json:"request_receipt_hash,omitempty"`
	Ruling                                SecureCellFederationIncidentDirectiveExtensionAppealRuling      `json:"ruling,omitempty"`
	RulingReceiptID                       string                                                          `json:"ruling_receipt_id,omitempty"`
	RulingReceiptHash                     string                                                          `json:"ruling_receipt_hash,omitempty"`
	RulingSummary                         string                                                          `json:"ruling_summary,omitempty"`
	RulingDescription                     string                                                          `json:"ruling_description,omitempty"`
	RulingEvidenceIDs                     []string                                                        `json:"ruling_evidence_ids,omitempty"`
	RuledBy                               string                                                          `json:"ruled_by,omitempty"`
	RuledAt                               *time.Time                                                      `json:"ruled_at,omitempty"`
	EnforcementAcknowledgementReceiptID   string                                                          `json:"enforcement_acknowledgement_receipt_id,omitempty"`
	EnforcementAcknowledgementReceiptHash string                                                          `json:"enforcement_acknowledgement_receipt_hash,omitempty"`
	EnforcementSummary                    string                                                          `json:"enforcement_summary,omitempty"`
	EnforcementDescription                string                                                          `json:"enforcement_description,omitempty"`
	EnforcementEvidenceIDs                []string                                                        `json:"enforcement_evidence_ids,omitempty"`
	EnforcementAcknowledgedBy             string                                                          `json:"enforcement_acknowledged_by,omitempty"`
	EnforcementAcknowledgedAt             *time.Time                                                      `json:"enforcement_acknowledged_at,omitempty"`
	CreatedAt                             time.Time                                                       `json:"created_at"`
	UpdatedAt                             time.Time                                                       `json:"updated_at"`
	Metadata                              map[string]string                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealRequest opens one
// governed appeal-board review over a resolved directive exception dispute.
type SecureCellFederationIncidentDirectiveExtensionAppealRequest struct {
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

// SecureCellFederationIncidentDirectiveExtensionAppealRehearingRequest
// requests one rehearing over a previously ruled directive-exception appeal.
type SecureCellFederationIncidentDirectiveExtensionAppealRehearingRequest struct {
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

// SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest records
// one board vote or final ruling for an appealed directive exception dispute.
type SecureCellFederationIncidentDirectiveExtensionAppealRulingRequest struct {
	ActorDID          string                                                     `json:"actor_did,omitempty"`
	BoardParty        SecureCellFederationIncidentResponseParty                  `json:"board_party,omitempty"`
	Ruling            SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary     string                                                     `json:"ruling_summary,omitempty"`
	RulingDescription string                                                     `json:"ruling_description,omitempty"`
	EvidenceIDs       []string                                                   `json:"evidence_ids,omitempty"`
	Reason            string                                                     `json:"reason,omitempty"`
	Metadata          map[string]string                                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealRecuseRequest records
// one conflict-of-interest recusal for an appeal-board reviewer.
type SecureCellFederationIncidentDirectiveExtensionAppealRecuseRequest struct {
	ActorDID    string                                    `json:"actor_did,omitempty"`
	BoardParty  SecureCellFederationIncidentResponseParty `json:"board_party,omitempty"`
	Summary     string                                    `json:"summary,omitempty"`
	Description string                                    `json:"description,omitempty"`
	EvidenceIDs []string                                  `json:"evidence_ids,omitempty"`
	Reason      string                                    `json:"reason,omitempty"`
	Metadata    map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest
// records reciprocal acknowledgement that the final appeal ruling will be
// enforced.
type SecureCellFederationIncidentDirectiveExtensionAppealAcknowledgeRequest struct {
	ActorDID           string                                    `json:"actor_did,omitempty"`
	AcknowledgingParty SecureCellFederationIncidentResponseParty `json:"acknowledging_party,omitempty"`
	Summary            string                                    `json:"summary,omitempty"`
	Description        string                                    `json:"description,omitempty"`
	EvidenceIDs        []string                                  `json:"evidence_ids,omitempty"`
	Reason             string                                    `json:"reason,omitempty"`
	Metadata           map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealFilter narrows operator
// queries across directive-exception appeals.
type SecureCellFederationIncidentDirectiveExtensionAppealFilter struct {
	CellID         string                                                     `json:"cell_id,omitempty"`
	OrganizationID string                                                     `json:"organization_id,omitempty"`
	IncidentID     string                                                     `json:"incident_id,omitempty"`
	ResponseID     string                                                     `json:"response_id,omitempty"`
	DirectiveID    string                                                     `json:"directive_id,omitempty"`
	ExtensionID    string                                                     `json:"extension_id,omitempty"`
	DisputeID      string                                                     `json:"dispute_id,omitempty"`
	AppealID       string                                                     `json:"appeal_id,omitempty"`
	ParentAppealID string                                                     `json:"parent_appeal_id,omitempty"`
	Status         SecureCellFederationIncidentDirectiveExtensionAppealStatus `json:"status,omitempty"`
	Since          *time.Time                                                 `json:"since,omitempty"`
	Until          *time.Time                                                 `json:"until,omitempty"`
	Limit          int                                                        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealSummary projects one
// bilateral appeal-board review for operator and auditor use.
type SecureCellFederationIncidentDirectiveExtensionAppealSummary struct {
	CellID                          string                                                          `json:"cell_id"`
	CellName                        string                                                          `json:"cell_name,omitempty"`
	Jurisdiction                    string                                                          `json:"jurisdiction,omitempty"`
	CellStatus                      SecureCellStatus                                                `json:"cell_status"`
	ResponseID                      string                                                          `json:"response_id"`
	OrganizationID                  string                                                          `json:"organization_id"`
	SponsorOfRecord                 string                                                          `json:"sponsor_of_record,omitempty"`
	IncidentID                      string                                                          `json:"incident_id"`
	DirectiveID                     string                                                          `json:"directive_id"`
	DirectiveTitle                  string                                                          `json:"directive_title"`
	DirectiveStatus                 SecureCellFederationIncidentDirectiveStatus                     `json:"directive_status"`
	ExtensionID                     string                                                          `json:"extension_id"`
	ExtensionStatus                 SecureCellFederationIncidentDirectiveExtensionStatus            `json:"extension_status"`
	DisputeID                       string                                                          `json:"dispute_id"`
	DisputeStatus                   SecureCellFederationIncidentDirectiveExtensionDisputeStatus     `json:"dispute_status"`
	AppealID                        string                                                          `json:"appeal_id"`
	ParentAppealID                  string                                                          `json:"parent_appeal_id,omitempty"`
	AppealGeneration                int                                                             `json:"appeal_generation,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                       `json:"appealing_party"`
	BoardParty                      SecureCellFederationIncidentResponseParty                       `json:"board_party"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                       `json:"enforcement_acknowledgement_party"`
	ChallengedResolution            SecureCellFederationIncidentDirectiveExtensionDisputeResolution `json:"challenged_resolution"`
	ChallengedExtensionStatus       SecureCellFederationIncidentDirectiveExtensionStatus            `json:"challenged_extension_status"`
	AppealedBy                      string                                                          `json:"appealed_by,omitempty"`
	Summary                         string                                                          `json:"summary"`
	Description                     string                                                          `json:"description,omitempty"`
	Status                          SecureCellFederationIncidentDirectiveExtensionAppealStatus      `json:"status"`
	BoardReviewThreshold            int                                                             `json:"board_review_threshold"`
	EligibleBoardReviewerCount      int                                                             `json:"eligible_board_reviewer_count"`
	BoardDelegationCount            int                                                             `json:"board_delegation_count"`
	BoardRecusalCount               int                                                             `json:"board_recusal_count"`
	BoardCommitteeMemberCount       int                                                             `json:"board_committee_member_count"`
	BoardRecordedVoteCount          int                                                             `json:"board_recorded_vote_count"`
	BoardOutstandingVotes           int                                                             `json:"board_outstanding_votes"`
	BoardMissingQuorumCount         int                                                             `json:"board_missing_quorum_count"`
	RatifyVoteCount                 int                                                             `json:"ratify_vote_count"`
	OverturnVoteCount               int                                                             `json:"overturn_vote_count"`
	BoardThresholdSatisfied         bool                                                            `json:"board_threshold_satisfied"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling      `json:"ruling,omitempty"`
	RulingSummary                   string                                                          `json:"ruling_summary,omitempty"`
	RuledBy                         string                                                          `json:"ruled_by,omitempty"`
	RuledAt                         *time.Time                                                      `json:"ruled_at,omitempty"`
	EnforcementAcknowledgedBy       string                                                          `json:"enforcement_acknowledged_by,omitempty"`
	EnforcementAcknowledgedAt       *time.Time                                                      `json:"enforcement_acknowledged_at,omitempty"`
	CreatedAt                       time.Time                                                       `json:"created_at"`
	UpdatedAt                       time.Time                                                       `json:"updated_at"`
	Metadata                        map[string]string                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter narrows
// operator queries over reviewer-conflict recusals on appeal-board reviews.
type SecureCellFederationIncidentDirectiveExtensionAppealRecusalFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	ExtensionID    string     `json:"extension_id,omitempty"`
	DisputeID      string     `json:"dispute_id,omitempty"`
	AppealID       string     `json:"appeal_id,omitempty"`
	ActorDID       string     `json:"actor_did,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealRecusalSummary projects
// one evidence-bearing appeal-board recusal for operator and auditor use.
type SecureCellFederationIncidentDirectiveExtensionAppealRecusalSummary struct {
	CellID           string                                                      `json:"cell_id"`
	CellName         string                                                      `json:"cell_name,omitempty"`
	Jurisdiction     string                                                      `json:"jurisdiction,omitempty"`
	CellStatus       SecureCellStatus                                            `json:"cell_status"`
	ResponseID       string                                                      `json:"response_id"`
	OrganizationID   string                                                      `json:"organization_id"`
	SponsorOfRecord  string                                                      `json:"sponsor_of_record,omitempty"`
	IncidentID       string                                                      `json:"incident_id"`
	DirectiveID      string                                                      `json:"directive_id"`
	DirectiveTitle   string                                                      `json:"directive_title"`
	DirectiveStatus  SecureCellFederationIncidentDirectiveStatus                 `json:"directive_status"`
	ExtensionID      string                                                      `json:"extension_id"`
	ExtensionStatus  SecureCellFederationIncidentDirectiveExtensionStatus        `json:"extension_status"`
	DisputeID        string                                                      `json:"dispute_id"`
	DisputeStatus    SecureCellFederationIncidentDirectiveExtensionDisputeStatus `json:"dispute_status"`
	AppealID         string                                                      `json:"appeal_id"`
	AppealStatus     SecureCellFederationIncidentDirectiveExtensionAppealStatus  `json:"appeal_status"`
	ParentAppealID   string                                                      `json:"parent_appeal_id,omitempty"`
	AppealGeneration int                                                         `json:"appeal_generation,omitempty"`
	BoardParty       SecureCellFederationIncidentResponseParty                   `json:"board_party"`
	RecusalID        string                                                      `json:"recusal_id"`
	ActorDID         string                                                      `json:"actor_did"`
	Summary          string                                                      `json:"summary,omitempty"`
	Description      string                                                      `json:"description,omitempty"`
	CreatedAt        time.Time                                                   `json:"created_at"`
	Metadata         map[string]string                                           `json:"metadata,omitempty"`
}
