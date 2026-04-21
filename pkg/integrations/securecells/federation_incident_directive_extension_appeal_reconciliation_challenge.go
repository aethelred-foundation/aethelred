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

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus
// tracks the board-review posture for one challenged bilateral appeal
// reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus = "pending_board_review"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus = "ratified"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusOverturned         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus = "overturned"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType
// captures one challenge-board transition over a bilateral appeal
// reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType string

const (
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionChallenged   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType = "challenge"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionVoteRecorded SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType = "vote_recorded"
	SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled        SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType = "ruled"
)

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest
// opens one bilateral reconciliation-board review over the current appeal
// reconciliation posture.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest struct {
	ActorDID                  string                                    `json:"actor_did,omitempty"`
	ChallengingParty          SecureCellFederationIncidentResponseParty `json:"challenging_party,omitempty"`
	Summary                   string                                    `json:"summary,omitempty"`
	Description               string                                    `json:"description,omitempty"`
	EvidenceIDs               []string                                  `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                       `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                  `json:"eligible_board_reviewer_dids,omitempty"`
	Reason                    string                                    `json:"reason,omitempty"`
	Metadata                  map[string]string                         `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest
// records one board vote or final ruling over a reconciliation challenge.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest struct {
	ActorDID          string                                                     `json:"actor_did,omitempty"`
	BoardParty        SecureCellFederationIncidentResponseParty                  `json:"board_party,omitempty"`
	Ruling            SecureCellFederationIncidentDirectiveExtensionAppealRuling `json:"ruling,omitempty"`
	RulingSummary     string                                                     `json:"ruling_summary,omitempty"`
	RulingDescription string                                                     `json:"ruling_description,omitempty"`
	EvidenceIDs       []string                                                   `json:"evidence_ids,omitempty"`
	Reason            string                                                     `json:"reason,omitempty"`
	Metadata          map[string]string                                          `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter
// narrows operator views across reconciliation-board reviews.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter struct {
	CellID           string                                                                            `json:"cell_id,omitempty"`
	OrganizationID   string                                                                            `json:"organization_id,omitempty"`
	IncidentID       string                                                                            `json:"incident_id,omitempty"`
	ResponseID       string                                                                            `json:"response_id,omitempty"`
	DirectiveID      string                                                                            `json:"directive_id,omitempty"`
	ExtensionID      string                                                                            `json:"extension_id,omitempty"`
	DisputeID        string                                                                            `json:"dispute_id,omitempty"`
	AppealID         string                                                                            `json:"appeal_id,omitempty"`
	ComparisonKey    string                                                                            `json:"comparison_key,omitempty"`
	ChallengeID      string                                                                            `json:"challenge_id,omitempty"`
	Status           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus `json:"status,omitempty"`
	ChallengingParty SecureCellFederationIncidentResponseParty                                         `json:"challenging_party,omitempty"`
	BoardParty       SecureCellFederationIncidentResponseParty                                         `json:"board_party,omitempty"`
	Ruling           SecureCellFederationIncidentDirectiveExtensionAppealRuling                        `json:"ruling,omitempty"`
	ActorDID         string                                                                            `json:"actor_did,omitempty"`
	Limit            int                                                                               `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter
// narrows operator views across challenge-board evidence records.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter struct {
	CellID           string                                                                                `json:"cell_id,omitempty"`
	OrganizationID   string                                                                                `json:"organization_id,omitempty"`
	IncidentID       string                                                                                `json:"incident_id,omitempty"`
	ResponseID       string                                                                                `json:"response_id,omitempty"`
	DirectiveID      string                                                                                `json:"directive_id,omitempty"`
	ExtensionID      string                                                                                `json:"extension_id,omitempty"`
	DisputeID        string                                                                                `json:"dispute_id,omitempty"`
	AppealID         string                                                                                `json:"appeal_id,omitempty"`
	ComparisonKey    string                                                                                `json:"comparison_key,omitempty"`
	ChallengeID      string                                                                                `json:"challenge_id,omitempty"`
	Status           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus     `json:"status,omitempty"`
	Action           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType `json:"action,omitempty"`
	ChallengingParty SecureCellFederationIncidentResponseParty                                             `json:"challenging_party,omitempty"`
	BoardParty       SecureCellFederationIncidentResponseParty                                             `json:"board_party,omitempty"`
	Ruling           SecureCellFederationIncidentDirectiveExtensionAppealRuling                            `json:"ruling,omitempty"`
	ActorDID         string                                                                                `json:"actor_did,omitempty"`
	Limit            int                                                                                   `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord
// is the operator-facing evidence record for one reconciliation-board action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord struct {
	CellID                    string                                                                                          `json:"cell_id"`
	CellName                  string                                                                                          `json:"cell_name,omitempty"`
	CellStatus                SecureCellStatus                                                                                `json:"cell_status"`
	Jurisdiction              string                                                                                          `json:"jurisdiction,omitempty"`
	OrganizationID            string                                                                                          `json:"organization_id"`
	SponsorOfRecord           string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey             string                                                                                          `json:"comparison_key"`
	IncidentID                string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                string                                                                                          `json:"response_id,omitempty"`
	DirectiveID               string                                                                                          `json:"directive_id,omitempty"`
	ExtensionID               string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                 string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                  string                                                                                          `json:"appeal_id,omitempty"`
	LocalAppealID             string                                                                                          `json:"local_appeal_id,omitempty"`
	CounterpartySnapshotID    string                                                                                          `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID      string                                                                                          `json:"counterparty_bundle_id,omitempty"`
	CounterpartyAppealID      string                                                                                          `json:"counterparty_appeal_id,omitempty"`
	ChallengeID               string                                                                                          `json:"challenge_id"`
	ReconciliationStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	AttestationStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	ChallengeStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status"`
	Action                    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType           `json:"action"`
	ChallengingParty          SecureCellFederationIncidentResponseParty                                                       `json:"challenging_party,omitempty"`
	BoardParty                SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	BoardReviewThreshold      int                                                                                             `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                                                        `json:"eligible_board_reviewer_dids,omitempty"`
	BoardCommitteeMemberCount int                                                                                             `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount    int                                                                                             `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes     int                                                                                             `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount   int                                                                                             `json:"board_missing_quorum_count,omitempty"`
	BoardQuorumSatisfied      bool                                                                                            `json:"board_quorum_satisfied"`
	RatifyVoteCount           int                                                                                             `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount         int                                                                                             `json:"overturn_vote_count,omitempty"`
	Ruling                    SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"ruling,omitempty"`
	ChallengeSummary          string                                                                                          `json:"challenge_summary,omitempty"`
	ChallengeDescription      string                                                                                          `json:"challenge_description,omitempty"`
	RulingSummary             string                                                                                          `json:"ruling_summary,omitempty"`
	RulingDescription         string                                                                                          `json:"ruling_description,omitempty"`
	EvidenceIDs               []string                                                                                        `json:"evidence_ids,omitempty"`
	TransitionID              string                                                                                          `json:"transition_id,omitempty"`
	PolicyReceiptID           string                                                                                          `json:"policy_receipt_id,omitempty"`
	PolicyReceiptHash         string                                                                                          `json:"policy_receipt_hash,omitempty"`
	SealID                    string                                                                                          `json:"seal_id,omitempty"`
	TraceLinkID               string                                                                                          `json:"trace_link_id,omitempty"`
	ActorDID                  string                                                                                          `json:"actor_did,omitempty"`
	Reason                    string                                                                                          `json:"reason,omitempty"`
	Metadata                  map[string]string                                                                               `json:"metadata,omitempty"`
	OccurredAt                time.Time                                                                                       `json:"occurred_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary
// projects one bilateral challenge-board review for operator and auditor use.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary struct {
	CellID                    string                                                                                          `json:"cell_id"`
	CellName                  string                                                                                          `json:"cell_name,omitempty"`
	Jurisdiction              string                                                                                          `json:"jurisdiction,omitempty"`
	CellStatus                SecureCellStatus                                                                                `json:"cell_status"`
	OrganizationID            string                                                                                          `json:"organization_id"`
	SponsorOfRecord           string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName          string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey             string                                                                                          `json:"comparison_key"`
	IncidentID                string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                string                                                                                          `json:"response_id,omitempty"`
	DirectiveID               string                                                                                          `json:"directive_id,omitempty"`
	DirectiveTitle            string                                                                                          `json:"directive_title,omitempty"`
	ExtensionID               string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                 string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                  string                                                                                          `json:"appeal_id,omitempty"`
	LocalAppealID             string                                                                                          `json:"local_appeal_id,omitempty"`
	CounterpartySnapshotID    string                                                                                          `json:"counterparty_snapshot_id,omitempty"`
	CounterpartyBundleID      string                                                                                          `json:"counterparty_bundle_id,omitempty"`
	CounterpartyAppealID      string                                                                                          `json:"counterparty_appeal_id,omitempty"`
	ChallengeID               string                                                                                          `json:"challenge_id"`
	ReconciliationStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	AttestationStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	ChallengeStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status"`
	ChallengingParty          SecureCellFederationIncidentResponseParty                                                       `json:"challenging_party,omitempty"`
	BoardParty                SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	ChallengeSummary          string                                                                                          `json:"challenge_summary,omitempty"`
	ChallengeDescription      string                                                                                          `json:"challenge_description,omitempty"`
	EvidenceIDs               []string                                                                                        `json:"evidence_ids,omitempty"`
	BoardReviewThreshold      int                                                                                             `json:"board_review_threshold,omitempty"`
	EligibleBoardReviewerDIDs []string                                                                                        `json:"eligible_board_reviewer_dids,omitempty"`
	BoardCommitteeMemberCount int                                                                                             `json:"board_committee_member_count,omitempty"`
	BoardRecordedVoteCount    int                                                                                             `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes     int                                                                                             `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount   int                                                                                             `json:"board_missing_quorum_count,omitempty"`
	BoardQuorumSatisfied      bool                                                                                            `json:"board_quorum_satisfied"`
	RatifyVoteCount           int                                                                                             `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount         int                                                                                             `json:"overturn_vote_count,omitempty"`
	Ruling                    SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"ruling,omitempty"`
	RulingSummary             string                                                                                          `json:"ruling_summary,omitempty"`
	RulingDescription         string                                                                                          `json:"ruling_description,omitempty"`
	CreatedBy                 string                                                                                          `json:"created_by,omitempty"`
	CreatedAt                 time.Time                                                                                       `json:"created_at"`
	RuledBy                   string                                                                                          `json:"ruled_by,omitempty"`
	RuledAt                   *time.Time                                                                                      `json:"ruled_at,omitempty"`
	UpdatedAt                 time.Time                                                                                       `json:"updated_at"`
	ActionCount               int                                                                                             `json:"action_count"`
	Metadata                  map[string]string                                                                               `json:"metadata,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeState struct {
	summary SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary
	votes   map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling
}

func (s *Service) ChallengeFederationIncidentDirectiveExtensionAppealReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: service is required")
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
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, reconciliation.ResponseID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	challengingParty, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationActorParty(run, *response, actorDID, req.ChallengingParty)
	if err != nil {
		return nil, err
	}
	boardParty := secureCellFederationIncidentResponseOppositeParty(challengingParty)
	if boardParty == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: board party is required", ErrPolicyDenied)
	}
	reviewStatus := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(reconciliation)
	if reviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed && reviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusResolved {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: reconciliation %q must be disputed or resolved before board review can open", comparisonKey)
	}
	if strings.TrimSpace(reconciliation.CounterpartySnapshotID) == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: counterparty appeal evidence is required to challenge reconciliation %q", comparisonKey)
	}
	if latest := secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallenge(run, comparisonKey); latest != nil && latest.ChallengeStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: reconciliation %q already has an open challenge board review", comparisonKey)
	}

	eligibleReviewers := secureCellFederationIncidentDirectiveExtensionAppealEligibleReviewers(run, *response, boardParty, req.EligibleBoardReviewerDIDs)
	if len(eligibleReviewers) == 0 {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: no eligible board reviewers are available for reconciliation %q", ErrPolicyDenied, comparisonKey)
	}
	boardThreshold := normalizeSecureCellThreshold(req.BoardReviewThreshold)
	if boardThreshold > len(eligibleReviewers) {
		boardThreshold = len(eligibleReviewers)
	}

	now := time.Now().UTC()
	challengeID := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeID(reconciliation.ComparisonKey, actorDID, now, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeCount(run, reconciliation.ComparisonKey))
	summaryText := firstNonEmpty(strings.TrimSpace(req.Summary), "challenge bilateral appeal reconciliation posture")
	receipt, err := s.evaluateStage(ctx, run.request, "challenge_federation_incident_directive_extension_appeal_reconciliation", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                           reconciliation.OrganizationID,
		"federation_incident_id":                                                               reconciliation.IncidentID,
		"federation_incident_response_id":                                                      reconciliation.ResponseID,
		"federation_incident_directive_id":                                                     reconciliation.DirectiveID,
		"federation_incident_directive_extension_id":                                           reconciliation.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                   reconciliation.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                    reconciliation.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                    reconciliation.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":           challengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":       string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview),
		"federation_incident_directive_extension_appeal_reconciliation_challenging_party":      string(challengingParty),
		"federation_incident_directive_extension_appeal_reconciliation_board_party":            string(boardParty),
		"federation_incident_directive_extension_appeal_reconciliation_board_threshold":        fmt.Sprintf("%d", boardThreshold),
		"federation_incident_directive_extension_appeal_reconciliation_board_members":          strings.Join(eligibleReviewers, ","),
		"federation_incident_directive_extension_appeal_reconciliation_review":                 string(reviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_attestation_status":     string(secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(reconciliation)),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_summary":      summaryText,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_description":  strings.TrimSpace(req.Description),
		"federation_incident_directive_extension_appeal_reconciliation_challenge_evidence_ids": strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"federation_incident_directive_extension_local_appeal_id":                              reconciliation.LocalAppealID,
		"federation_counterparty_incident_directive_extension_appeal_snapshot_id":              reconciliation.CounterpartySnapshotID,
		"federation_counterparty_incident_directive_extension_appeal_bundle_id":                reconciliation.CounterpartyBundleID,
		"federation_counterparty_incident_directive_extension_appeal_id":                       reconciliation.CounterpartyAppealID,
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w", ErrPolicyDenied)
	}

	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_challenged", challengeID),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenged",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge",
		TargetDID:        challengeID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                            reconciliation.OrganizationID,
			"federation_sponsor_of_record":                                                          responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                          reconciliation.OrganizationName,
			"federation_incident_id":                                                                reconciliation.IncidentID,
			"federation_incident_response_id":                                                       reconciliation.ResponseID,
			"federation_incident_directive_id":                                                      reconciliation.DirectiveID,
			"federation_incident_directive_title":                                                   reconciliation.DirectiveTitle,
			"federation_incident_directive_extension_id":                                            reconciliation.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                    reconciliation.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                     reconciliation.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                     reconciliation.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                  string(reconciliation.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review":                  string(reviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":      string(secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(reconciliation)),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":            challengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":        string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview),
			"federation_incident_directive_extension_appeal_reconciliation_challenging_party":       string(challengingParty),
			"federation_incident_directive_extension_appeal_reconciliation_board_party":             string(boardParty),
			"federation_incident_directive_extension_appeal_reconciliation_board_threshold":         fmt.Sprintf("%d", boardThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_board_members":           strings.Join(eligibleReviewers, ","),
			"federation_incident_directive_extension_appeal_reconciliation_board_committee_members": fmt.Sprintf("%d", len(eligibleReviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_board_recorded_votes":    "0",
			"federation_incident_directive_extension_appeal_reconciliation_board_outstanding_votes": fmt.Sprintf("%d", len(eligibleReviewers)),
			"federation_incident_directive_extension_appeal_reconciliation_board_missing_quorum":    fmt.Sprintf("%d", boardThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_board_quorum_satisfied":  "false",
			"federation_incident_directive_extension_appeal_reconciliation_ratify_vote_count":       "0",
			"federation_incident_directive_extension_appeal_reconciliation_overturn_vote_count":     "0",
			"federation_incident_directive_extension_appeal_reconciliation_challenge_summary":       summaryText,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_description":   strings.TrimSpace(req.Description),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_evidence_ids":  strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
			"federation_incident_directive_extension_local_appeal_id":                               reconciliation.LocalAppealID,
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id":               reconciliation.CounterpartySnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":                 reconciliation.CounterpartyBundleID,
			"federation_counterparty_incident_directive_extension_appeal_id":                        reconciliation.CounterpartyAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) RuleFederationIncidentDirectiveExtensionAppealReconciliation(ctx context.Context, cellID string, comparisonKey string, req SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeRulingRequest) (*SecureCellResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: service is required")
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
	if challenge == nil || challenge.ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: reconciliation %q does not have a pending board review", comparisonKey)
	}
	responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, challenge.ResponseID)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(req.ActorDID), run.request.OwnerIdentity.AgentID())
	boardParty := secureCellNormalizedFederationIncidentResponseParty(req.BoardParty)
	if boardParty == "" {
		boardParty = challenge.BoardParty
	}
	if boardParty != challenge.BoardParty {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: invalid board party %q", ErrPolicyDenied, boardParty)
	}
	if !secureCellFederationIncidentResponsePartyAllowed(run, *response, actorDID, boardParty) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: actor %q is not permitted to rule on challenge %q", ErrPolicyDenied, actorDID, challenge.ChallengeID)
	}
	if len(challenge.EligibleBoardReviewerDIDs) > 0 && !secureCellStringSliceContains(challenge.EligibleBoardReviewerDIDs, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: actor %q is not an eligible board reviewer for challenge %q", ErrPolicyDenied, actorDID, challenge.ChallengeID)
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeHasVote(run, challenge.ChallengeID, actorDID) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: actor %q already voted on challenge %q", actorDID, challenge.ChallengeID)
	}
	ruling := secureCellNormalizedFederationIncidentDirectiveExtensionAppealRuling(req.Ruling)
	if ruling == "" {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: ruling is required")
	}

	ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeVoteCounts(run, challenge.ChallengeID)
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		ratifyVotes++
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		overturnVotes++
	}
	recordedVoteCount := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeVoteCount(run, challenge.ChallengeID) + 1
	memberCount := len(challenge.EligibleBoardReviewerDIDs)
	if memberCount == 0 {
		memberCount = recordedVoteCount
	}
	bestVoteCount := ratifyVotes
	if overturnVotes > bestVoteCount {
		bestVoteCount = overturnVotes
	}
	missingQuorumCount := challenge.BoardReviewThreshold - bestVoteCount
	if missingQuorumCount < 0 {
		missingQuorumCount = 0
	}
	outstandingVotes := memberCount - recordedVoteCount
	if outstandingVotes < 0 {
		outstandingVotes = 0
	}
	quorumSatisfied := bestVoteCount >= challenge.BoardReviewThreshold
	challengeStatus := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview
	action := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionVoteRecorded
	if quorumSatisfied {
		challengeStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusForRuling(ruling)
		action = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled
	}
	receipt, err := s.evaluateStage(ctx, run.request, "rule_federation_incident_directive_extension_appeal_reconciliation", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                            reconciliation.OrganizationID,
		"federation_incident_id":                                                                reconciliation.IncidentID,
		"federation_incident_response_id":                                                       reconciliation.ResponseID,
		"federation_incident_directive_id":                                                      reconciliation.DirectiveID,
		"federation_incident_directive_extension_id":                                            reconciliation.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                                    reconciliation.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                     reconciliation.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                     reconciliation.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_id":            challenge.ChallengeID,
		"federation_incident_directive_extension_appeal_reconciliation_challenge_status":        string(challengeStatus),
		"federation_incident_directive_extension_appeal_reconciliation_challenging_party":       string(challenge.ChallengingParty),
		"federation_incident_directive_extension_appeal_reconciliation_board_party":             string(challenge.BoardParty),
		"federation_incident_directive_extension_appeal_reconciliation_board_threshold":         fmt.Sprintf("%d", challenge.BoardReviewThreshold),
		"federation_incident_directive_extension_appeal_reconciliation_board_members":           strings.Join(challenge.EligibleBoardReviewerDIDs, ","),
		"federation_incident_directive_extension_appeal_reconciliation_board_recorded_votes":    fmt.Sprintf("%d", recordedVoteCount),
		"federation_incident_directive_extension_appeal_reconciliation_board_outstanding_votes": fmt.Sprintf("%d", outstandingVotes),
		"federation_incident_directive_extension_appeal_reconciliation_board_missing_quorum":    fmt.Sprintf("%d", missingQuorumCount),
		"federation_incident_directive_extension_appeal_reconciliation_board_quorum_satisfied":  fmt.Sprintf("%t", quorumSatisfied),
		"federation_incident_directive_extension_appeal_reconciliation_ratify_vote_count":       fmt.Sprintf("%d", ratifyVotes),
		"federation_incident_directive_extension_appeal_reconciliation_overturn_vote_count":     fmt.Sprintf("%d", overturnVotes),
		"federation_incident_directive_extension_appeal_reconciliation_review":                  string(reconciliation.ReviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_attestation_status":      string(reconciliation.AttestationStatus),
		"federation_incident_directive_extension_appeal_reconciliation_ruling":                  string(ruling),
		"federation_incident_directive_extension_appeal_reconciliation_ruling_summary":          strings.TrimSpace(req.RulingSummary),
		"federation_incident_directive_extension_appeal_reconciliation_ruling_description":      strings.TrimSpace(req.RulingDescription),
		"federation_incident_directive_extension_appeal_reconciliation_ruling_evidence_ids":     strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
		"transition_reason": strings.TrimSpace(req.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w", ErrPolicyDenied)
	}

	transitionSuffix := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeTransitionSuffix(action)
	transition := SecureCellTransition{
		ID:               transitionID(run.request, transitionSuffix, challenge.ChallengeID),
		Action:           "secure_cell." + transitionSuffix,
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation_challenge",
		TargetDID:        challenge.ChallengeID,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(req.Reason),
		Metadata: mergeStringMaps(req.Metadata, map[string]string{
			"federation_organization_id":                                                            reconciliation.OrganizationID,
			"federation_sponsor_of_record":                                                          responseSummary.SponsorOfRecord,
			"federation_organization_name":                                                          reconciliation.OrganizationName,
			"federation_incident_id":                                                                reconciliation.IncidentID,
			"federation_incident_response_id":                                                       reconciliation.ResponseID,
			"federation_incident_directive_id":                                                      reconciliation.DirectiveID,
			"federation_incident_directive_title":                                                   reconciliation.DirectiveTitle,
			"federation_incident_directive_extension_id":                                            reconciliation.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                                    reconciliation.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                     reconciliation.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                     reconciliation.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                  string(reconciliation.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review":                  string(reconciliation.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status":      string(reconciliation.AttestationStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenge_id":            challenge.ChallengeID,
			"federation_incident_directive_extension_appeal_reconciliation_challenge_status":        string(challengeStatus),
			"federation_incident_directive_extension_appeal_reconciliation_challenging_party":       string(challenge.ChallengingParty),
			"federation_incident_directive_extension_appeal_reconciliation_board_party":             string(challenge.BoardParty),
			"federation_incident_directive_extension_appeal_reconciliation_board_threshold":         fmt.Sprintf("%d", challenge.BoardReviewThreshold),
			"federation_incident_directive_extension_appeal_reconciliation_board_members":           strings.Join(challenge.EligibleBoardReviewerDIDs, ","),
			"federation_incident_directive_extension_appeal_reconciliation_board_committee_members": fmt.Sprintf("%d", memberCount),
			"federation_incident_directive_extension_appeal_reconciliation_board_recorded_votes":    fmt.Sprintf("%d", recordedVoteCount),
			"federation_incident_directive_extension_appeal_reconciliation_board_outstanding_votes": fmt.Sprintf("%d", outstandingVotes),
			"federation_incident_directive_extension_appeal_reconciliation_board_missing_quorum":    fmt.Sprintf("%d", missingQuorumCount),
			"federation_incident_directive_extension_appeal_reconciliation_board_quorum_satisfied":  fmt.Sprintf("%t", quorumSatisfied),
			"federation_incident_directive_extension_appeal_reconciliation_ratify_vote_count":       fmt.Sprintf("%d", ratifyVotes),
			"federation_incident_directive_extension_appeal_reconciliation_overturn_vote_count":     fmt.Sprintf("%d", overturnVotes),
			"federation_incident_directive_extension_appeal_reconciliation_ruling":                  string(ruling),
			"federation_incident_directive_extension_appeal_reconciliation_ruling_summary":          strings.TrimSpace(req.RulingSummary),
			"federation_incident_directive_extension_appeal_reconciliation_ruling_description":      strings.TrimSpace(req.RulingDescription),
			"federation_incident_directive_extension_appeal_reconciliation_ruling_evidence_ids":     strings.Join(uniqueTrimmedStrings(req.EvidenceIDs), ","),
			"federation_incident_directive_extension_local_appeal_id":                               reconciliation.LocalAppealID,
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id":               reconciliation.CounterpartySnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":                 reconciliation.CounterpartyBundleID,
			"federation_counterparty_incident_directive_extension_appeal_id":                        reconciliation.CounterpartyAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallenges(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(item, filter) {
				continue
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ChallengeID < items[j].ChallengeID
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

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFromTransition(run, transition)
			if !ok {
				continue
			}
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter(record, filter) {
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeID(comparisonKey string, actorDID string, createdAt time.Time, ordinal int) string {
	seed := fmt.Sprintf("%s|%s|%s|%d", strings.TrimSpace(comparisonKey), strings.TrimSpace(actorDID), createdAt.UTC().Format(time.RFC3339Nano), ordinal+1)
	return fmt.Sprintf("%x-appeal-reconciliation-challenge-%x", sha256.Sum256([]byte(strings.TrimSpace(comparisonKey))), sha256.Sum256([]byte(seed)))
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationActorParty(run *secureCellRun, response SecureCellFederationIncidentResponse, actorDID string, preferred SecureCellFederationIncidentResponseParty) (SecureCellFederationIncidentResponseParty, error) {
	preferred = secureCellNormalizedFederationIncidentResponseParty(preferred)
	if preferred != "" {
		if !secureCellFederationIncidentResponsePartyAllowed(run, response, actorDID, preferred) {
			return "", fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: actor %q is not permitted for party %q", ErrPolicyDenied, actorDID, preferred)
		}
		return preferred, nil
	}
	if secureCellFederationIncidentResponsePartyAllowed(run, response, actorDID, SecureCellFederationIncidentResponsePartyLocalOrg) {
		return SecureCellFederationIncidentResponsePartyLocalOrg, nil
	}
	if secureCellFederationIncidentResponsePartyAllowed(run, response, actorDID, SecureCellFederationIncidentResponsePartyCounterpartyOrg) {
		return SecureCellFederationIncidentResponsePartyCounterpartyOrg, nil
	}
	return "", fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge: %w: actor %q is not permitted to challenge reconciliation", ErrPolicyDenied, actorDID)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusForRuling(ruling SecureCellFederationIncidentDirectiveExtensionAppealRuling) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus {
	switch ruling {
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingRatify:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusRatified
	case SecureCellFederationIncidentDirectiveExtensionAppealRulingOverturn:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusOverturned
	default:
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFromTransition(run *secureCellRun, transition SecureCellTransition) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord, bool) {
	actionType, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionTypeFromTransitionAction(transition.Action)
	if !ok {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord{}, false
	}
	meta := cloneStringMap(transition.Metadata)
	record := SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord{
		CellID:                    safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.CellID) }),
		CellName:                  safeString(run.result, func(in *SecureCellResult) string { return strings.TrimSpace(in.Name) }),
		CellStatus:                safeSecureCellStatus(run),
		Jurisdiction:              safeString(run, func(in *secureCellRun) string { return strings.TrimSpace(in.request.Jurisdiction) }),
		OrganizationID:            strings.TrimSpace(meta["federation_organization_id"]),
		SponsorOfRecord:           strings.TrimSpace(meta["federation_sponsor_of_record"]),
		OrganizationName:          strings.TrimSpace(meta["federation_organization_name"]),
		ComparisonKey:             strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
		IncidentID:                strings.TrimSpace(meta["federation_incident_id"]),
		ResponseID:                strings.TrimSpace(meta["federation_incident_response_id"]),
		DirectiveID:               strings.TrimSpace(meta["federation_incident_directive_id"]),
		ExtensionID:               strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
		DisputeID:                 strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
		AppealID:                  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
		LocalAppealID:             strings.TrimSpace(meta["federation_incident_directive_extension_local_appeal_id"]),
		CounterpartySnapshotID:    strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_snapshot_id"]),
		CounterpartyBundleID:      strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_bundle_id"]),
		CounterpartyAppealID:      strings.TrimSpace(meta["federation_counterparty_incident_directive_extension_appeal_id"]),
		ChallengeID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
		ReconciliationStatus:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_status"])),
		ReviewStatus:              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review"])),
		AttestationStatus:         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_attestation_status"])),
		ChallengeStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_status"])),
		Action:                    actionType,
		ChallengingParty:          SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenging_party"])),
		BoardParty:                SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_board_party"])),
		BoardReviewThreshold:      secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_threshold"),
		EligibleBoardReviewerDIDs: uniqueTrimmedStrings(strings.Split(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_board_members"]), ",")),
		BoardCommitteeMemberCount: secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_committee_members"),
		BoardRecordedVoteCount:    secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_recorded_votes"),
		BoardOutstandingVotes:     secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_outstanding_votes"),
		BoardMissingQuorumCount:   secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_missing_quorum"),
		BoardQuorumSatisfied:      secureCellMetadataBool(meta, "federation_incident_directive_extension_appeal_reconciliation_board_quorum_satisfied"),
		RatifyVoteCount:           secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_ratify_vote_count"),
		OverturnVoteCount:         secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_overturn_vote_count"),
		Ruling:                    SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_ruling"])),
		ChallengeSummary:          strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_summary"]),
		ChallengeDescription:      strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_description"]),
		RulingSummary:             strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_ruling_summary"]),
		RulingDescription:         strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_ruling_description"]),
		EvidenceIDs:               uniqueTrimmedStrings(strings.Split(firstNonEmpty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_ruling_evidence_ids"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_evidence_ids"])), ",")),
		TransitionID:              strings.TrimSpace(transition.ID),
		ActorDID:                  strings.TrimSpace(transition.Actor),
		Reason:                    firstNonEmpty(strings.TrimSpace(transition.Reason), strings.TrimSpace(meta["transition_reason"])),
		Metadata:                  meta,
		OccurredAt:                transition.OccurredAt.UTC(),
	}
	if record.ChallengeStatus == "" {
		switch actionType {
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionChallenged:
			record.ChallengeStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview
		case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled:
			record.ChallengeStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusForRuling(record.Ruling)
		default:
			record.ChallengeStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview
		}
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionTypeFromTransitionAction(action string) (SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType, bool) {
	switch strings.TrimSpace(action) {
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_challenged":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionChallenged, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_vote_recorded":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionVoteRecorded, true
	case "secure_cell.federation_incident_directive_extension_appeal_reconciliation_ruled":
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled, true
	default:
		return "", false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeTransitionSuffix(action SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionType) string {
	switch action {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionChallenged:
		return "federation_incident_directive_extension_appeal_reconciliation_challenged"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionVoteRecorded:
		return "federation_incident_directive_extension_appeal_reconciliation_vote_recorded"
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled:
		return "federation_incident_directive_extension_appeal_reconciliation_ruled"
	default:
		return "federation_incident_directive_extension_appeal_reconciliation_challenge_updated"
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run *secureCellRun) []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary {
	if run == nil || run.result == nil {
		return nil
	}
	records := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord, 0)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFromTransition(run, transition)
		if !ok {
			continue
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].OccurredAt.Equal(records[j].OccurredAt) {
			return records[i].TransitionID < records[j].TransitionID
		}
		return records[i].OccurredAt.Before(records[j].OccurredAt)
	})
	states := make(map[string]*secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeState)
	order := make([]string, 0)
	for _, record := range records {
		challengeID := strings.TrimSpace(record.ChallengeID)
		if challengeID == "" {
			continue
		}
		state := states[challengeID]
		if state == nil {
			state = &secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeState{
				summary: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary{
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
					ExtensionID:               record.ExtensionID,
					DisputeID:                 record.DisputeID,
					AppealID:                  record.AppealID,
					LocalAppealID:             record.LocalAppealID,
					CounterpartySnapshotID:    record.CounterpartySnapshotID,
					CounterpartyBundleID:      record.CounterpartyBundleID,
					CounterpartyAppealID:      record.CounterpartyAppealID,
					ChallengeID:               challengeID,
					ReconciliationStatus:      record.ReconciliationStatus,
					ReviewStatus:              record.ReviewStatus,
					AttestationStatus:         record.AttestationStatus,
					ChallengeStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview,
					ChallengingParty:          record.ChallengingParty,
					BoardParty:                record.BoardParty,
					ChallengeSummary:          record.ChallengeSummary,
					ChallengeDescription:      record.ChallengeDescription,
					EvidenceIDs:               append([]string(nil), record.EvidenceIDs...),
					BoardReviewThreshold:      normalizeSecureCellThreshold(record.BoardReviewThreshold),
					EligibleBoardReviewerDIDs: append([]string(nil), record.EligibleBoardReviewerDIDs...),
					CreatedBy:                 record.ActorDID,
					CreatedAt:                 record.OccurredAt,
					UpdatedAt:                 record.OccurredAt,
					Metadata:                  cloneStringMap(record.Metadata),
				},
				votes: make(map[string]SecureCellFederationIncidentDirectiveExtensionAppealRuling),
			}
			if state.summary.BoardReviewThreshold > len(state.summary.EligibleBoardReviewerDIDs) && len(state.summary.EligibleBoardReviewerDIDs) > 0 {
				state.summary.BoardReviewThreshold = len(state.summary.EligibleBoardReviewerDIDs)
			}
			states[challengeID] = state
			order = append(order, challengeID)
		}
		state.summary.ReconciliationStatus = record.ReconciliationStatus
		state.summary.ReviewStatus = record.ReviewStatus
		state.summary.AttestationStatus = record.AttestationStatus
		state.summary.ActionCount++
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionChallenged {
			state.summary.ChallengeStatus = SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview
			state.summary.UpdatedAt = record.OccurredAt
			continue
		}
		if record.Ruling != "" && strings.TrimSpace(record.ActorDID) != "" {
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
		state.summary.BoardQuorumSatisfied = bestVoteCount >= state.summary.BoardReviewThreshold
		state.summary.UpdatedAt = record.OccurredAt
		if record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled {
			state.summary.ChallengeStatus = secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusForRuling(record.Ruling)
			state.summary.Ruling = record.Ruling
			state.summary.RulingSummary = record.RulingSummary
			state.summary.RulingDescription = record.RulingDescription
			state.summary.RuledBy = record.ActorDID
			ruledAt := record.OccurredAt.UTC()
			state.summary.RuledAt = &ruledAt
		}
	}
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, 0, len(states))
	for _, challengeID := range order {
		if state := states[challengeID]; state != nil {
			items = append(items, state.summary)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].UpdatedAt.Equal(items[j].UpdatedAt) {
			return items[i].ChallengeID > items[j].ChallengeID
		}
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	return items
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionsForComparisonKey(run *secureCellRun, comparisonKey string) []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord {
	if run == nil || run.result == nil {
		return nil
	}
	key := strings.TrimSpace(comparisonKey)
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord, 0)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFromTransition(run, transition)
		if !ok || !strings.EqualFold(strings.TrimSpace(record.ComparisonKey), key) {
			continue
		}
		items = append(items, record)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			return items[i].TransitionID > items[j].TransitionID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	return items
}

func secureCellLatestFederationIncidentDirectiveExtensionAppealReconciliationChallenge(run *secureCellRun, comparisonKey string) *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary {
	if run == nil || run.result == nil {
		return nil
	}
	key := strings.TrimSpace(comparisonKey)
	var latest *SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
		if !strings.EqualFold(strings.TrimSpace(item.ComparisonKey), key) {
			continue
		}
		current := item
		latest = &current
		break
	}
	return latest
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeCount(run *secureCellRun, comparisonKey string) int {
	total := 0
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ComparisonKey), strings.TrimSpace(comparisonKey)) {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusCount(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, status SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus) int {
	total := 0
	for _, item := range items {
		if item.ChallengeStatus == status {
			total++
		}
	}
	return total
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeVoteCounts(run *secureCellRun, challengeID string) (int, int) {
	ratifyVotes := 0
	overturnVotes := 0
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(challengeID)) {
			ratifyVotes = item.RatifyVoteCount
			overturnVotes = item.OverturnVoteCount
			break
		}
	}
	return ratifyVotes, overturnVotes
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeVoteCount(run *secureCellRun, challengeID string) int {
	for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
		if strings.EqualFold(strings.TrimSpace(item.ChallengeID), strings.TrimSpace(challengeID)) {
			return item.BoardRecordedVoteCount
		}
	}
	return 0
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeHasVote(run *secureCellRun, challengeID string, actorDID string) bool {
	if run == nil || run.result == nil {
		return false
	}
	challengeID = strings.TrimSpace(challengeID)
	actorDID = strings.TrimSpace(actorDID)
	for _, transition := range run.result.Transitions {
		record, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFromTransition(run, transition)
		if !ok || !strings.EqualFold(strings.TrimSpace(record.ChallengeID), challengeID) {
			continue
		}
		if (record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionVoteRecorded || record.Action == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRuled) && strings.EqualFold(strings.TrimSpace(record.ActorDID), actorDID) {
			return true
		}
	}
	return false
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter) bool {
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
	if filter.Status != "" && item.ChallengeStatus != filter.Status {
		return false
	}
	if filter.ChallengingParty != "" && item.ChallengingParty != filter.ChallengingParty {
		return false
	}
	if filter.BoardParty != "" && item.BoardParty != filter.BoardParty {
		return false
	}
	if filter.Ruling != "" && item.Ruling != filter.Ruling {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.CreatedBy), strings.TrimSpace(filter.ActorDID)) && !strings.EqualFold(strings.TrimSpace(item.RuledBy), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionRecord, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeActionFilter) bool {
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
	if filter.Status != "" && item.ChallengeStatus != filter.Status {
		return false
	}
	if filter.Action != "" && item.Action != filter.Action {
		return false
	}
	if filter.ChallengingParty != "" && item.ChallengingParty != filter.ChallengingParty {
		return false
	}
	if filter.BoardParty != "" && item.BoardParty != filter.BoardParty {
		return false
	}
	if filter.Ruling != "" && item.Ruling != filter.Ruling {
		return false
	}
	if filter.ActorDID != "" && !strings.EqualFold(strings.TrimSpace(item.ActorDID), strings.TrimSpace(filter.ActorDID)) {
		return false
	}
	return true
}
