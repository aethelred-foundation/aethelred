package securecells

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeBoardReviewSLA = 12 * time.Hour

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueState struct {
	pendingAction    string
	automationAction string
	overdueReason    string
	dueAt            time.Time
	boardReviewDueAt *time.Time
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan struct {
	action        string
	trigger       string
	reason        string
	pendingAction string
	dueAt         time.Time
	tierID        string
	targetDID     string
	targetSource  string
}

// SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter
// narrows operator queries across overdue challenge-board reviews.
type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter struct {
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
	Before           *time.Time                                                                        `json:"before,omitempty"`
	Limit            int                                                                               `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge
// projects one overdue bilateral challenge-board review.
type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge struct {
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
	ChallengeID               string                                                                                          `json:"challenge_id"`
	ReconciliationStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status"`
	ReviewStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	AttestationStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	ChallengeStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status"`
	ChallengingParty          SecureCellFederationIncidentResponseParty                                                       `json:"challenging_party,omitempty"`
	BoardParty                SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	PendingAction             string                                                                                          `json:"pending_action"`
	AutomationAction          string                                                                                          `json:"automation_action"`
	OverdueReason             string                                                                                          `json:"overdue_reason"`
	BoardReviewThreshold      int                                                                                             `json:"board_review_threshold,omitempty"`
	BoardCommitteeMemberCount int                                                                                             `json:"board_committee_member_count,omitempty"`
	BoardDelegationCount      int                                                                                             `json:"board_delegation_count,omitempty"`
	BoardRecordedVoteCount    int                                                                                             `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes     int                                                                                             `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount   int                                                                                             `json:"board_missing_quorum_count,omitempty"`
	BoardQuorumSatisfied      bool                                                                                            `json:"board_quorum_satisfied"`
	RatifyVoteCount           int                                                                                             `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount         int                                                                                             `json:"overturn_vote_count,omitempty"`
	Ruling                    SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"ruling,omitempty"`
	TierID                    string                                                                                          `json:"tier_id,omitempty"`
	TargetDID                 string                                                                                          `json:"target_did,omitempty"`
	DueAt                     time.Time                                                                                       `json:"due_at"`
	OverdueSeconds            int64                                                                                           `json:"overdue_seconds"`
	BoardReviewDueAt          *time.Time                                                                                      `json:"board_review_due_at,omitempty"`
	CreatedBy                 string                                                                                          `json:"created_by,omitempty"`
	CreatedAt                 time.Time                                                                                       `json:"created_at"`
	UpdatedAt                 time.Time                                                                                       `json:"updated_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter
// narrows operator queries over automated challenge-board actions.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	ExtensionID    string     `json:"extension_id,omitempty"`
	DisputeID      string     `json:"dispute_id,omitempty"`
	AppealID       string     `json:"appeal_id,omitempty"`
	ComparisonKey  string     `json:"comparison_key,omitempty"`
	ChallengeID    string     `json:"challenge_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord
// projects one automated challenge-board delegation, escalation, or containment
// action.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord struct {
	CellID                    string                                                                                          `json:"cell_id"`
	CellName                  string                                                                                          `json:"cell_name,omitempty"`
	Jurisdiction              string                                                                                          `json:"jurisdiction,omitempty"`
	CellStatus                SecureCellStatus                                                                                `json:"cell_status"`
	OrganizationID            string                                                                                          `json:"organization_id,omitempty"`
	SponsorOfRecord           string                                                                                          `json:"sponsor_of_record,omitempty"`
	ComparisonKey             string                                                                                          `json:"comparison_key,omitempty"`
	IncidentID                string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                string                                                                                          `json:"response_id,omitempty"`
	DirectiveID               string                                                                                          `json:"directive_id,omitempty"`
	DirectiveTitle            string                                                                                          `json:"directive_title,omitempty"`
	ExtensionID               string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                 string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                  string                                                                                          `json:"appeal_id,omitempty"`
	ChallengeID               string                                                                                          `json:"challenge_id,omitempty"`
	ReconciliationStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status,omitempty"`
	ReviewStatus              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status,omitempty"`
	AttestationStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status,omitempty"`
	ChallengeStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus               `json:"challenge_status,omitempty"`
	ChallengingParty          SecureCellFederationIncidentResponseParty                                                       `json:"challenging_party,omitempty"`
	BoardParty                SecureCellFederationIncidentResponseParty                                                       `json:"board_party,omitempty"`
	PendingAction             string                                                                                          `json:"pending_action,omitempty"`
	BoardReviewThreshold      int                                                                                             `json:"board_review_threshold,omitempty"`
	BoardCommitteeMemberCount int                                                                                             `json:"board_committee_member_count,omitempty"`
	BoardDelegationCount      int                                                                                             `json:"board_delegation_count,omitempty"`
	BoardRecordedVoteCount    int                                                                                             `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes     int                                                                                             `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount   int                                                                                             `json:"board_missing_quorum_count,omitempty"`
	BoardQuorumSatisfied      bool                                                                                            `json:"board_quorum_satisfied"`
	RatifyVoteCount           int                                                                                             `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount         int                                                                                             `json:"overturn_vote_count,omitempty"`
	Ruling                    SecureCellFederationIncidentDirectiveExtensionAppealRuling                                      `json:"ruling,omitempty"`
	ContractID                string                                                                                          `json:"contract_id,omitempty"`
	ContractStatusBefore      SecureCellFederationContractStatus                                                              `json:"contract_status_before,omitempty"`
	ContractStatusAfter       SecureCellFederationContractStatus                                                              `json:"contract_status_after,omitempty"`
	Action                    string                                                                                          `json:"action"`
	Trigger                   string                                                                                          `json:"trigger,omitempty"`
	TierID                    string                                                                                          `json:"tier_id,omitempty"`
	TargetDID                 string                                                                                          `json:"target_did,omitempty"`
	DueAt                     *time.Time                                                                                      `json:"due_at,omitempty"`
	Actor                     string                                                                                          `json:"actor"`
	AutomatedActor            string                                                                                          `json:"automated_actor,omitempty"`
	Reason                    string                                                                                          `json:"reason,omitempty"`
	TransitionID              string                                                                                          `json:"transition_id"`
	OccurredAt                time.Time                                                                                       `json:"occurred_at"`
	Metadata                  map[string]string                                                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSweepResult
// summarizes one automated challenge-board sweep.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	ChallengesScanned  int       `json:"challenges_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	CommitteesExpanded int       `json:"committees_expanded"`
	ResponsesEscalated int       `json:"responses_escalated"`
	ContractsSuspended int       `json:"contracts_suspended"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}

// ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenges
// returns operator-facing projections for challenge-board reviews whose
// governed deadline has elapsed.
func (s *Service) ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenges(_ context.Context, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter) ([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, challenge := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationFilter(challenge, filter) {
				continue
			}
			overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueStateForAt(challenge, at)
			if !ok {
				continue
			}
			responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, challenge.ResponseID)
			if err != nil {
				return nil, err
			}
			plan, _ := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlanFromRun(run, *response, challenge, at)
			automationAction := overdue.automationAction
			tierID := ""
			targetDID := ""
			if plan.action != "" {
				automationAction = plan.action
				tierID = plan.tierID
				targetDID = plan.targetDID
			}
			items = append(items, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallenge{
				CellID:                    challenge.CellID,
				CellName:                  challenge.CellName,
				Jurisdiction:              challenge.Jurisdiction,
				CellStatus:                challenge.CellStatus,
				OrganizationID:            challenge.OrganizationID,
				SponsorOfRecord:           responseSummary.SponsorOfRecord,
				OrganizationName:          challenge.OrganizationName,
				ComparisonKey:             challenge.ComparisonKey,
				IncidentID:                challenge.IncidentID,
				ResponseID:                challenge.ResponseID,
				DirectiveID:               challenge.DirectiveID,
				DirectiveTitle:            challenge.DirectiveTitle,
				ExtensionID:               challenge.ExtensionID,
				DisputeID:                 challenge.DisputeID,
				AppealID:                  challenge.AppealID,
				ChallengeID:               challenge.ChallengeID,
				ReconciliationStatus:      challenge.ReconciliationStatus,
				ReviewStatus:              challenge.ReviewStatus,
				AttestationStatus:         challenge.AttestationStatus,
				ChallengeStatus:           challenge.ChallengeStatus,
				ChallengingParty:          challenge.ChallengingParty,
				BoardParty:                challenge.BoardParty,
				PendingAction:             overdue.pendingAction,
				AutomationAction:          automationAction,
				OverdueReason:             overdue.overdueReason,
				BoardReviewThreshold:      challenge.BoardReviewThreshold,
				BoardCommitteeMemberCount: challenge.BoardCommitteeMemberCount,
				BoardDelegationCount:      challenge.BoardDelegationCount,
				BoardRecordedVoteCount:    challenge.BoardRecordedVoteCount,
				BoardOutstandingVotes:     challenge.BoardOutstandingVotes,
				BoardMissingQuorumCount:   challenge.BoardMissingQuorumCount,
				BoardQuorumSatisfied:      challenge.BoardQuorumSatisfied,
				RatifyVoteCount:           challenge.RatifyVoteCount,
				OverturnVoteCount:         challenge.OverturnVoteCount,
				Ruling:                    challenge.Ruling,
				TierID:                    tierID,
				TargetDID:                 targetDID,
				DueAt:                     overdue.dueAt,
				OverdueSeconds:            int64(at.Sub(overdue.dueAt).Seconds()),
				BoardReviewDueAt:          cloneTimePtr(overdue.boardReviewDueAt),
				CreatedBy:                 challenge.CreatedBy,
				CreatedAt:                 challenge.CreatedAt.UTC(),
				UpdatedAt:                 challenge.UpdatedAt.UTC(),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ChallengeID < items[j].ChallengeID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].DueAt.Before(items[j].DueAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions
// returns automated challenge-board governance actions already applied by the runtime.
func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var since time.Time
	if filter.Since != nil && !filter.Since.IsZero() {
		since = filter.Since.UTC()
	}
	var until time.Time
	if filter.Until != nil && !filter.Until.IsZero() {
		until = filter.Until.UTC()
	}
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAction(transition) {
				continue
			}
			if filter.Action != "" && !strings.EqualFold(strings.TrimSpace(transition.Action), strings.TrimSpace(filter.Action)) {
				continue
			}
			meta := transition.Metadata
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_organization_id"]), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_id"]), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_response_id"]), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_id"]), strings.TrimSpace(filter.DirectiveID)) {
				continue
			}
			if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_id"]), strings.TrimSpace(filter.ExtensionID)) {
				continue
			}
			if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]), strings.TrimSpace(filter.DisputeID)) {
				continue
			}
			if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]), strings.TrimSpace(filter.AppealID)) {
				continue
			}
			if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]), strings.TrimSpace(filter.ComparisonKey)) {
				continue
			}
			if filter.ChallengeID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]), strings.TrimSpace(filter.ChallengeID)) {
				continue
			}
			if filter.ContractID != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_contract_id"]), strings.TrimSpace(filter.ContractID)) {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			items = append(items, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationActionRecord{
				CellID:                    run.result.CellID,
				CellName:                  run.result.Name,
				Jurisdiction:              run.request.Jurisdiction,
				CellStatus:                run.result.Status,
				OrganizationID:            strings.TrimSpace(meta["federation_organization_id"]),
				SponsorOfRecord:           strings.TrimSpace(meta["federation_sponsor_of_record"]),
				ComparisonKey:             strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_key"]),
				IncidentID:                strings.TrimSpace(meta["federation_incident_id"]),
				ResponseID:                strings.TrimSpace(meta["federation_incident_response_id"]),
				DirectiveID:               strings.TrimSpace(meta["federation_incident_directive_id"]),
				DirectiveTitle:            strings.TrimSpace(meta["federation_incident_directive_title"]),
				ExtensionID:               strings.TrimSpace(meta["federation_incident_directive_extension_id"]),
				DisputeID:                 strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
				AppealID:                  strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
				ChallengeID:               strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
				ReconciliationStatus:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_status"])),
				ReviewStatus:              SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review"])),
				AttestationStatus:         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_attestation_status"])),
				ChallengeStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_status"])),
				ChallengingParty:          SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenging_party"])),
				BoardParty:                SecureCellFederationIncidentResponseParty(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_board_party"])),
				PendingAction:             strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_pending_action"]),
				BoardReviewThreshold:      secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_threshold"),
				BoardCommitteeMemberCount: secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_committee_members"),
				BoardDelegationCount:      secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_delegation_count"),
				BoardRecordedVoteCount:    secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_recorded_votes"),
				BoardOutstandingVotes:     secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_outstanding_votes"),
				BoardMissingQuorumCount:   secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_board_missing_quorum"),
				BoardQuorumSatisfied:      secureCellMetadataBool(meta, "federation_incident_directive_extension_appeal_reconciliation_board_quorum_satisfied"),
				RatifyVoteCount:           secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_ratify_vote_count"),
				OverturnVoteCount:         secureCellMetadataInt(meta, "federation_incident_directive_extension_appeal_reconciliation_overturn_vote_count"),
				Ruling:                    SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_ruling"])),
				ContractID:                strings.TrimSpace(meta["federation_contract_id"]),
				ContractStatusBefore:      SecureCellFederationContractStatus(strings.TrimSpace(meta["federation_contract_status_before"])),
				ContractStatusAfter:       SecureCellFederationContractStatus(strings.TrimSpace(meta["federation_contract_status_after"])),
				Action:                    transition.Action,
				Trigger:                   strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_trigger"]),
				TierID:                    strings.TrimSpace(meta["federation_incident_response_tier_id"]),
				TargetDID:                 firstNonEmpty(strings.TrimSpace(meta["federation_incident_response_target_did"]), strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_challenge_delegated_to"]), strings.TrimSpace(meta["decision_route_target"])),
				DueAt:                     parseSecureCellTransitionDueAtWithKey(meta, "federation_incident_directive_extension_appeal_reconciliation_challenge_due_at"),
				Actor:                     transition.Actor,
				AutomatedActor:            strings.TrimSpace(meta["automated_actor"]),
				Reason:                    transition.Reason,
				TransitionID:              transition.ID,
				OccurredAt:                occurredAt,
				Metadata:                  cloneStringMap(meta),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].OccurredAt.Equal(items[j].OccurredAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].TransitionID > items[j].TransitionID
			}
			return items[i].CellID < items[j].CellID
		}
		return items[i].OccurredAt.After(items[j].OccurredAt)
	})
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

// SweepFederationIncidentDirectiveExtensionAppealReconciliationChallenges applies
// automated committee expansion, response escalation, or fail-closed contract
// suspension to overdue challenge-board reviews.
func (s *Service) SweepFederationIncidentDirectiveExtensionAppealReconciliationChallenges(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-automation: service is required")
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

	report := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutatedCells := make(map[string]struct{})
	escalatedResponses := make(map[string]struct{})
	suspendedOrgs := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		challenges := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengesFromRun(run)
		report.ChallengesScanned += len(challenges)
		for _, challenge := range challenges {
			plan, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlanFromRun(run, SecureCellFederationIncidentResponse{}, challenge, at)
			if !ok {
				continue
			}
			responseSummary, _, err := secureCellFederationIncidentResponseSummaryAndRef(run, challenge.ResponseID)
			if err != nil {
				return nil, err
			}
			if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationAlreadyApplied(run, challenge.ChallengeID, challenge.ChallengeStatus, plan.pendingAction, plan.action, plan.targetDID) {
				continue
			}

			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_challenge_sweep_mode":     "automated",
				"federation_incident_directive_extension_appeal_reconciliation_challenge_action":         plan.action,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_trigger":        plan.trigger,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_pending_action": plan.pendingAction,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_due_at":         plan.dueAt.UTC().Format(time.RFC3339Nano),
				"federation_organization_id":                                                            challenge.OrganizationID,
				"federation_sponsor_of_record":                                                          responseSummary.SponsorOfRecord,
				"federation_incident_id":                                                                challenge.IncidentID,
				"federation_incident_response_id":                                                       challenge.ResponseID,
				"federation_incident_directive_id":                                                      challenge.DirectiveID,
				"federation_incident_directive_title":                                                   challenge.DirectiveTitle,
				"federation_incident_directive_extension_id":                                            challenge.ExtensionID,
				"federation_incident_directive_extension_dispute_id":                                    challenge.DisputeID,
				"federation_incident_directive_extension_appeal_id":                                     challenge.AppealID,
				"federation_incident_directive_extension_local_appeal_id":                               challenge.LocalAppealID,
				"federation_counterparty_incident_directive_extension_appeal_snapshot_id":               challenge.CounterpartySnapshotID,
				"federation_counterparty_incident_directive_extension_appeal_bundle_id":                 challenge.CounterpartyBundleID,
				"federation_counterparty_incident_directive_extension_appeal_id":                        challenge.CounterpartyAppealID,
				"federation_incident_directive_extension_appeal_reconciliation_key":                     challenge.ComparisonKey,
				"federation_incident_directive_extension_appeal_reconciliation_status":                  string(challenge.ReconciliationStatus),
				"federation_incident_directive_extension_appeal_reconciliation_review":                  string(challenge.ReviewStatus),
				"federation_incident_directive_extension_appeal_reconciliation_attestation_status":      string(challenge.AttestationStatus),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_id":            challenge.ChallengeID,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_status":        string(challenge.ChallengeStatus),
				"federation_incident_directive_extension_appeal_reconciliation_challenging_party":       string(challenge.ChallengingParty),
				"federation_incident_directive_extension_appeal_reconciliation_board_party":             string(challenge.BoardParty),
				"federation_incident_directive_extension_appeal_reconciliation_board_threshold":         strconv.Itoa(challenge.BoardReviewThreshold),
				"federation_incident_directive_extension_appeal_reconciliation_board_members":           strings.Join(challenge.EligibleBoardReviewerDIDs, ","),
				"federation_incident_directive_extension_appeal_reconciliation_board_committee_members": strconv.Itoa(challenge.BoardCommitteeMemberCount),
				"federation_incident_directive_extension_appeal_reconciliation_board_delegation_count":  strconv.Itoa(challenge.BoardDelegationCount),
				"federation_incident_directive_extension_appeal_reconciliation_board_recorded_votes":    strconv.Itoa(challenge.BoardRecordedVoteCount),
				"federation_incident_directive_extension_appeal_reconciliation_board_outstanding_votes": strconv.Itoa(challenge.BoardOutstandingVotes),
				"federation_incident_directive_extension_appeal_reconciliation_board_missing_quorum":    strconv.Itoa(challenge.BoardMissingQuorumCount),
				"federation_incident_directive_extension_appeal_reconciliation_board_quorum_satisfied":  strconv.FormatBool(challenge.BoardQuorumSatisfied),
				"federation_incident_directive_extension_appeal_reconciliation_ratify_vote_count":       strconv.Itoa(challenge.RatifyVoteCount),
				"federation_incident_directive_extension_appeal_reconciliation_overturn_vote_count":     strconv.Itoa(challenge.OverturnVoteCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_summary":       challenge.ChallengeSummary,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_description":   challenge.ChallengeDescription,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_evidence_ids":  strings.Join(challenge.EvidenceIDs, ","),
			})
			if plan.targetSource != "" {
				baseMetadata["federation_incident_directive_extension_appeal_reconciliation_challenge_target_source"] = plan.targetSource
			}
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				baseMetadata["automated_actor"] = automatedActor
			}

			switch plan.action {
			case "delegate_review_committee":
				if _, err := s.DelegateFederationIncidentDirectiveExtensionAppealReconciliationChallengeReview(ctx, cellID, challenge.ChallengeID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
					ActorDID:  run.request.OwnerIdentity.AgentID(),
					TargetDID: plan.targetDID,
					Reason:    firstNonEmpty(strings.TrimSpace(lifecycle.Reason), plan.reason),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_incident_response_tier_id":                                                 plan.tierID,
						"federation_incident_response_target_did":                                              plan.targetDID,
						"federation_incident_directive_extension_appeal_reconciliation_challenge_delegated_to": plan.targetDID,
					}),
				}); err != nil {
					return nil, err
				}
				report.CommitteesExpanded++
				mutatedCells[cellID] = struct{}{}
			case "escalate_response":
				responseKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(challenge.ResponseID)
				if _, seen := escalatedResponses[responseKey]; seen {
					continue
				}
				if _, err := s.EscalateFederationIncidentResponse(ctx, cellID, challenge.ResponseID, SecureCellFederationIncidentResponseEscalateRequest{
					ActorDID: run.request.OwnerIdentity.AgentID(),
					TierID:   plan.tierID,
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), plan.reason),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_incident_response_tier_id":    plan.tierID,
						"federation_incident_response_target_did": plan.targetDID,
					}),
				}); err != nil {
					return nil, err
				}
				escalatedResponses[responseKey] = struct{}{}
				report.ResponsesEscalated++
				mutatedCells[cellID] = struct{}{}
			case "suspend_contracts":
				orgKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(challenge.OrganizationID)
				if _, seen := suspendedOrgs[orgKey]; seen {
					continue
				}
				activeContracts := activeFederationContractsForOrganization(run.result.FederationContracts, challenge.OrganizationID)
				if len(activeContracts) == 0 {
					continue
				}
				for _, contract := range activeContracts {
					if _, err := s.SuspendFederationContract(ctx, cellID, contract.ID, SecureCellLifecycleRequest{
						ActorDID: run.request.OwnerIdentity.AgentID(),
						Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), plan.reason),
						Metadata: mergeStringMaps(baseMetadata, map[string]string{
							"federation_contract_id":            contract.ID,
							"federation_contract_status_before": string(contract.Status),
							"federation_contract_status_after":  string(SecureCellFederationContractStatusSuspended),
						}),
					}); err != nil {
						return nil, err
					}
					report.ContractsSuspended++
				}
				suspendedOrgs[orgKey] = struct{}{}
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueStateForAt(challenge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueState, bool) {
	if challenge.ChallengeStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview || challenge.CreatedAt.IsZero() {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueState{}, false
	}
	boardReviewDueAt := challenge.CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeBoardReviewSLA)
	if boardReviewDueAt.After(at) {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueState{}, false
	}
	return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueState{
		pendingAction:    "board_review",
		automationAction: "escalate_response",
		overdueReason:    "appeal reconciliation challenge-board review deadline reached",
		dueAt:            boardReviewDueAt.UTC(),
		boardReviewDueAt: cloneTimePtr(&boardReviewDueAt),
	}, true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeUsesCommitteeGovernance(challenge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary) bool {
	return normalizeSecureCellThreshold(challenge.BoardReviewThreshold) > 1 || len(uniqueTrimmedStrings(challenge.EligibleBoardReviewerDIDs)) > 0 || challenge.BoardDelegationCount > 0
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlanFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, challenge SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan, bool) {
	if run == nil || run.result == nil {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{}, false
	}
	if strings.TrimSpace(response.ID) == "" {
		_, responseRef, err := secureCellFederationIncidentResponseSummaryAndRef(run, challenge.ResponseID)
		if err != nil {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{}, false
		}
		response = *responseRef
	}
	overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeOverdueStateForAt(challenge, at)
	if !ok {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{}, false
	}
	if challenge.ChallengeStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatusPendingBoardReview && secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeUsesCommitteeGovernance(challenge) {
		excluded := append([]string(nil), uniqueTrimmedStrings(challenge.EligibleBoardReviewerDIDs)...)
		if targetDID, tierID, targetSource := secureCellFederationIncidentDirectiveExtensionCommitteeTarget(run, response, challenge.BoardParty, excluded); targetDID != "" {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{
				action:        "delegate_review_committee",
				trigger:       overdue.pendingAction + "_due",
				reason:        "appeal reconciliation challenge-board quorum deadline reached",
				pendingAction: overdue.pendingAction,
				dueAt:         overdue.dueAt,
				tierID:        tierID,
				targetDID:     targetDID,
				targetSource:  targetSource,
			}, true
		}
	}
	if tier, ok := secureCellNextFederationIncidentResponseEscalationTier(response); ok {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{
			action:        "escalate_response",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.overdueReason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
			tierID:        strings.TrimSpace(tier.TierID),
			targetDID:     strings.TrimSpace(tier.TargetDID),
		}, true
	}
	if len(activeFederationContractsForOrganization(run.result.FederationContracts, challenge.OrganizationID)) > 0 {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{
			action:        "suspend_contracts",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.overdueReason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
		}, true
	}
	return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationPlan{}, false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationAlreadyApplied(run *secureCellRun, challengeID string, challengeStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus, pendingAction string, action string, targetDID string) bool {
	if run == nil || run.result == nil {
		return false
	}
	challengeID = strings.TrimSpace(challengeID)
	pendingAction = strings.TrimSpace(pendingAction)
	action = strings.TrimSpace(action)
	targetDID = strings.TrimSpace(targetDID)
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAction(transition) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]), challengeID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_pending_action"]), pendingAction) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_action"]), action) {
			continue
		}
		if targetDID != "" && action == "delegate_review_committee" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_delegated_to"]), targetDID) {
			continue
		}
		if SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_status"])) != challengeStatus {
			continue
		}
		return true
	}
	return false
}

func secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAction(transition SecureCellTransition) bool {
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_sweep_mode"]), "automated")
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAutomationFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeSummary, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeFilter) bool {
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
	return true
}
