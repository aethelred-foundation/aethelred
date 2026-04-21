package securecells

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBoardReviewSLA     = 24 * time.Hour
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgementSLA = 12 * time.Hour
)

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState struct {
	pendingAction string
	action        string
	reason        string
	dueAt         time.Time
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan struct {
	action        string
	trigger       string
	reason        string
	pendingAction string
	dueAt         time.Time
	tierID        string
	targetDID     string
	targetSource  string
}

type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter struct {
	CellID            string                                                                                  `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                  `json:"organization_id,omitempty"`
	IncidentID        string                                                                                  `json:"incident_id,omitempty"`
	ResponseID        string                                                                                  `json:"response_id,omitempty"`
	DirectiveID       string                                                                                  `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                  `json:"extension_id,omitempty"`
	DisputeID         string                                                                                  `json:"dispute_id,omitempty"`
	AppealID          string                                                                                  `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                  `json:"comparison_key,omitempty"`
	ChallengeID       string                                                                                  `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                  `json:"challenge_appeal_id,omitempty"`
	Status            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"status,omitempty"`
	Before            *time.Time                                                                              `json:"before,omitempty"`
	Limit             int                                                                                     `json:"limit,omitempty"`
}

type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal struct {
	CellID                          string                                                                                  `json:"cell_id"`
	CellName                        string                                                                                  `json:"cell_name,omitempty"`
	Jurisdiction                    string                                                                                  `json:"jurisdiction,omitempty"`
	CellStatus                      SecureCellStatus                                                                        `json:"cell_status"`
	OrganizationID                  string                                                                                  `json:"organization_id"`
	SponsorOfRecord                 string                                                                                  `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                  `json:"organization_name,omitempty"`
	ComparisonKey                   string                                                                                  `json:"comparison_key"`
	IncidentID                      string                                                                                  `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                  `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                  `json:"directive_id,omitempty"`
	DirectiveTitle                  string                                                                                  `json:"directive_title,omitempty"`
	ExtensionID                     string                                                                                  `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                  `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                  `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                  `json:"challenge_id"`
	ChallengeAppealID               string                                                                                  `json:"challenge_appeal_id"`
	ChallengeStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus       `json:"challenge_status"`
	ChallengeRuling                 SecureCellFederationIncidentDirectiveExtensionAppealRuling                              `json:"challenge_ruling,omitempty"`
	ChallengeAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"challenge_appeal_status"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                               `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                               `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                               `json:"enforcement_acknowledgement_party,omitempty"`
	PendingAction                   string                                                                                  `json:"pending_action"`
	AutomationAction                string                                                                                  `json:"automation_action"`
	OverdueReason                   string                                                                                  `json:"overdue_reason"`
	BoardReviewThreshold            int                                                                                     `json:"board_review_threshold,omitempty"`
	BoardCommitteeMemberCount       int                                                                                     `json:"board_committee_member_count,omitempty"`
	BoardDelegationCount            int                                                                                     `json:"board_delegation_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                     `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                     `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                     `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                    `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                     `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                     `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                              `json:"ruling,omitempty"`
	TierID                          string                                                                                  `json:"tier_id,omitempty"`
	TargetDID                       string                                                                                  `json:"target_did,omitempty"`
	DueAt                           time.Time                                                                               `json:"due_at"`
	OverdueSeconds                  int64                                                                                   `json:"overdue_seconds"`
	CreatedAt                       time.Time                                                                               `json:"created_at"`
	RuledAt                         *time.Time                                                                              `json:"ruled_at,omitempty"`
	UpdatedAt                       time.Time                                                                               `json:"updated_at"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter struct {
	CellID            string     `json:"cell_id,omitempty"`
	OrganizationID    string     `json:"organization_id,omitempty"`
	IncidentID        string     `json:"incident_id,omitempty"`
	ResponseID        string     `json:"response_id,omitempty"`
	DirectiveID       string     `json:"directive_id,omitempty"`
	ExtensionID       string     `json:"extension_id,omitempty"`
	DisputeID         string     `json:"dispute_id,omitempty"`
	AppealID          string     `json:"appeal_id,omitempty"`
	ComparisonKey     string     `json:"comparison_key,omitempty"`
	ChallengeID       string     `json:"challenge_id,omitempty"`
	ChallengeAppealID string     `json:"challenge_appeal_id,omitempty"`
	ContractID        string     `json:"contract_id,omitempty"`
	Action            string     `json:"action,omitempty"`
	Since             *time.Time `json:"since,omitempty"`
	Until             *time.Time `json:"until,omitempty"`
	Limit             int        `json:"limit,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord struct {
	CellID                          string                                                                                  `json:"cell_id"`
	CellName                        string                                                                                  `json:"cell_name,omitempty"`
	Jurisdiction                    string                                                                                  `json:"jurisdiction,omitempty"`
	CellStatus                      SecureCellStatus                                                                        `json:"cell_status"`
	OrganizationID                  string                                                                                  `json:"organization_id,omitempty"`
	SponsorOfRecord                 string                                                                                  `json:"sponsor_of_record,omitempty"`
	OrganizationName                string                                                                                  `json:"organization_name,omitempty"`
	ComparisonKey                   string                                                                                  `json:"comparison_key,omitempty"`
	IncidentID                      string                                                                                  `json:"incident_id,omitempty"`
	ResponseID                      string                                                                                  `json:"response_id,omitempty"`
	DirectiveID                     string                                                                                  `json:"directive_id,omitempty"`
	DirectiveTitle                  string                                                                                  `json:"directive_title,omitempty"`
	ExtensionID                     string                                                                                  `json:"extension_id,omitempty"`
	DisputeID                       string                                                                                  `json:"dispute_id,omitempty"`
	AppealID                        string                                                                                  `json:"appeal_id,omitempty"`
	ChallengeID                     string                                                                                  `json:"challenge_id,omitempty"`
	ChallengeAppealID               string                                                                                  `json:"challenge_appeal_id,omitempty"`
	ChallengeStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus       `json:"challenge_status,omitempty"`
	ChallengeRuling                 SecureCellFederationIncidentDirectiveExtensionAppealRuling                              `json:"challenge_ruling,omitempty"`
	ChallengeAppealStatus           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus `json:"challenge_appeal_status,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                                               `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                                               `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                                               `json:"enforcement_acknowledgement_party,omitempty"`
	PendingAction                   string                                                                                  `json:"pending_action,omitempty"`
	BoardReviewThreshold            int                                                                                     `json:"board_review_threshold,omitempty"`
	BoardCommitteeMemberCount       int                                                                                     `json:"board_committee_member_count,omitempty"`
	BoardDelegationCount            int                                                                                     `json:"board_delegation_count,omitempty"`
	BoardRecordedVoteCount          int                                                                                     `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                                                     `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                                                     `json:"board_missing_quorum_count,omitempty"`
	BoardThresholdSatisfied         bool                                                                                    `json:"board_threshold_satisfied"`
	RatifyVoteCount                 int                                                                                     `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                                                     `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling                              `json:"ruling,omitempty"`
	ContractID                      string                                                                                  `json:"contract_id,omitempty"`
	ContractStatusBefore            SecureCellFederationContractStatus                                                      `json:"contract_status_before,omitempty"`
	ContractStatusAfter             SecureCellFederationContractStatus                                                      `json:"contract_status_after,omitempty"`
	Action                          string                                                                                  `json:"action"`
	Trigger                         string                                                                                  `json:"trigger,omitempty"`
	TierID                          string                                                                                  `json:"tier_id,omitempty"`
	TargetDID                       string                                                                                  `json:"target_did,omitempty"`
	DueAt                           *time.Time                                                                              `json:"due_at,omitempty"`
	Actor                           string                                                                                  `json:"actor"`
	AutomatedActor                  string                                                                                  `json:"automated_actor,omitempty"`
	Reason                          string                                                                                  `json:"reason,omitempty"`
	TransitionID                    string                                                                                  `json:"transition_id"`
	OccurredAt                      time.Time                                                                               `json:"occurred_at"`
	Metadata                        map[string]string                                                                       `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	AppealsScanned     int       `json:"appeals_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	CommitteesExpanded int       `json:"committees_expanded"`
	ResponsesEscalated int       `json:"responses_escalated"`
	ContractsSuspended int       `json:"contracts_suspended"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}

func (s *Service) ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(_ context.Context, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter) ([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueFilter(item, filter) {
				continue
			}
			overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueStateForAt(item, at)
			if !ok {
				continue
			}
			responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, item.ResponseID)
			if err != nil {
				return nil, err
			}
			plan, _ := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlanFromRun(run, *response, item, at)
			automationAction := overdue.action
			tierID := ""
			targetDID := ""
			if plan.action != "" {
				automationAction = plan.action
				tierID = plan.tierID
				targetDID = plan.targetDID
			}
			items = append(items, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeal{
				CellID:                          item.CellID,
				CellName:                        item.CellName,
				Jurisdiction:                    item.Jurisdiction,
				CellStatus:                      item.CellStatus,
				OrganizationID:                  item.OrganizationID,
				SponsorOfRecord:                 responseSummary.SponsorOfRecord,
				OrganizationName:                item.OrganizationName,
				ComparisonKey:                   item.ComparisonKey,
				IncidentID:                      item.IncidentID,
				ResponseID:                      item.ResponseID,
				DirectiveID:                     item.DirectiveID,
				DirectiveTitle:                  item.DirectiveTitle,
				ExtensionID:                     item.ExtensionID,
				DisputeID:                       item.DisputeID,
				AppealID:                        item.AppealID,
				ChallengeID:                     item.ChallengeID,
				ChallengeAppealID:               item.ChallengeAppealID,
				ChallengeStatus:                 item.ChallengeStatus,
				ChallengeRuling:                 item.ChallengeRuling,
				ChallengeAppealStatus:           item.ChallengeAppealStatus,
				AppealingParty:                  item.AppealingParty,
				BoardParty:                      item.BoardParty,
				EnforcementAcknowledgementParty: item.EnforcementAcknowledgementParty,
				PendingAction:                   overdue.pendingAction,
				AutomationAction:                automationAction,
				OverdueReason:                   overdue.reason,
				BoardReviewThreshold:            item.BoardReviewThreshold,
				BoardCommitteeMemberCount:       item.BoardCommitteeMemberCount,
				BoardDelegationCount:            item.BoardDelegationCount,
				BoardRecordedVoteCount:          item.BoardRecordedVoteCount,
				BoardOutstandingVotes:           item.BoardOutstandingVotes,
				BoardMissingQuorumCount:         item.BoardMissingQuorumCount,
				BoardThresholdSatisfied:         item.BoardThresholdSatisfied,
				RatifyVoteCount:                 item.RatifyVoteCount,
				OverturnVoteCount:               item.OverturnVoteCount,
				Ruling:                          item.Ruling,
				TierID:                          tierID,
				TargetDID:                       targetDID,
				DueAt:                           overdue.dueAt,
				OverdueSeconds:                  int64(at.Sub(overdue.dueAt).Seconds()),
				CreatedAt:                       item.CreatedAt.UTC(),
				RuledAt:                         cloneTimePtr(item.RuledAt),
				UpdatedAt:                       item.UpdatedAt.UTC(),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ChallengeAppealID < items[j].ChallengeAppealID
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

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	incidentID := strings.TrimSpace(filter.IncidentID)
	responseID := strings.TrimSpace(filter.ResponseID)
	directiveID := strings.TrimSpace(filter.DirectiveID)
	extensionID := strings.TrimSpace(filter.ExtensionID)
	disputeID := strings.TrimSpace(filter.DisputeID)
	appealID := strings.TrimSpace(filter.AppealID)
	comparisonKey := strings.TrimSpace(filter.ComparisonKey)
	challengeID := strings.TrimSpace(filter.ChallengeID)
	challengeAppealID := strings.TrimSpace(filter.ChallengeAppealID)
	contractID := strings.TrimSpace(filter.ContractID)
	action := strings.TrimSpace(filter.Action)
	var since time.Time
	if filter.Since != nil && !filter.Since.IsZero() {
		since = filter.Since.UTC()
	}
	var until time.Time
	if filter.Until != nil && !filter.Until.IsZero() {
		until = filter.Until.UTC()
	}

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(transition) {
				continue
			}
			if action != "" && !strings.EqualFold(strings.TrimSpace(transition.Action), action) {
				continue
			}
			data := transition.Metadata
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_organization_id"]), organizationID) {
				continue
			}
			if incidentID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_id"]), incidentID) {
				continue
			}
			if responseID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_response_id"]), responseID) {
				continue
			}
			if directiveID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_id"]), directiveID) {
				continue
			}
			if extensionID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_id"]), extensionID) {
				continue
			}
			if disputeID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_dispute_id"]), disputeID) {
				continue
			}
			if appealID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_id"]), appealID) {
				continue
			}
			if comparisonKey != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_key"]), comparisonKey) {
				continue
			}
			if challengeID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]), challengeID) {
				continue
			}
			if challengeAppealID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]), challengeAppealID) {
				continue
			}
			if contractID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_contract_id"]), contractID) {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			items = append(items, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord{
				CellID:                          strings.TrimSpace(run.result.CellID),
				CellName:                        strings.TrimSpace(run.result.Name),
				Jurisdiction:                    strings.TrimSpace(run.request.Jurisdiction),
				CellStatus:                      run.result.Status,
				OrganizationID:                  strings.TrimSpace(data["federation_organization_id"]),
				SponsorOfRecord:                 strings.TrimSpace(data["federation_sponsor_of_record"]),
				OrganizationName:                strings.TrimSpace(data["federation_organization_name"]),
				ComparisonKey:                   strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_key"]),
				IncidentID:                      strings.TrimSpace(data["federation_incident_id"]),
				ResponseID:                      strings.TrimSpace(data["federation_incident_response_id"]),
				DirectiveID:                     strings.TrimSpace(data["federation_incident_directive_id"]),
				DirectiveTitle:                  strings.TrimSpace(data["federation_incident_directive_title"]),
				ExtensionID:                     strings.TrimSpace(data["federation_incident_directive_extension_id"]),
				DisputeID:                       strings.TrimSpace(data["federation_incident_directive_extension_dispute_id"]),
				AppealID:                        strings.TrimSpace(data["federation_incident_directive_extension_appeal_id"]),
				ChallengeID:                     strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
				ChallengeAppealID:               strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
				ChallengeStatus:                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeStatus(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_status"])),
				ChallengeRuling:                 SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_ruling"])),
				ChallengeAppealStatus:           SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])),
				AppealingParty:                  SecureCellFederationIncidentResponseParty(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party"])),
				BoardParty:                      SecureCellFederationIncidentResponseParty(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party"])),
				EnforcementAcknowledgementParty: SecureCellFederationIncidentResponseParty(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party"])),
				PendingAction:                   strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_pending_action"]),
				BoardReviewThreshold:            secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold"),
				BoardCommitteeMemberCount:       secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members"),
				BoardDelegationCount:            secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_delegation_count"),
				BoardRecordedVoteCount:          secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes"),
				BoardOutstandingVotes:           secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes"),
				BoardMissingQuorumCount:         secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum"),
				BoardThresholdSatisfied:         secureCellMetadataBool(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied"),
				RatifyVoteCount:                 secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count"),
				OverturnVoteCount:               secureCellMetadataInt(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count"),
				Ruling:                          SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling"])),
				ContractID:                      strings.TrimSpace(data["federation_contract_id"]),
				ContractStatusBefore:            SecureCellFederationContractStatus(strings.TrimSpace(data["federation_contract_status_before"])),
				ContractStatusAfter:             SecureCellFederationContractStatus(strings.TrimSpace(data["federation_contract_status_after"])),
				Action:                          transition.Action,
				Trigger:                         strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_trigger"]),
				TierID:                          strings.TrimSpace(data["federation_incident_response_tier_id"]),
				TargetDID:                       firstNonEmpty(strings.TrimSpace(data["federation_incident_response_target_did"]), strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_delegated_to"])),
				DueAt:                           parseSecureCellTransitionDueAtWithKey(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_due_at"),
				Actor:                           transition.Actor,
				AutomatedActor:                  strings.TrimSpace(data["automated_actor"]),
				Reason:                          strings.TrimSpace(transition.Reason),
				TransitionID:                    strings.TrimSpace(transition.ID),
				OccurredAt:                      occurredAt,
				Metadata:                        cloneStringMap(data),
			})
		}
	}
	reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActions(items)
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) SweepFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppeals(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-automation: service is required")
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

	report := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSweepResult{
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
		appeals := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealsFromRun(run)
		report.AppealsScanned += len(appeals)
		for _, appeal := range appeals {
			overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueStateForAt(appeal, at)
			if !ok {
				continue
			}
			responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, appeal.ResponseID)
			if err != nil {
				return nil, err
			}
			plan, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlanFromRun(run, *response, appeal, at)
			if !ok {
				continue
			}
			if secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationAlreadyApplied(run, appeal.ChallengeAppealID, appeal.ChallengeAppealStatus, overdue.pendingAction, plan.action, plan.targetDID) {
				continue
			}

			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_sweep_mode":                "automated",
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_action":                    plan.action,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_trigger":                   plan.trigger,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_pending_action":            plan.pendingAction,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_due_at":                    plan.dueAt.UTC().Format(time.RFC3339Nano),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                        appeal.ChallengeAppealID,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":                    string(appeal.ChallengeAppealStatus),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_party":               string(appeal.BoardParty),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ack_party":                 string(appeal.EnforcementAcknowledgementParty),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold":           strconv.Itoa(appeal.BoardReviewThreshold),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_committee_members":   strconv.Itoa(appeal.BoardCommitteeMemberCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_delegation_count":    strconv.Itoa(appeal.BoardDelegationCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_recorded_votes":      strconv.Itoa(appeal.BoardRecordedVoteCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_outstanding_votes":   strconv.Itoa(appeal.BoardOutstandingVotes),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_missing_quorum":      strconv.Itoa(appeal.BoardMissingQuorumCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_board_threshold_satisfied": strconv.FormatBool(appeal.BoardThresholdSatisfied),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ratify_vote_count":         strconv.Itoa(appeal.RatifyVoteCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_overturn_vote_count":       strconv.Itoa(appeal.OverturnVoteCount),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_ruling":                    string(appeal.Ruling),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appealing_party":                  string(appeal.AppealingParty),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                               appeal.ChallengeID,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_status":                           string(appeal.ChallengeStatus),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_ruling":                           string(appeal.ChallengeRuling),
				"federation_incident_directive_extension_appeal_reconciliation_key":                                        appeal.ComparisonKey,
				"federation_incident_directive_extension_appeal_id":                                                        appeal.AppealID,
				"federation_incident_directive_extension_dispute_id":                                                       appeal.DisputeID,
				"federation_incident_directive_extension_id":                                                               appeal.ExtensionID,
				"federation_incident_directive_id":                                                                         appeal.DirectiveID,
				"federation_incident_directive_title":                                                                      appeal.DirectiveTitle,
				"federation_incident_response_id":                                                                          appeal.ResponseID,
				"federation_organization_id":                                                                               appeal.OrganizationID,
				"federation_organization_name":                                                                             appeal.OrganizationName,
				"federation_sponsor_of_record":                                                                             responseSummary.SponsorOfRecord,
				"federation_incident_id":                                                                                   appeal.IncidentID,
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				baseMetadata["automated_actor"] = automatedActor
			}
			if plan.targetSource != "" {
				baseMetadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_target_source"] = plan.targetSource
			}

			switch plan.action {
			case "delegate_review_committee":
				if _, err := s.DelegateFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealReview(ctx, cellID, appeal.ChallengeAppealID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
					ActorDID:  run.request.OwnerIdentity.AgentID(),
					TargetDID: plan.targetDID,
					Reason:    firstNonEmpty(strings.TrimSpace(lifecycle.Reason), plan.reason),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_incident_response_tier_id":                                                        plan.tierID,
						"federation_incident_response_target_did":                                                     plan.targetDID,
						"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_delegated_to": plan.targetDID,
					}),
				}); err != nil {
					return nil, err
				}
				report.CommitteesExpanded++
				mutatedCells[cellID] = struct{}{}
			case "escalate_response":
				responseKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(appeal.ResponseID) + "|" + plan.pendingAction
				if _, seen := escalatedResponses[responseKey]; seen {
					continue
				}
				if _, err := s.EscalateFederationIncidentResponse(ctx, cellID, appeal.ResponseID, SecureCellFederationIncidentResponseEscalateRequest{
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
				orgKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(appeal.OrganizationID) + "|" + plan.pendingAction
				if _, seen := suspendedOrgs[orgKey]; seen {
					continue
				}
				activeContracts := activeFederationContractsForOrganization(run.result.FederationContracts, appeal.OrganizationID)
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueStateForAt(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState, bool) {
	switch appeal.ChallengeAppealStatus {
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview:
		if appeal.CreatedAt.IsZero() {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{}, false
		}
		dueAt := appeal.CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealBoardReviewSLA)
		if dueAt.After(at) {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{}, false
		}
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{
			pendingAction: "board_review",
			action:        "escalate_response",
			reason:        "reconciliation challenge appeal board-review deadline reached",
			dueAt:         dueAt.UTC(),
		}, true
	case SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusRatified, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusOverturned:
		if appeal.RuledAt == nil || appeal.RuledAt.IsZero() {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{}, false
		}
		dueAt := appeal.RuledAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAcknowledgementSLA)
		if dueAt.After(at) {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{}, false
		}
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{
			pendingAction: "acknowledge_enforcement",
			action:        "escalate_response",
			reason:        "reconciliation challenge appeal enforcement acknowledgement deadline reached",
			dueAt:         dueAt.UTC(),
		}, true
	default:
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueState{}, false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealUsesCommitteeGovernance(appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary) bool {
	return normalizeSecureCellThreshold(appeal.BoardReviewThreshold) > 1 || len(uniqueTrimmedStrings(appeal.EligibleBoardReviewerDIDs)) > 0 || appeal.BoardDelegationCount > 0 || appeal.BoardRecusalCount > 0
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlanFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, appeal SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan, bool) {
	if run == nil || run.result == nil {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan{}, false
	}
	overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueStateForAt(appeal, at)
	if !ok {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan{}, false
	}
	if appeal.ChallengeAppealStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusPendingBoardReview && secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealUsesCommitteeGovernance(appeal) {
		excluded := append([]string(nil), uniqueTrimmedStrings(appeal.EligibleBoardReviewerDIDs)...)
		excluded = append(excluded, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecordedVoterDIDs(run, appeal.ChallengeAppealID)...)
		excluded = append(excluded, secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealRecusedReviewerDIDs(run, appeal.ChallengeAppealID)...)
		if targetDID, tierID, targetSource := secureCellFederationIncidentDirectiveExtensionCommitteeTarget(run, response, appeal.BoardParty, excluded); targetDID != "" {
			return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan{
				action:        "delegate_review_committee",
				trigger:       overdue.pendingAction + "_due",
				reason:        "reconciliation challenge appeal-board quorum deadline reached",
				pendingAction: overdue.pendingAction,
				dueAt:         overdue.dueAt,
				tierID:        tierID,
				targetDID:     targetDID,
				targetSource:  targetSource,
			}, true
		}
	}
	if tier, ok := secureCellNextFederationIncidentResponseEscalationTier(response); ok {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan{
			action:        "escalate_response",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.reason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
			tierID:        strings.TrimSpace(tier.TierID),
			targetDID:     strings.TrimSpace(tier.TargetDID),
		}, true
	}
	if len(activeFederationContractsForOrganization(run.result.FederationContracts, appeal.OrganizationID)) > 0 {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan{
			action:        "suspend_contracts",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.reason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
		}, true
	}
	return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationPlan{}, false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationAlreadyApplied(run *secureCellRun, challengeAppealID string, challengeAppealStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus, pendingAction string, action string, targetDID string) bool {
	if run == nil || run.result == nil {
		return false
	}
	challengeAppealID = strings.TrimSpace(challengeAppealID)
	pendingAction = strings.TrimSpace(pendingAction)
	action = strings.TrimSpace(action)
	targetDID = strings.TrimSpace(targetDID)
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(transition) {
			continue
		}
		data := transition.Metadata
		if !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]), challengeAppealID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_pending_action"]), pendingAction) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_action"]), action) {
			continue
		}
		if targetDID != "" && action == "delegate_review_committee" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_delegated_to"]), targetDID) {
			continue
		}
		if SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])) != challengeAppealStatus {
			continue
		}
		return true
	}
	return false
}

func secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAction(transition SecureCellTransition) bool {
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_sweep_mode"]), "automated")
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealOverdueFilter(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealFilter) bool {
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
	return true
}

func reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActions(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAutomationActionRecord) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}
