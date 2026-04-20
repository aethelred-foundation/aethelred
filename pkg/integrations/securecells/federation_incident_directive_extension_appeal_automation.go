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
	secureCellFederationIncidentDirectiveExtensionAppealBoardReviewSLA     = 24 * time.Hour
	secureCellFederationIncidentDirectiveExtensionAppealAcknowledgementSLA = 12 * time.Hour
)

type secureCellFederationIncidentDirectiveExtensionAppealOverdueState struct {
	pendingAction    string
	automationAction string
	overdueReason    string
	dueAt            time.Time
	boardReviewDueAt *time.Time
	enforcementDueAt *time.Time
}

type secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan struct {
	action        string
	trigger       string
	reason        string
	pendingAction string
	dueAt         time.Time
	tierID        string
	targetDID     string
	targetSource  string
}

// SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter narrows
// operator queries over overdue appeal-board or enforcement steps.
type SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter struct {
	CellID         string                                                     `json:"cell_id,omitempty"`
	OrganizationID string                                                     `json:"organization_id,omitempty"`
	IncidentID     string                                                     `json:"incident_id,omitempty"`
	ResponseID     string                                                     `json:"response_id,omitempty"`
	DirectiveID    string                                                     `json:"directive_id,omitempty"`
	ExtensionID    string                                                     `json:"extension_id,omitempty"`
	DisputeID      string                                                     `json:"dispute_id,omitempty"`
	AppealID       string                                                     `json:"appeal_id,omitempty"`
	Status         SecureCellFederationIncidentDirectiveExtensionAppealStatus `json:"status,omitempty"`
	Before         *time.Time                                                 `json:"before,omitempty"`
	Limit          int                                                        `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentDirectiveExtensionAppeal projects one
// bilateral appeal review or enforcement acknowledgement whose governed
// deadline has elapsed.
type SecureCellOverdueFederationIncidentDirectiveExtensionAppeal struct {
	CellID                          string                                                      `json:"cell_id"`
	CellName                        string                                                      `json:"cell_name,omitempty"`
	Jurisdiction                    string                                                      `json:"jurisdiction,omitempty"`
	CellStatus                      SecureCellStatus                                            `json:"cell_status"`
	ResponseID                      string                                                      `json:"response_id"`
	OrganizationID                  string                                                      `json:"organization_id"`
	SponsorOfRecord                 string                                                      `json:"sponsor_of_record,omitempty"`
	IncidentID                      string                                                      `json:"incident_id"`
	DirectiveID                     string                                                      `json:"directive_id"`
	DirectiveTitle                  string                                                      `json:"directive_title"`
	DirectiveStatus                 SecureCellFederationIncidentDirectiveStatus                 `json:"directive_status"`
	ExtensionID                     string                                                      `json:"extension_id"`
	ExtensionStatus                 SecureCellFederationIncidentDirectiveExtensionStatus        `json:"extension_status"`
	DisputeID                       string                                                      `json:"dispute_id"`
	DisputeStatus                   SecureCellFederationIncidentDirectiveExtensionDisputeStatus `json:"dispute_status"`
	AppealID                        string                                                      `json:"appeal_id"`
	AppealStatus                    SecureCellFederationIncidentDirectiveExtensionAppealStatus  `json:"appeal_status"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                   `json:"appealing_party"`
	BoardParty                      SecureCellFederationIncidentResponseParty                   `json:"board_party"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                   `json:"enforcement_acknowledgement_party"`
	PendingAction                   string                                                      `json:"pending_action"`
	AutomationAction                string                                                      `json:"automation_action"`
	OverdueReason                   string                                                      `json:"overdue_reason"`
	BoardReviewThreshold            int                                                         `json:"board_review_threshold,omitempty"`
	BoardCommitteeMemberCount       int                                                         `json:"board_committee_member_count,omitempty"`
	BoardDelegationCount            int                                                         `json:"board_delegation_count,omitempty"`
	BoardRecordedVoteCount          int                                                         `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                         `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                         `json:"board_missing_quorum_count,omitempty"`
	BoardQuorumSatisfied            bool                                                        `json:"board_quorum_satisfied"`
	RatifyVoteCount                 int                                                         `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                         `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling  `json:"ruling,omitempty"`
	TierID                          string                                                      `json:"tier_id,omitempty"`
	TargetDID                       string                                                      `json:"target_did,omitempty"`
	DueAt                           time.Time                                                   `json:"due_at"`
	OverdueSeconds                  int64                                                       `json:"overdue_seconds"`
	BoardReviewDueAt                *time.Time                                                  `json:"board_review_due_at,omitempty"`
	EnforcementAcknowledgementDueAt *time.Time                                                  `json:"enforcement_acknowledgement_due_at,omitempty"`
	RuledAt                         *time.Time                                                  `json:"ruled_at,omitempty"`
	UpdatedAt                       time.Time                                                   `json:"updated_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter
// narrows operator queries over automated appeal-board governance actions.
type SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	ExtensionID    string     `json:"extension_id,omitempty"`
	DisputeID      string     `json:"dispute_id,omitempty"`
	AppealID       string     `json:"appeal_id,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord
// projects one automated appeal-board delegation, escalation, or containment
// step applied because bilateral appeal governance breached a deadline.
type SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord struct {
	CellID                          string                                                      `json:"cell_id"`
	CellName                        string                                                      `json:"cell_name,omitempty"`
	Jurisdiction                    string                                                      `json:"jurisdiction,omitempty"`
	CellStatus                      SecureCellStatus                                            `json:"cell_status"`
	OrganizationID                  string                                                      `json:"organization_id,omitempty"`
	SponsorOfRecord                 string                                                      `json:"sponsor_of_record,omitempty"`
	IncidentID                      string                                                      `json:"incident_id,omitempty"`
	ResponseID                      string                                                      `json:"response_id,omitempty"`
	DirectiveID                     string                                                      `json:"directive_id,omitempty"`
	DirectiveTitle                  string                                                      `json:"directive_title,omitempty"`
	DirectiveStatus                 SecureCellFederationIncidentDirectiveStatus                 `json:"directive_status,omitempty"`
	ExtensionID                     string                                                      `json:"extension_id,omitempty"`
	ExtensionStatus                 SecureCellFederationIncidentDirectiveExtensionStatus        `json:"extension_status,omitempty"`
	DisputeID                       string                                                      `json:"dispute_id,omitempty"`
	DisputeStatus                   SecureCellFederationIncidentDirectiveExtensionDisputeStatus `json:"dispute_status,omitempty"`
	AppealID                        string                                                      `json:"appeal_id,omitempty"`
	AppealStatus                    SecureCellFederationIncidentDirectiveExtensionAppealStatus  `json:"appeal_status,omitempty"`
	AppealingParty                  SecureCellFederationIncidentResponseParty                   `json:"appealing_party,omitempty"`
	BoardParty                      SecureCellFederationIncidentResponseParty                   `json:"board_party,omitempty"`
	EnforcementAcknowledgementParty SecureCellFederationIncidentResponseParty                   `json:"enforcement_acknowledgement_party,omitempty"`
	PendingAction                   string                                                      `json:"pending_action,omitempty"`
	BoardReviewThreshold            int                                                         `json:"board_review_threshold,omitempty"`
	BoardCommitteeMemberCount       int                                                         `json:"board_committee_member_count,omitempty"`
	BoardDelegationCount            int                                                         `json:"board_delegation_count,omitempty"`
	BoardRecordedVoteCount          int                                                         `json:"board_recorded_vote_count,omitempty"`
	BoardOutstandingVotes           int                                                         `json:"board_outstanding_votes,omitempty"`
	BoardMissingQuorumCount         int                                                         `json:"board_missing_quorum_count,omitempty"`
	BoardQuorumSatisfied            bool                                                        `json:"board_quorum_satisfied"`
	RatifyVoteCount                 int                                                         `json:"ratify_vote_count,omitempty"`
	OverturnVoteCount               int                                                         `json:"overturn_vote_count,omitempty"`
	Ruling                          SecureCellFederationIncidentDirectiveExtensionAppealRuling  `json:"ruling,omitempty"`
	ContractID                      string                                                      `json:"contract_id,omitempty"`
	ContractStatusBefore            SecureCellFederationContractStatus                          `json:"contract_status_before,omitempty"`
	ContractStatusAfter             SecureCellFederationContractStatus                          `json:"contract_status_after,omitempty"`
	Action                          string                                                      `json:"action"`
	Trigger                         string                                                      `json:"trigger,omitempty"`
	TierID                          string                                                      `json:"tier_id,omitempty"`
	TargetDID                       string                                                      `json:"target_did,omitempty"`
	DueAt                           *time.Time                                                  `json:"due_at,omitempty"`
	Actor                           string                                                      `json:"actor"`
	AutomatedActor                  string                                                      `json:"automated_actor,omitempty"`
	Reason                          string                                                      `json:"reason,omitempty"`
	TransitionID                    string                                                      `json:"transition_id"`
	OccurredAt                      time.Time                                                   `json:"occurred_at"`
	Metadata                        map[string]string                                           `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealSweepResult summarizes
// one automated appeal-board governance sweep across the live secure-cell
// fleet.
type SecureCellFederationIncidentDirectiveExtensionAppealSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	AppealsScanned     int       `json:"appeals_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	CommitteesExpanded int       `json:"committees_expanded"`
	ResponsesEscalated int       `json:"responses_escalated"`
	ContractsSuspended int       `json:"contracts_suspended"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}

// ListOverdueFederationIncidentDirectiveExtensionAppeals returns operator-
// facing projections for appeal-board or enforcement steps whose governed
// deadline has elapsed.
func (s *Service) ListOverdueFederationIncidentDirectiveExtensionAppeals(_ context.Context, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealFilter) ([]SecureCellOverdueFederationIncidentDirectiveExtensionAppeal, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentDirectiveExtensionAppeal, 0)
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
			for _, directive := range response.IncidentDirectives {
				if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(directive.ID), strings.TrimSpace(filter.DirectiveID)) {
					continue
				}
				for _, extension := range directive.Extensions {
					if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(extension.ID), strings.TrimSpace(filter.ExtensionID)) {
						continue
					}
					for _, dispute := range extension.Disputes {
						if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(dispute.ID), strings.TrimSpace(filter.DisputeID)) {
							continue
						}
						for _, appeal := range dispute.Appeals {
							if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(appeal.ID), strings.TrimSpace(filter.AppealID)) {
								continue
							}
							if filter.Status != "" && appeal.Status != filter.Status {
								continue
							}
							overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealOverdueStateForAt(appeal, at)
							if !ok {
								continue
							}
							plan, _ := secureCellFederationIncidentDirectiveExtensionAppealAutomationPlanFromRun(run, response, directive, extension, dispute, appeal, at)
							committeeState := secureCellFederationIncidentDirectiveExtensionAppealCommitteeSnapshot(appeal)
							ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(appeal)
							automationAction := overdue.automationAction
							tierID := ""
							targetDID := ""
							if plan.action != "" {
								automationAction = plan.action
								tierID = plan.tierID
								targetDID = plan.targetDID
							}
							items = append(items, SecureCellOverdueFederationIncidentDirectiveExtensionAppeal{
								CellID:                          strings.TrimSpace(run.result.CellID),
								CellName:                        strings.TrimSpace(run.result.Name),
								Jurisdiction:                    strings.TrimSpace(run.request.Jurisdiction),
								CellStatus:                      run.result.Status,
								ResponseID:                      strings.TrimSpace(response.ID),
								OrganizationID:                  strings.TrimSpace(response.OrganizationID),
								SponsorOfRecord:                 strings.TrimSpace(response.SponsorOfRecord),
								IncidentID:                      strings.TrimSpace(response.IncidentID),
								DirectiveID:                     strings.TrimSpace(directive.ID),
								DirectiveTitle:                  strings.TrimSpace(directive.Title),
								DirectiveStatus:                 directive.Status,
								ExtensionID:                     strings.TrimSpace(extension.ID),
								ExtensionStatus:                 extension.Status,
								DisputeID:                       strings.TrimSpace(dispute.ID),
								DisputeStatus:                   dispute.Status,
								AppealID:                        strings.TrimSpace(appeal.ID),
								AppealStatus:                    appeal.Status,
								AppealingParty:                  appeal.AppealingParty,
								BoardParty:                      appeal.BoardParty,
								EnforcementAcknowledgementParty: appeal.EnforcementAcknowledgementParty,
								PendingAction:                   overdue.pendingAction,
								AutomationAction:                automationAction,
								OverdueReason:                   overdue.overdueReason,
								BoardReviewThreshold:            committeeState.threshold,
								BoardCommitteeMemberCount:       committeeState.memberCount,
								BoardDelegationCount:            committeeState.delegationCount,
								BoardRecordedVoteCount:          committeeState.recordedVoteCount,
								BoardOutstandingVotes:           committeeState.outstandingMemberCount,
								BoardMissingQuorumCount:         committeeState.missingQuorumCount,
								BoardQuorumSatisfied:            committeeState.quorumSatisfied,
								RatifyVoteCount:                 ratifyVotes,
								OverturnVoteCount:               overturnVotes,
								Ruling:                          appeal.Ruling,
								TierID:                          tierID,
								TargetDID:                       targetDID,
								DueAt:                           overdue.dueAt,
								OverdueSeconds:                  int64(at.Sub(overdue.dueAt).Seconds()),
								BoardReviewDueAt:                cloneTimePtr(overdue.boardReviewDueAt),
								EnforcementAcknowledgementDueAt: cloneTimePtr(overdue.enforcementDueAt),
								RuledAt:                         cloneTimePtr(appeal.RuledAt),
								UpdatedAt:                       appeal.UpdatedAt.UTC(),
							})
						}
					}
				}
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].AppealID < items[j].AppealID
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

// ListFederationIncidentDirectiveExtensionAppealAutomationActions returns
// automated appeal-board governance actions already applied by the runtime.
func (s *Service) ListFederationIncidentDirectiveExtensionAppealAutomationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord, error) {
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

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealAction(transition) {
				continue
			}
			if action != "" && !strings.EqualFold(strings.TrimSpace(transition.Action), action) {
				continue
			}
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_organization_id"]), organizationID) {
				continue
			}
			if incidentID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_id"]), incidentID) {
				continue
			}
			if responseID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_response_id"]), responseID) {
				continue
			}
			if directiveID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_id"]), directiveID) {
				continue
			}
			if extensionID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_id"]), extensionID) {
				continue
			}
			if disputeID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_dispute_id"]), disputeID) {
				continue
			}
			if appealID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_id"]), appealID) {
				continue
			}
			if contractID != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_contract_id"]), contractID) {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			items = append(items, SecureCellFederationIncidentDirectiveExtensionAppealAutomationActionRecord{
				CellID:                          strings.TrimSpace(run.result.CellID),
				CellName:                        strings.TrimSpace(run.result.Name),
				Jurisdiction:                    strings.TrimSpace(run.request.Jurisdiction),
				CellStatus:                      run.result.Status,
				OrganizationID:                  strings.TrimSpace(transition.Metadata["federation_organization_id"]),
				SponsorOfRecord:                 strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
				IncidentID:                      strings.TrimSpace(transition.Metadata["federation_incident_id"]),
				ResponseID:                      strings.TrimSpace(transition.Metadata["federation_incident_response_id"]),
				DirectiveID:                     strings.TrimSpace(transition.Metadata["federation_incident_directive_id"]),
				DirectiveTitle:                  strings.TrimSpace(transition.Metadata["federation_incident_directive_title"]),
				DirectiveStatus:                 SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_status"])),
				ExtensionID:                     strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_id"]),
				ExtensionStatus:                 SecureCellFederationIncidentDirectiveExtensionStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_status"])),
				DisputeID:                       strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_dispute_id"]),
				DisputeStatus:                   SecureCellFederationIncidentDirectiveExtensionDisputeStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_dispute_status"])),
				AppealID:                        strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_id"]),
				AppealStatus:                    SecureCellFederationIncidentDirectiveExtensionAppealStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_status"])),
				AppealingParty:                  SecureCellFederationIncidentResponseParty(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appealing_party"])),
				BoardParty:                      SecureCellFederationIncidentResponseParty(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_board_party"])),
				EnforcementAcknowledgementParty: SecureCellFederationIncidentResponseParty(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_enforcement_acknowledgement_party"])),
				PendingAction:                   strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_pending_action"]),
				BoardReviewThreshold:            secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_board_threshold"),
				BoardCommitteeMemberCount:       secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_committee_members"),
				BoardDelegationCount:            secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_delegation_count"),
				BoardRecordedVoteCount:          secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_vote_count"),
				BoardOutstandingVotes:           secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_outstanding_votes"),
				BoardMissingQuorumCount:         secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_missing_quorum"),
				BoardQuorumSatisfied:            secureCellMetadataBool(transition.Metadata, "federation_incident_directive_extension_appeal_quorum_satisfied"),
				RatifyVoteCount:                 secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_ratify_votes"),
				OverturnVoteCount:               secureCellMetadataInt(transition.Metadata, "federation_incident_directive_extension_appeal_overturn_votes"),
				Ruling:                          SecureCellFederationIncidentDirectiveExtensionAppealRuling(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_ruling"])),
				ContractID:                      strings.TrimSpace(transition.Metadata["federation_contract_id"]),
				ContractStatusBefore:            SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_before"])),
				ContractStatusAfter:             SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_after"])),
				Action:                          transition.Action,
				Trigger:                         strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_trigger"]),
				TierID:                          strings.TrimSpace(transition.Metadata["federation_incident_response_tier_id"]),
				TargetDID:                       firstNonEmpty(strings.TrimSpace(transition.Metadata["federation_incident_response_target_did"]), strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_delegated_to"]), strings.TrimSpace(transition.Metadata["decision_route_target"])),
				DueAt:                           parseSecureCellTransitionDueAtWithKey(transition.Metadata, "federation_incident_directive_extension_appeal_due_at"),
				Actor:                           transition.Actor,
				AutomatedActor:                  strings.TrimSpace(transition.Metadata["automated_actor"]),
				Reason:                          strings.TrimSpace(transition.Reason),
				TransitionID:                    strings.TrimSpace(transition.ID),
				OccurredAt:                      occurredAt,
				Metadata:                        cloneStringMap(transition.Metadata),
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

// SweepFederationIncidentDirectiveExtensionAppeals applies automated board
// delegation, response escalation, or fail-closed contract suspension to
// overdue directive-exception appeals.
func (s *Service) SweepFederationIncidentDirectiveExtensionAppeals(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentDirectiveExtensionAppealSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-automation: service is required")
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

	report := &SecureCellFederationIncidentDirectiveExtensionAppealSweepResult{
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
		for _, response := range run.result.FederationIncidentResponses {
			for _, directive := range response.IncidentDirectives {
				for _, extension := range directive.Extensions {
					for _, dispute := range extension.Disputes {
						report.AppealsScanned += len(dispute.Appeals)
						for _, appeal := range dispute.Appeals {
							plan, ok := secureCellFederationIncidentDirectiveExtensionAppealAutomationPlanFromRun(run, response, directive, extension, dispute, appeal, at)
							if !ok {
								continue
							}
							if secureCellFederationIncidentDirectiveExtensionAppealAutomationAlreadyApplied(run, appeal.ID, appeal.Status, plan.pendingAction, plan.action, plan.targetDID) {
								continue
							}

							committeeState := secureCellFederationIncidentDirectiveExtensionAppealCommitteeSnapshot(appeal)
							ratifyVotes, overturnVotes := secureCellFederationIncidentDirectiveExtensionAppealVoteCounts(appeal)
							baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
								"federation_incident_directive_extension_appeal_sweep_mode":                        "automated",
								"federation_incident_directive_extension_appeal_action":                            plan.action,
								"federation_incident_directive_extension_appeal_trigger":                           plan.trigger,
								"federation_incident_directive_extension_appeal_id":                                appeal.ID,
								"federation_incident_directive_extension_appeal_status":                            string(appeal.Status),
								"federation_incident_directive_extension_appeal_pending_action":                    plan.pendingAction,
								"federation_incident_directive_extension_appeal_due_at":                            plan.dueAt.UTC().Format(time.RFC3339Nano),
								"federation_incident_directive_extension_appeal_board_party":                       string(appeal.BoardParty),
								"federation_incident_directive_extension_appealing_party":                          string(appeal.AppealingParty),
								"federation_incident_directive_extension_appeal_enforcement_acknowledgement_party": string(appeal.EnforcementAcknowledgementParty),
								"federation_incident_directive_extension_appeal_board_threshold":                   strconv.Itoa(committeeState.threshold),
								"federation_incident_directive_extension_appeal_delegation_count":                  strconv.Itoa(committeeState.delegationCount),
								"federation_incident_directive_extension_appeal_committee_members":                 strconv.Itoa(committeeState.memberCount),
								"federation_incident_directive_extension_appeal_vote_count":                        strconv.Itoa(committeeState.recordedVoteCount),
								"federation_incident_directive_extension_appeal_outstanding_votes":                 strconv.Itoa(committeeState.outstandingMemberCount),
								"federation_incident_directive_extension_appeal_missing_quorum":                    strconv.Itoa(committeeState.missingQuorumCount),
								"federation_incident_directive_extension_appeal_quorum_satisfied":                  strconv.FormatBool(committeeState.quorumSatisfied),
								"federation_incident_directive_extension_appeal_ratify_votes":                      strconv.Itoa(ratifyVotes),
								"federation_incident_directive_extension_appeal_overturn_votes":                    strconv.Itoa(overturnVotes),
								"federation_incident_directive_extension_appeal_ruling":                            string(appeal.Ruling),
								"federation_incident_directive_extension_dispute_id":                               dispute.ID,
								"federation_incident_directive_extension_dispute_status":                           string(dispute.Status),
								"federation_incident_directive_extension_id":                                       extension.ID,
								"federation_incident_directive_extension_status":                                   string(extension.Status),
								"federation_incident_directive_id":                                                 directive.ID,
								"federation_incident_directive_title":                                              directive.Title,
								"federation_incident_directive_status":                                             string(directive.Status),
								"federation_incident_response_id":                                                  response.ID,
								"federation_organization_id":                                                       response.OrganizationID,
								"federation_sponsor_of_record":                                                     response.SponsorOfRecord,
								"federation_incident_id":                                                           response.IncidentID,
							})
							if plan.targetSource != "" {
								baseMetadata["federation_incident_directive_extension_appeal_target_source"] = plan.targetSource
							}
							if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
								baseMetadata["automated_actor"] = automatedActor
							}

							switch plan.action {
							case "delegate_review_committee":
								if _, err := s.DelegateFederationIncidentDirectiveExtensionAppealReview(ctx, cellID, appeal.ID, SecureCellFederationIncidentDirectiveExtensionDelegationRequest{
									ActorDID:  run.request.OwnerIdentity.AgentID(),
									TargetDID: plan.targetDID,
									Reason:    firstNonEmpty(strings.TrimSpace(lifecycle.Reason), plan.reason),
									Metadata: mergeStringMaps(baseMetadata, map[string]string{
										"federation_incident_response_tier_id":                      plan.tierID,
										"federation_incident_response_target_did":                   plan.targetDID,
										"federation_incident_directive_extension_appeal_target_did": plan.targetDID,
									}),
								}); err != nil {
									return nil, err
								}
								report.CommitteesExpanded++
								mutatedCells[cellID] = struct{}{}
							case "escalate_response":
								responseKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(response.ID)
								if _, seen := escalatedResponses[responseKey]; seen {
									continue
								}
								if _, err := s.EscalateFederationIncidentResponse(ctx, cellID, response.ID, SecureCellFederationIncidentResponseEscalateRequest{
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
								orgKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(response.OrganizationID)
								if _, seen := suspendedOrgs[orgKey]; seen {
									continue
								}
								activeContracts := activeFederationContractsForOrganization(run.result.FederationContracts, response.OrganizationID)
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
				}
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

func secureCellFederationIncidentDirectiveExtensionAppealOverdueStateForAt(appeal SecureCellFederationIncidentDirectiveExtensionAppeal, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealOverdueState, bool) {
	switch appeal.Status {
	case SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview:
		if appeal.CreatedAt.IsZero() {
			return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{}, false
		}
		boardReviewDueAt := appeal.CreatedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealBoardReviewSLA)
		if boardReviewDueAt.After(at) {
			return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{}, false
		}
		return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{
			pendingAction:    "board_review",
			automationAction: "escalate_response",
			overdueReason:    "directive extension appeal-board review deadline reached",
			dueAt:            boardReviewDueAt.UTC(),
			boardReviewDueAt: cloneTimePtr(&boardReviewDueAt),
		}, true
	case SecureCellFederationIncidentDirectiveExtensionAppealStatusRatified, SecureCellFederationIncidentDirectiveExtensionAppealStatusOverturned:
		if appeal.RuledAt == nil || appeal.RuledAt.IsZero() {
			return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{}, false
		}
		enforcementDueAt := appeal.RuledAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealAcknowledgementSLA)
		if enforcementDueAt.After(at) {
			return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{}, false
		}
		return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{
			pendingAction:    "acknowledge_enforcement",
			automationAction: "escalate_response",
			overdueReason:    "directive extension appeal enforcement acknowledgement deadline reached",
			dueAt:            enforcementDueAt.UTC(),
			enforcementDueAt: cloneTimePtr(&enforcementDueAt),
		}, true
	default:
		return secureCellFederationIncidentDirectiveExtensionAppealOverdueState{}, false
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealUsesCommitteeGovernance(appeal SecureCellFederationIncidentDirectiveExtensionAppeal) bool {
	return secureCellFederationIncidentDirectiveExtensionAppealThreshold(appeal) > 1 || len(secureCellFederationIncidentDirectiveExtensionAppealCommitteeMemberDIDs(appeal)) > 0 || len(appeal.BoardDelegations) > 0
}

func secureCellFederationIncidentDirectiveExtensionAppealAutomationPlanFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, _ SecureCellFederationIncidentDirective, _ SecureCellFederationIncidentDirectiveExtension, _ SecureCellFederationIncidentDirectiveExtensionDispute, appeal SecureCellFederationIncidentDirectiveExtensionAppeal, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan, bool) {
	if run == nil || run.result == nil {
		return secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan{}, false
	}
	overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealOverdueStateForAt(appeal, at)
	if !ok {
		return secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan{}, false
	}
	if appeal.Status == SecureCellFederationIncidentDirectiveExtensionAppealStatusPendingBoardReview && secureCellFederationIncidentDirectiveExtensionAppealUsesCommitteeGovernance(appeal) {
		excluded := append([]string(nil), secureCellFederationIncidentDirectiveExtensionAppealCommitteeMemberDIDs(appeal)...)
		excluded = append(excluded, secureCellFederationIncidentDirectiveExtensionAppealRecordedVoterDIDs(appeal)...)
		if targetDID, tierID, targetSource := secureCellFederationIncidentDirectiveExtensionCommitteeTarget(run, response, appeal.BoardParty, excluded); targetDID != "" {
			return secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan{
				action:        "delegate_review_committee",
				trigger:       overdue.pendingAction + "_due",
				reason:        "directive extension appeal-board quorum deadline reached",
				pendingAction: overdue.pendingAction,
				dueAt:         overdue.dueAt,
				tierID:        tierID,
				targetDID:     targetDID,
				targetSource:  targetSource,
			}, true
		}
	}
	if tier, ok := secureCellNextFederationIncidentResponseEscalationTier(response); ok {
		return secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan{
			action:        "escalate_response",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.overdueReason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
			tierID:        strings.TrimSpace(tier.TierID),
			targetDID:     strings.TrimSpace(tier.TargetDID),
		}, true
	}
	if len(activeFederationContractsForOrganization(run.result.FederationContracts, response.OrganizationID)) > 0 {
		return secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan{
			action:        "suspend_contracts",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.overdueReason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
		}, true
	}
	return secureCellFederationIncidentDirectiveExtensionAppealAutomationPlan{}, false
}

func secureCellFederationIncidentDirectiveExtensionAppealAutomationAlreadyApplied(run *secureCellRun, appealID string, appealStatus SecureCellFederationIncidentDirectiveExtensionAppealStatus, pendingAction string, action string, targetDID string) bool {
	if run == nil || run.result == nil {
		return false
	}
	appealID = strings.TrimSpace(appealID)
	pendingAction = strings.TrimSpace(pendingAction)
	action = strings.TrimSpace(action)
	targetDID = strings.TrimSpace(targetDID)
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealAction(transition) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_id"]), appealID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_pending_action"]), pendingAction) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_action"]), action) {
			continue
		}
		if targetDID != "" && action == "delegate_review_committee" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_delegated_to"]), targetDID) {
			continue
		}
		if SecureCellFederationIncidentDirectiveExtensionAppealStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_status"])) != appealStatus {
			continue
		}
		return true
	}
	return false
}

func secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealAction(transition SecureCellTransition) bool {
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_sweep_mode"]), "automated")
}
