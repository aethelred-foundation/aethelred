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
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeSLA = 8 * time.Hour
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeSLA     = 2 * time.Hour
)

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueState struct {
	pendingAction string
	action        string
	reason        string
	dueAt         time.Time
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan struct {
	action        string
	trigger       string
	reason        string
	pendingAction string
	dueAt         time.Time
	tierID        string
	targetDID     string
}

type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentFilter struct {
	CellID            string                                                                                                 `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                 `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                 `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                 `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                 `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                 `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                 `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                 `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                                 `json:"comparison_key,omitempty"`
	ChallengeID       string                                                                                                 `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                 `json:"challenge_appeal_id,omitempty"`
	SnapshotID        string                                                                                                 `json:"snapshot_id,omitempty"`
	Status            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus    `json:"status,omitempty"`
	AlignmentStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus       `json:"alignment_status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus `json:"review_status,omitempty"`
	Before            *time.Time                                                                                             `json:"before,omitempty"`
	Limit             int                                                                                                    `json:"limit,omitempty"`
}

type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment struct {
	CellID                        string                                                                                                 `json:"cell_id"`
	CellName                      string                                                                                                 `json:"cell_name,omitempty"`
	Jurisdiction                  string                                                                                                 `json:"jurisdiction,omitempty"`
	CellStatus                    SecureCellStatus                                                                                       `json:"cell_status"`
	OrganizationID                string                                                                                                 `json:"organization_id"`
	SponsorOfRecord               string                                                                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName              string                                                                                                 `json:"organization_name,omitempty"`
	SnapshotID                    string                                                                                                 `json:"snapshot_id"`
	BundleID                      string                                                                                                 `json:"bundle_id,omitempty"`
	ComparisonKey                 string                                                                                                 `json:"comparison_key"`
	IncidentID                    string                                                                                                 `json:"incident_id,omitempty"`
	ResponseID                    string                                                                                                 `json:"response_id,omitempty"`
	DirectiveID                   string                                                                                                 `json:"directive_id,omitempty"`
	ExtensionID                   string                                                                                                 `json:"extension_id,omitempty"`
	DisputeID                     string                                                                                                 `json:"dispute_id,omitempty"`
	AppealID                      string                                                                                                 `json:"appeal_id,omitempty"`
	ChallengeID                   string                                                                                                 `json:"challenge_id,omitempty"`
	ChallengeAppealID             string                                                                                                 `json:"challenge_appeal_id,omitempty"`
	ChallengeAppealStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus                `json:"challenge_appeal_status"`
	Status                        SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus    `json:"status"`
	AlignmentStatus               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus       `json:"alignment_status"`
	ReviewStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus `json:"review_status"`
	PendingAction                 string                                                                                                 `json:"pending_action"`
	AutomationAction              string                                                                                                 `json:"automation_action"`
	OverdueReason                 string                                                                                                 `json:"overdue_reason"`
	TierID                        string                                                                                                 `json:"tier_id,omitempty"`
	TargetDID                     string                                                                                                 `json:"target_did,omitempty"`
	MatchedLocalChallengeAppealID string                                                                                                 `json:"matched_local_challenge_appeal_id,omitempty"`
	VerificationMessage           string                                                                                                 `json:"verification_message,omitempty"`
	AlignmentDivergenceCount      int                                                                                                    `json:"alignment_divergence_count,omitempty"`
	ReviewActionCount             int                                                                                                    `json:"review_action_count,omitempty"`
	DueAt                         time.Time                                                                                              `json:"due_at"`
	OverdueSeconds                int64                                                                                                  `json:"overdue_seconds"`
	ReceivedAt                    time.Time                                                                                              `json:"received_at"`
	LastReviewedAt                *time.Time                                                                                             `json:"last_reviewed_at,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFilter struct {
	CellID            string                                                                                                 `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                                 `json:"organization_id,omitempty"`
	IncidentID        string                                                                                                 `json:"incident_id,omitempty"`
	ResponseID        string                                                                                                 `json:"response_id,omitempty"`
	DirectiveID       string                                                                                                 `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                                 `json:"extension_id,omitempty"`
	DisputeID         string                                                                                                 `json:"dispute_id,omitempty"`
	AppealID          string                                                                                                 `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                                 `json:"comparison_key,omitempty"`
	ChallengeID       string                                                                                                 `json:"challenge_id,omitempty"`
	ChallengeAppealID string                                                                                                 `json:"challenge_appeal_id,omitempty"`
	SnapshotID        string                                                                                                 `json:"snapshot_id,omitempty"`
	Status            SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus    `json:"status,omitempty"`
	AlignmentStatus   SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus       `json:"alignment_status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus `json:"review_status,omitempty"`
	PendingAction     string                                                                                                 `json:"pending_action,omitempty"`
	ContractID        string                                                                                                 `json:"contract_id,omitempty"`
	Action            string                                                                                                 `json:"action,omitempty"`
	Since             *time.Time                                                                                             `json:"since,omitempty"`
	Until             *time.Time                                                                                             `json:"until,omitempty"`
	Limit             int                                                                                                    `json:"limit,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord struct {
	CellID                        string                                                                                                 `json:"cell_id"`
	CellName                      string                                                                                                 `json:"cell_name,omitempty"`
	Jurisdiction                  string                                                                                                 `json:"jurisdiction,omitempty"`
	CellStatus                    SecureCellStatus                                                                                       `json:"cell_status"`
	OrganizationID                string                                                                                                 `json:"organization_id"`
	SponsorOfRecord               string                                                                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName              string                                                                                                 `json:"organization_name,omitempty"`
	SnapshotID                    string                                                                                                 `json:"snapshot_id"`
	BundleID                      string                                                                                                 `json:"bundle_id,omitempty"`
	ComparisonKey                 string                                                                                                 `json:"comparison_key"`
	IncidentID                    string                                                                                                 `json:"incident_id,omitempty"`
	ResponseID                    string                                                                                                 `json:"response_id,omitempty"`
	DirectiveID                   string                                                                                                 `json:"directive_id,omitempty"`
	ExtensionID                   string                                                                                                 `json:"extension_id,omitempty"`
	DisputeID                     string                                                                                                 `json:"dispute_id,omitempty"`
	AppealID                      string                                                                                                 `json:"appeal_id,omitempty"`
	ChallengeID                   string                                                                                                 `json:"challenge_id,omitempty"`
	ChallengeAppealID             string                                                                                                 `json:"challenge_appeal_id,omitempty"`
	ChallengeAppealStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus                `json:"challenge_appeal_status,omitempty"`
	Status                        SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus    `json:"status,omitempty"`
	AlignmentStatus               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus       `json:"alignment_status,omitempty"`
	ReviewStatus                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus `json:"review_status,omitempty"`
	PendingAction                 string                                                                                                 `json:"pending_action,omitempty"`
	MatchedLocalChallengeAppealID string                                                                                                 `json:"matched_local_challenge_appeal_id,omitempty"`
	VerificationMessage           string                                                                                                 `json:"verification_message,omitempty"`
	AlignmentDivergenceCount      int                                                                                                    `json:"alignment_divergence_count,omitempty"`
	ReviewActionCount             int                                                                                                    `json:"review_action_count,omitempty"`
	ContractID                    string                                                                                                 `json:"contract_id,omitempty"`
	ContractStatusBefore          SecureCellFederationContractStatus                                                                     `json:"contract_status_before,omitempty"`
	ContractStatusAfter           SecureCellFederationContractStatus                                                                     `json:"contract_status_after,omitempty"`
	Action                        string                                                                                                 `json:"action"`
	Trigger                       string                                                                                                 `json:"trigger,omitempty"`
	TierID                        string                                                                                                 `json:"tier_id,omitempty"`
	TargetDID                     string                                                                                                 `json:"target_did,omitempty"`
	DueAt                         *time.Time                                                                                             `json:"due_at,omitempty"`
	Actor                         string                                                                                                 `json:"actor"`
	AutomatedActor                string                                                                                                 `json:"automated_actor,omitempty"`
	Reason                        string                                                                                                 `json:"reason,omitempty"`
	TransitionID                  string                                                                                                 `json:"transition_id"`
	OccurredAt                    time.Time                                                                                              `json:"occurred_at"`
	Metadata                      map[string]string                                                                                      `json:"metadata,omitempty"`
}

type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentSweepResult struct {
	At                 time.Time `json:"at"`
	CellsScanned       int       `json:"cells_scanned"`
	SnapshotsScanned   int       `json:"snapshots_scanned"`
	CellsMutated       int       `json:"cells_mutated"`
	ResponsesEscalated int       `json:"responses_escalated"`
	ContractsSuspended int       `json:"contracts_suspended"`
	CellIDs            []string  `json:"cell_ids,omitempty"`
}

func (s *Service) ListOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignments(_ context.Context, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentFilter) ([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if !secureCellFederationRunMatchesCellFilter(run, strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, item := range secureCellLatestFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummariesFromRun(run) {
			if !matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueFilter(item, filter) {
				continue
			}
			overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueStateForAt(item, at)
			if !ok {
				continue
			}
			responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, item.ResponseID)
			if err != nil {
				return nil, err
			}
			plan, _ := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlanFromRun(run, *response, item, at)
			automationAction := overdue.action
			tierID := ""
			targetDID := ""
			if plan.action != "" {
				automationAction = plan.action
				tierID = plan.tierID
				targetDID = plan.targetDID
			}
			items = append(items, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignment{
				CellID:                        item.CellID,
				CellName:                      item.CellName,
				Jurisdiction:                  item.Jurisdiction,
				CellStatus:                    item.CellStatus,
				OrganizationID:                item.OrganizationID,
				SponsorOfRecord:               responseSummary.SponsorOfRecord,
				OrganizationName:              item.OrganizationName,
				SnapshotID:                    item.SnapshotID,
				BundleID:                      item.BundleID,
				ComparisonKey:                 item.ComparisonKey,
				IncidentID:                    item.IncidentID,
				ResponseID:                    item.ResponseID,
				DirectiveID:                   item.DirectiveID,
				ExtensionID:                   item.ExtensionID,
				DisputeID:                     item.DisputeID,
				AppealID:                      item.AppealID,
				ChallengeID:                   item.ChallengeID,
				ChallengeAppealID:             item.ChallengeAppealID,
				ChallengeAppealStatus:         item.ChallengeAppealStatus,
				Status:                        item.Status,
				AlignmentStatus:               item.AlignmentStatus,
				ReviewStatus:                  item.ReviewStatus,
				PendingAction:                 overdue.pendingAction,
				AutomationAction:              automationAction,
				OverdueReason:                 overdue.reason,
				TierID:                        tierID,
				TargetDID:                     targetDID,
				MatchedLocalChallengeAppealID: item.MatchedLocalChallengeAppealID,
				VerificationMessage:           item.VerificationMessage,
				AlignmentDivergenceCount:      item.AlignmentDivergenceCount,
				ReviewActionCount:             item.ReviewActionCount,
				DueAt:                         overdue.dueAt,
				OverdueSeconds:                int64(at.Sub(overdue.dueAt).Seconds()),
				ReceivedAt:                    item.ReceivedAt.UTC(),
				LastReviewedAt:                cloneTimePtr(item.LastReviewedAt),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].SnapshotID < items[j].SnapshotID
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

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord, error) {
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
	snapshotID := strings.TrimSpace(filter.SnapshotID)
	pendingAction := strings.TrimSpace(filter.PendingAction)
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

	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(transition) {
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
			if snapshotID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id"]), snapshotID) {
				continue
			}
			if pendingAction != "" && !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_pending_action"]), pendingAction) {
				continue
			}
			if contractID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_contract_id"]), contractID) {
				continue
			}
			if filter.Status != "" && SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_status"])) != filter.Status {
				continue
			}
			if filter.AlignmentStatus != "" && SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status"])) != filter.AlignmentStatus {
				continue
			}
			if filter.ReviewStatus != "" && SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status"])) != filter.ReviewStatus {
				continue
			}
			occurredAt := transition.OccurredAt.UTC()
			if !since.IsZero() && occurredAt.Before(since) {
				continue
			}
			if !until.IsZero() && occurredAt.After(until) {
				continue
			}
			dueAt := parseSecureCellTransitionDueAtWithKey(data, "federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_due_at")
			items = append(items, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord{
				CellID:                        strings.TrimSpace(run.result.CellID),
				CellName:                      strings.TrimSpace(run.result.Name),
				Jurisdiction:                  strings.TrimSpace(run.request.Jurisdiction),
				CellStatus:                    run.result.Status,
				OrganizationID:                strings.TrimSpace(data["federation_organization_id"]),
				SponsorOfRecord:               strings.TrimSpace(data["federation_sponsor_of_record"]),
				OrganizationName:              strings.TrimSpace(data["federation_organization_name"]),
				SnapshotID:                    strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id"]),
				BundleID:                      strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id"]),
				ComparisonKey:                 strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_key"]),
				IncidentID:                    strings.TrimSpace(data["federation_incident_id"]),
				ResponseID:                    strings.TrimSpace(data["federation_incident_response_id"]),
				DirectiveID:                   strings.TrimSpace(data["federation_incident_directive_id"]),
				ExtensionID:                   strings.TrimSpace(data["federation_incident_directive_extension_id"]),
				DisputeID:                     strings.TrimSpace(data["federation_incident_directive_extension_dispute_id"]),
				AppealID:                      strings.TrimSpace(data["federation_incident_directive_extension_appeal_id"]),
				ChallengeID:                   strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_id"]),
				ChallengeAppealID:             strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id"]),
				ChallengeAppealStatus:         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status"])),
				Status:                        SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_status"])),
				AlignmentStatus:               SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status"])),
				ReviewStatus:                  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatus(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status"])),
				PendingAction:                 strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_pending_action"]),
				MatchedLocalChallengeAppealID: strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id"]),
				VerificationMessage:           strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message"]),
				AlignmentDivergenceCount:      secureCellMetadataInt(data, "federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_divergence_count"),
				ReviewActionCount:             secureCellMetadataInt(data, "federation_counterparty_incident_directive_extension_appeal_reconciliation_review_action_count"),
				ContractID:                    strings.TrimSpace(data["federation_contract_id"]),
				ContractStatusBefore:          SecureCellFederationContractStatus(strings.TrimSpace(data["federation_contract_status_before"])),
				ContractStatusAfter:           SecureCellFederationContractStatus(strings.TrimSpace(data["federation_contract_status_after"])),
				Action:                        transition.Action,
				Trigger:                       strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_trigger"]),
				TierID:                        strings.TrimSpace(data["federation_incident_response_tier_id"]),
				TargetDID:                     strings.TrimSpace(data["federation_incident_response_target_did"]),
				DueAt:                         cloneTimePtr(dueAt),
				Actor:                         transition.Actor,
				AutomatedActor:                strings.TrimSpace(data["automated_actor"]),
				Reason:                        strings.TrimSpace(transition.Reason),
				TransitionID:                  strings.TrimSpace(transition.ID),
				OccurredAt:                    occurredAt,
				Metadata:                      cloneStringMap(data),
			})
		}
	}
	reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActions(items)
	if filter.Limit > 0 && len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (s *Service) SweepFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignments(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-challenge-appeal-alignment-automation: service is required")
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

	report := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutatedCells := make(map[string]struct{})
	escalatedResponses := make(map[string]struct{})
	suspendedContracts := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		summaries := secureCellLatestFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummariesFromRun(run)
		report.SnapshotsScanned += len(summaries)
		for _, item := range summaries {
			if _, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueStateForAt(item, at); !ok {
				continue
			}
			responseSummary, response, err := secureCellFederationIncidentResponseSummaryAndRef(run, item.ResponseID)
			if err != nil {
				return nil, err
			}
			plan, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlanFromRun(run, *response, item, at)
			if !ok {
				continue
			}
			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_sweep_mode":     "automated",
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_action":         plan.action,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_trigger":        plan.trigger,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_pending_action": plan.pendingAction,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_due_at":         plan.dueAt.UTC().Format(time.RFC3339Nano),
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id":                  item.SnapshotID,
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_bundle_id":                    item.BundleID,
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_status":                       string(item.Status),
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_status":             string(item.AlignmentStatus),
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_review_status":                string(item.ReviewStatus),
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_matched_local_id":             item.MatchedLocalChallengeAppealID,
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_verification_message":         item.VerificationMessage,
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_alignment_divergence_count":   strconv.Itoa(item.AlignmentDivergenceCount),
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_review_action_count":          strconv.Itoa(item.ReviewActionCount),
				"federation_counterparty_incident_directive_extension_appeal_reconciliation_challenge_appeal_status":      string(item.ChallengeAppealStatus),
				"federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_id":                       item.ChallengeAppealID,
				"federation_incident_directive_extension_appeal_reconciliation_challenge_id":                              item.ChallengeID,
				"federation_incident_directive_extension_appeal_reconciliation_key":                                       item.ComparisonKey,
				"federation_incident_directive_extension_appeal_id":                                                       item.AppealID,
				"federation_incident_directive_extension_dispute_id":                                                      item.DisputeID,
				"federation_incident_directive_extension_id":                                                              item.ExtensionID,
				"federation_incident_directive_id":                                                                        item.DirectiveID,
				"federation_incident_response_id":                                                                         item.ResponseID,
				"federation_organization_id":                                                                              item.OrganizationID,
				"federation_organization_name":                                                                            item.OrganizationName,
				"federation_sponsor_of_record":                                                                            responseSummary.SponsorOfRecord,
				"federation_incident_id":                                                                                  item.IncidentID,
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				baseMetadata["automated_actor"] = automatedActor
			}

			switch plan.action {
			case "escalate_response":
				actionKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(item.SnapshotID) + "|" + plan.pendingAction + "|" + plan.action
				if _, seen := escalatedResponses[actionKey]; seen || secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAlreadyApplied(run, item.SnapshotID, plan.pendingAction, plan.action, "") {
					continue
				}
				if _, err := s.EscalateFederationIncidentResponse(ctx, cellID, item.ResponseID, SecureCellFederationIncidentResponseEscalateRequest{
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
				escalatedResponses[actionKey] = struct{}{}
				report.ResponsesEscalated++
				mutatedCells[cellID] = struct{}{}
			case "suspend_contracts":
				activeContracts := activeFederationContractsForOrganization(run.result.FederationContracts, item.OrganizationID)
				for _, contract := range activeContracts {
					contractKey := strings.TrimSpace(cellID) + "|" + strings.TrimSpace(item.SnapshotID) + "|" + strings.TrimSpace(contract.ID) + "|" + plan.pendingAction
					if _, seen := suspendedContracts[contractKey]; seen || secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAlreadyApplied(run, item.SnapshotID, plan.pendingAction, plan.action, contract.ID) {
						continue
					}
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
					suspendedContracts[contractKey] = struct{}{}
					report.ContractsSuspended++
					mutatedCells[cellID] = struct{}{}
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

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueStateForAt(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueState, bool) {
	if item.ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentReviewStatusUnreviewed || item.ReceivedAt.IsZero() {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueState{}, false
	}
	dueAt := item.ReceivedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentDisputeSLA)
	state := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueState{
		pendingAction: "dispute_alignment",
		action:        "suspend_contracts",
		reason:        "reciprocal challenge appeal alignment dispute deadline reached",
		dueAt:         dueAt.UTC(),
	}
	if item.Status == SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealStatusVerified && item.AlignmentStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentStatusAligned {
		state.pendingAction = "acknowledge_alignment"
		state.action = "escalate_response"
		state.reason = "reciprocal challenge appeal alignment acknowledgement deadline reached"
		state.dueAt = item.ReceivedAt.UTC().Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAcknowledgeSLA)
	}
	if state.dueAt.After(at) {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueState{}, false
	}
	return state, true
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlanFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan, bool) {
	if run == nil || run.result == nil {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan{}, false
	}
	overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueStateForAt(item, at)
	if !ok {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan{}, false
	}
	if overdue.pendingAction == "dispute_alignment" && len(activeFederationContractsForOrganization(run.result.FederationContracts, item.OrganizationID)) > 0 {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan{
			action:        "suspend_contracts",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.reason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
		}, true
	}
	if tier, ok := secureCellNextFederationIncidentResponseEscalationTier(response); ok {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan{
			action:        "escalate_response",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.reason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
			tierID:        strings.TrimSpace(tier.TierID),
			targetDID:     strings.TrimSpace(tier.TargetDID),
		}, true
	}
	if len(activeFederationContractsForOrganization(run.result.FederationContracts, item.OrganizationID)) > 0 {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan{
			action:        "suspend_contracts",
			trigger:       overdue.pendingAction + "_due",
			reason:        overdue.reason,
			pendingAction: overdue.pendingAction,
			dueAt:         overdue.dueAt,
		}, true
	}
	return secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationPlan{}, false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationAlreadyApplied(run *secureCellRun, snapshotID string, pendingAction string, action string, contractID string) bool {
	if run == nil || run.result == nil {
		return false
	}
	snapshotID = strings.TrimSpace(snapshotID)
	pendingAction = strings.TrimSpace(pendingAction)
	action = strings.TrimSpace(action)
	contractID = strings.TrimSpace(contractID)
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(transition) {
			continue
		}
		data := transition.Metadata
		if !strings.EqualFold(strings.TrimSpace(data["federation_counterparty_incident_directive_extension_appeal_reconciliation_snapshot_id"]), snapshotID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_pending_action"]), pendingAction) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(data["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_action"]), action) {
			continue
		}
		if contractID != "" && !strings.EqualFold(strings.TrimSpace(data["federation_contract_id"]), contractID) {
			continue
		}
		return true
	}
	return false
}

func secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAction(transition SecureCellTransition) bool {
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_challenge_appeal_alignment_sweep_mode"]), "automated")
}

func matchesSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentOverdueFilter(item SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentFilter) bool {
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
	return true
}

func secureCellLatestFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummariesFromRun(run *secureCellRun) []SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary {
	if run == nil || run.result == nil {
		return nil
	}
	latestByChallengeAppealID := make(map[string]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary)
	for _, snapshot := range run.result.FederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppeals {
		summary := secureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummaryFromRun(run, snapshot)
		key := strings.TrimSpace(summary.ChallengeAppealID)
		if key == "" {
			key = strings.TrimSpace(summary.SnapshotID)
		}
		current, exists := latestByChallengeAppealID[key]
		if exists {
			if current.ReceivedAt.After(summary.ReceivedAt) {
				continue
			}
			if current.ReceivedAt.Equal(summary.ReceivedAt) && strings.Compare(current.SnapshotID, summary.SnapshotID) > 0 {
				continue
			}
		}
		latestByChallengeAppealID[key] = summary
	}
	items := make([]SecureCellFederationCounterpartyIncidentDirectiveExtensionAppealReconciliationChallengeAppealSummary, 0, len(latestByChallengeAppealID))
	for _, item := range latestByChallengeAppealID {
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].ReceivedAt.Equal(items[j].ReceivedAt) {
			return items[i].SnapshotID > items[j].SnapshotID
		}
		return items[i].ReceivedAt.After(items[j].ReceivedAt)
	})
	return items
}

func reverseSecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActions(items []SecureCellFederationIncidentDirectiveExtensionAppealReconciliationChallengeAppealAlignmentAutomationActionRecord) {
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
}
