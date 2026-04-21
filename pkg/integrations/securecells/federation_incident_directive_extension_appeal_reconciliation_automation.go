package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aethelred/aethelred/pkg/governance/policy"
)

const (
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewSLA          = 6 * time.Hour
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAckSLA = 12 * time.Hour
	secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionSLA      = 24 * time.Hour
)

// SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter
// narrows operator queries across appeal reconciliations whose next governed
// review or counterparty-response milestone is overdue.
type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter struct {
	CellID            string                                                                                          `json:"cell_id,omitempty"`
	OrganizationID    string                                                                                          `json:"organization_id,omitempty"`
	IncidentID        string                                                                                          `json:"incident_id,omitempty"`
	ResponseID        string                                                                                          `json:"response_id,omitempty"`
	DirectiveID       string                                                                                          `json:"directive_id,omitempty"`
	ExtensionID       string                                                                                          `json:"extension_id,omitempty"`
	DisputeID         string                                                                                          `json:"dispute_id,omitempty"`
	AppealID          string                                                                                          `json:"appeal_id,omitempty"`
	ComparisonKey     string                                                                                          `json:"comparison_key,omitempty"`
	Status            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"status,omitempty"`
	ReviewStatus      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status,omitempty"`
	AttestationStatus SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status,omitempty"`
	Before            *time.Time                                                                                      `json:"before,omitempty"`
	Limit             int                                                                                             `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation
// projects one overdue appeal-reconciliation milestone.
type SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation struct {
	CellID                       string                                                                                          `json:"cell_id"`
	CellName                     string                                                                                          `json:"cell_name,omitempty"`
	Jurisdiction                 string                                                                                          `json:"jurisdiction,omitempty"`
	CellStatus                   SecureCellStatus                                                                                `json:"cell_status"`
	OrganizationID               string                                                                                          `json:"organization_id"`
	SponsorOfRecord              string                                                                                          `json:"sponsor_of_record,omitempty"`
	OrganizationName             string                                                                                          `json:"organization_name,omitempty"`
	ComparisonKey                string                                                                                          `json:"comparison_key"`
	IncidentID                   string                                                                                          `json:"incident_id,omitempty"`
	ResponseID                   string                                                                                          `json:"response_id,omitempty"`
	DirectiveID                  string                                                                                          `json:"directive_id,omitempty"`
	DirectiveTitle               string                                                                                          `json:"directive_title,omitempty"`
	ExtensionID                  string                                                                                          `json:"extension_id,omitempty"`
	DisputeID                    string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                     string                                                                                          `json:"appeal_id,omitempty"`
	Status                       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"status"`
	ReviewStatus                 SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status"`
	AttestationStatus            SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status"`
	AutomationAction             string                                                                                          `json:"automation_action"`
	OverdueReason                string                                                                                          `json:"overdue_reason"`
	DueAt                        time.Time                                                                                       `json:"due_at"`
	OverdueSeconds               int64                                                                                           `json:"overdue_seconds"`
	ReviewDueAt                  *time.Time                                                                                      `json:"review_due_at,omitempty"`
	CounterpartyAcknowledgeDueAt *time.Time                                                                                      `json:"counterparty_acknowledge_due_at,omitempty"`
	ResolutionDueAt              *time.Time                                                                                      `json:"resolution_due_at,omitempty"`
	LocalAppealID                string                                                                                          `json:"local_appeal_id,omitempty"`
	CounterpartyAppealID         string                                                                                          `json:"counterparty_appeal_id,omitempty"`
	LastReviewedBy               string                                                                                          `json:"last_reviewed_by,omitempty"`
	LastReviewedAt               *time.Time                                                                                      `json:"last_reviewed_at,omitempty"`
	LastCounterpartyAttestedBy   string                                                                                          `json:"last_counterparty_attested_by,omitempty"`
	LastCounterpartyAttestedAt   *time.Time                                                                                      `json:"last_counterparty_attested_at,omitempty"`
	Divergences                  []string                                                                                        `json:"divergences,omitempty"`
	UpdatedAt                    time.Time                                                                                       `json:"updated_at"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter
// narrows operator queries over automated appeal-reconciliation actions.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ResponseID     string     `json:"response_id,omitempty"`
	DirectiveID    string     `json:"directive_id,omitempty"`
	ExtensionID    string     `json:"extension_id,omitempty"`
	DisputeID      string     `json:"dispute_id,omitempty"`
	AppealID       string     `json:"appeal_id,omitempty"`
	ComparisonKey  string     `json:"comparison_key,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord
// projects one automated escalation or containment action over a bilateral
// appeal reconciliation.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord struct {
	CellID                  string                                                                                          `json:"cell_id"`
	CellName                string                                                                                          `json:"cell_name,omitempty"`
	Jurisdiction            string                                                                                          `json:"jurisdiction,omitempty"`
	CellStatus              SecureCellStatus                                                                                `json:"cell_status"`
	OrganizationID          string                                                                                          `json:"organization_id,omitempty"`
	SponsorOfRecord         string                                                                                          `json:"sponsor_of_record,omitempty"`
	ComparisonKey           string                                                                                          `json:"comparison_key,omitempty"`
	IncidentID              string                                                                                          `json:"incident_id,omitempty"`
	ResponseID              string                                                                                          `json:"response_id,omitempty"`
	DirectiveID             string                                                                                          `json:"directive_id,omitempty"`
	DisputeID               string                                                                                          `json:"dispute_id,omitempty"`
	AppealID                string                                                                                          `json:"appeal_id,omitempty"`
	ReconciliationStatus    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus                        `json:"reconciliation_status,omitempty"`
	ReviewStatusBefore      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status_before,omitempty"`
	ReviewStatusAfter       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus                  `json:"review_status_after,omitempty"`
	AttestationStatusBefore SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status_before,omitempty"`
	AttestationStatusAfter  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus `json:"attestation_status_after,omitempty"`
	ContractID              string                                                                                          `json:"contract_id,omitempty"`
	ContractStatusBefore    SecureCellFederationContractStatus                                                              `json:"contract_status_before,omitempty"`
	ContractStatusAfter     SecureCellFederationContractStatus                                                              `json:"contract_status_after,omitempty"`
	Action                  string                                                                                          `json:"action"`
	Trigger                 string                                                                                          `json:"trigger,omitempty"`
	DueAt                   *time.Time                                                                                      `json:"due_at,omitempty"`
	Actor                   string                                                                                          `json:"actor"`
	AutomatedActor          string                                                                                          `json:"automated_actor,omitempty"`
	Reason                  string                                                                                          `json:"reason,omitempty"`
	TransitionID            string                                                                                          `json:"transition_id"`
	OccurredAt              time.Time                                                                                       `json:"occurred_at"`
	Metadata                map[string]string                                                                               `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSweepResult
// summarizes one automated appeal-reconciliation sweep.
type SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSweepResult struct {
	At                          time.Time `json:"at"`
	CellsScanned                int       `json:"cells_scanned"`
	ReconciliationsScanned      int       `json:"reconciliations_scanned"`
	CellsMutated                int       `json:"cells_mutated"`
	ReconciliationsAutoDisputed int       `json:"reconciliations_auto_disputed"`
	ReconciliationsEscalated    int       `json:"reconciliations_escalated"`
	ContractsSuspended          int       `json:"contracts_suspended"`
	CellIDs                     []string  `json:"cell_ids,omitempty"`
}

type secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState struct {
	reviewStatus         SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus
	attestationStatus    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus
	automationAction     string
	overdueReason        string
	dueAt                time.Time
	reviewDueAt          *time.Time
	counterpartyAckDueAt *time.Time
	resolutionDueAt      *time.Time
}

func (s *Service) ListOverdueFederationIncidentDirectiveExtensionAppealReconciliations(_ context.Context, filter SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter) ([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items := make([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, reconciliation := range secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run) {
			if filter.OrganizationID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.OrganizationID), strings.TrimSpace(filter.OrganizationID)) {
				continue
			}
			if filter.IncidentID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.IncidentID), strings.TrimSpace(filter.IncidentID)) {
				continue
			}
			if filter.ResponseID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.ResponseID), strings.TrimSpace(filter.ResponseID)) {
				continue
			}
			if filter.DirectiveID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.DirectiveID), strings.TrimSpace(filter.DirectiveID)) {
				continue
			}
			if filter.ExtensionID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.ExtensionID), strings.TrimSpace(filter.ExtensionID)) {
				continue
			}
			if filter.DisputeID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.DisputeID), strings.TrimSpace(filter.DisputeID)) {
				continue
			}
			if filter.AppealID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.AppealID), strings.TrimSpace(filter.AppealID)) {
				continue
			}
			if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.ComparisonKey), strings.TrimSpace(filter.ComparisonKey)) {
				continue
			}
			if filter.Status != "" && reconciliation.Status != filter.Status {
				continue
			}
			overdue, ok := secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueStateForAt(reconciliation, at)
			if !ok {
				continue
			}
			if filter.ReviewStatus != "" && overdue.reviewStatus != filter.ReviewStatus {
				continue
			}
			if filter.AttestationStatus != "" && overdue.attestationStatus != filter.AttestationStatus {
				continue
			}
			items = append(items, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation{
				CellID:                       reconciliation.CellID,
				CellName:                     reconciliation.CellName,
				Jurisdiction:                 reconciliation.Jurisdiction,
				CellStatus:                   reconciliation.CellStatus,
				OrganizationID:               reconciliation.OrganizationID,
				SponsorOfRecord:              reconciliation.SponsorOfRecord,
				OrganizationName:             reconciliation.OrganizationName,
				ComparisonKey:                reconciliation.ComparisonKey,
				IncidentID:                   reconciliation.IncidentID,
				ResponseID:                   reconciliation.ResponseID,
				DirectiveID:                  reconciliation.DirectiveID,
				DirectiveTitle:               reconciliation.DirectiveTitle,
				ExtensionID:                  reconciliation.ExtensionID,
				DisputeID:                    reconciliation.DisputeID,
				AppealID:                     reconciliation.AppealID,
				Status:                       reconciliation.Status,
				ReviewStatus:                 overdue.reviewStatus,
				AttestationStatus:            overdue.attestationStatus,
				AutomationAction:             overdue.automationAction,
				OverdueReason:                overdue.overdueReason,
				DueAt:                        overdue.dueAt,
				OverdueSeconds:               int64(at.Sub(overdue.dueAt).Seconds()),
				ReviewDueAt:                  cloneTimePtr(overdue.reviewDueAt),
				CounterpartyAcknowledgeDueAt: cloneTimePtr(overdue.counterpartyAckDueAt),
				ResolutionDueAt:              cloneTimePtr(overdue.resolutionDueAt),
				LocalAppealID:                reconciliation.LocalAppealID,
				CounterpartyAppealID:         reconciliation.CounterpartyAppealID,
				LastReviewedBy:               reconciliation.LastReviewedBy,
				LastReviewedAt:               cloneTimePtr(reconciliation.LastReviewedAt),
				LastCounterpartyAttestedBy:   reconciliation.LastCounterpartyAttestedBy,
				LastCounterpartyAttestedAt:   cloneTimePtr(reconciliation.LastCounterpartyAttestedAt),
				Divergences:                  append([]string(nil), reconciliation.Divergences...),
				UpdatedAt:                    secureCellFederationIncidentDirectiveExtensionAppealReconciliationUpdatedAt(reconciliation),
			})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].DueAt.Equal(items[j].DueAt) {
			if items[i].CellID == items[j].CellID {
				return items[i].ComparisonKey < items[j].ComparisonKey
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

func (s *Service) ListFederationIncidentDirectiveExtensionAppealReconciliationAutomationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionFilter) ([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord, error) {
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
	items := make([]SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if filter.CellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), strings.TrimSpace(filter.CellID)) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationAction(transition) {
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
			if filter.ComparisonKey != "" && !strings.EqualFold(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_comparison_key"]), strings.TrimSpace(filter.ComparisonKey)) {
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
			items = append(items, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationActionRecord{
				CellID:                  run.result.CellID,
				CellName:                run.result.Name,
				Jurisdiction:            run.request.Jurisdiction,
				CellStatus:              run.result.Status,
				OrganizationID:          strings.TrimSpace(meta["federation_organization_id"]),
				SponsorOfRecord:         strings.TrimSpace(meta["federation_sponsor_of_record"]),
				ComparisonKey:           strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_comparison_key"]),
				IncidentID:              strings.TrimSpace(meta["federation_incident_id"]),
				ResponseID:              strings.TrimSpace(meta["federation_incident_response_id"]),
				DirectiveID:             strings.TrimSpace(meta["federation_incident_directive_id"]),
				DisputeID:               strings.TrimSpace(meta["federation_incident_directive_extension_dispute_id"]),
				AppealID:                strings.TrimSpace(meta["federation_incident_directive_extension_appeal_id"]),
				ReconciliationStatus:    SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_status"])),
				ReviewStatusBefore:      SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review_status_before"])),
				ReviewStatusAfter:       SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_review_status_after"])),
				AttestationStatusBefore: SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_attestation_status_before"])),
				AttestationStatusAfter:  SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus(strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_attestation_status_after"])),
				ContractID:              strings.TrimSpace(meta["federation_contract_id"]),
				ContractStatusBefore:    SecureCellFederationContractStatus(strings.TrimSpace(meta["federation_contract_status_before"])),
				ContractStatusAfter:     SecureCellFederationContractStatus(strings.TrimSpace(meta["federation_contract_status_after"])),
				Action:                  transition.Action,
				Trigger:                 strings.TrimSpace(meta["federation_incident_directive_extension_appeal_reconciliation_trigger"]),
				DueAt:                   parseSecureCellTransitionDueAtWithKey(meta, "federation_incident_directive_extension_appeal_reconciliation_due_at"),
				Actor:                   transition.Actor,
				AutomatedActor:          strings.TrimSpace(meta["automated_actor"]),
				Reason:                  transition.Reason,
				TransitionID:            transition.ID,
				OccurredAt:              occurredAt,
				Metadata:                cloneStringMap(meta),
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

func (s *Service) SweepFederationIncidentDirectiveExtensionAppealReconciliations(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-automation: service is required")
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

	report := &SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}
	overdueItems, err := s.ListOverdueFederationIncidentDirectiveExtensionAppealReconciliations(ctx, SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliationFilter{
		Before: &at,
	})
	if err != nil {
		return nil, err
	}
	selectedOverdue := make([]SecureCellOverdueFederationIncidentDirectiveExtensionAppealReconciliation, 0, len(overdueItems))
	selectedByKey := make(map[string]int, len(overdueItems))
	for _, item := range overdueItems {
		key := strings.TrimSpace(item.CellID) + "|" + strings.TrimSpace(item.ComparisonKey)
		if idx, ok := selectedByKey[key]; ok {
			existing := selectedOverdue[idx]
			itemPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationPriority(item.AutomationAction)
			existingPriority := secureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationPriority(existing.AutomationAction)
			if itemPriority > existingPriority || (itemPriority == existingPriority && item.DueAt.Before(existing.DueAt)) {
				selectedOverdue[idx] = item
			}
			continue
		}
		selectedByKey[key] = len(selectedOverdue)
		selectedOverdue = append(selectedOverdue, item)
	}
	sort.SliceStable(selectedOverdue, func(i, j int) bool {
		if selectedOverdue[i].DueAt.Equal(selectedOverdue[j].DueAt) {
			if selectedOverdue[i].CellID == selectedOverdue[j].CellID {
				return selectedOverdue[i].ComparisonKey < selectedOverdue[j].ComparisonKey
			}
			return selectedOverdue[i].CellID < selectedOverdue[j].CellID
		}
		return selectedOverdue[i].DueAt.Before(selectedOverdue[j].DueAt)
	})

	mutated := make(map[string]struct{})
	autoDisputed := make(map[string]struct{})
	escalated := make(map[string]struct{})
	suspendedOrgs := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		reconciliations := secureCellFederationIncidentDirectiveExtensionAppealReconciliationsFromRun(run)
		report.ReconciliationsScanned += len(reconciliations)
	}
	for _, overdue := range selectedOverdue {
		cellID := strings.TrimSpace(overdue.CellID)
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		reconciliation, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, overdue.ComparisonKey)
		if err != nil {
			return nil, err
		}
		baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_incident_directive_extension_appeal_reconciliation_sweep_mode":                "automated",
			"federation_incident_directive_extension_appeal_reconciliation_action":                    overdue.AutomationAction,
			"federation_incident_directive_extension_appeal_reconciliation_trigger":                   secureCellFederationIncidentDirectiveExtensionAppealReconciliationTrigger(overdue.AutomationAction),
			"federation_incident_directive_extension_appeal_reconciliation_comparison_key":            reconciliation.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":                    string(reconciliation.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review_status_before":      string(overdue.ReviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status_before": string(overdue.AttestationStatus),
			"federation_organization_id":                                              reconciliation.OrganizationID,
			"federation_sponsor_of_record":                                            reconciliation.SponsorOfRecord,
			"federation_incident_id":                                                  reconciliation.IncidentID,
			"federation_incident_response_id":                                         reconciliation.ResponseID,
			"federation_incident_directive_id":                                        reconciliation.DirectiveID,
			"federation_incident_directive_extension_id":                              reconciliation.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                      reconciliation.DisputeID,
			"federation_incident_directive_extension_appeal_id":                       reconciliation.AppealID,
			"federation_incident_directive_extension_local_appeal_id":                 reconciliation.LocalAppealID,
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id": reconciliation.CounterpartySnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":   reconciliation.CounterpartyBundleID,
			"federation_counterparty_incident_directive_extension_appeal_id":          reconciliation.CounterpartyAppealID,
		})
		if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
			baseMetadata["automated_actor"] = automatedActor
		}
		baseMetadata["federation_incident_directive_extension_appeal_reconciliation_due_at"] = overdue.DueAt.UTC().Format(time.RFC3339Nano)
		if overdue.ReviewDueAt != nil && !overdue.ReviewDueAt.IsZero() {
			baseMetadata["federation_incident_directive_extension_appeal_reconciliation_review_due_at"] = overdue.ReviewDueAt.UTC().Format(time.RFC3339Nano)
		}
		if overdue.CounterpartyAcknowledgeDueAt != nil && !overdue.CounterpartyAcknowledgeDueAt.IsZero() {
			baseMetadata["federation_incident_directive_extension_appeal_reconciliation_counterparty_ack_due_at"] = overdue.CounterpartyAcknowledgeDueAt.UTC().Format(time.RFC3339Nano)
		}
		if overdue.ResolutionDueAt != nil && !overdue.ResolutionDueAt.IsZero() {
			baseMetadata["federation_incident_directive_extension_appeal_reconciliation_resolution_due_at"] = overdue.ResolutionDueAt.UTC().Format(time.RFC3339Nano)
		}

		switch overdue.AutomationAction {
		case "auto_dispute":
			key := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.ComparisonKey)
			if _, seen := autoDisputed[key]; seen {
				continue
			}
			if _, err := s.DisputeFederationIncidentDirectiveExtensionAppealReconciliation(ctx, cellID, reconciliation.ComparisonKey, SecureCellFederationIncidentDirectiveExtensionAppealReconciliationDisputeRequest{
				ActorDID:    run.request.OwnerIdentity.AgentID(),
				Reason:      firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.OverdueReason),
				Divergences: append([]string(nil), reconciliation.Divergences...),
				Metadata: mergeStringMaps(baseMetadata, map[string]string{
					"federation_incident_directive_extension_appeal_reconciliation_review_status_after":      string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed),
					"federation_incident_directive_extension_appeal_reconciliation_attestation_status_after": string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested),
				}),
			}); err != nil {
				return nil, err
			}
			autoDisputed[key] = struct{}{}
			report.ReconciliationsAutoDisputed++
			mutated[cellID] = struct{}{}
		case "escalate_counterparty":
			key := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.ComparisonKey)
			if _, seen := escalated[key]; seen {
				continue
			}
			if _, err := s.recordFederationIncidentDirectiveExtensionAppealReconciliationEscalation(ctx, cellID, reconciliation.ComparisonKey, SecureCellLifecycleRequest{
				ActorDID: run.request.OwnerIdentity.AgentID(),
				Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.OverdueReason),
				Metadata: mergeStringMaps(baseMetadata, map[string]string{
					"federation_incident_directive_extension_appeal_reconciliation_review_status_after":      string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed),
					"federation_incident_directive_extension_appeal_reconciliation_attestation_status_after": string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested),
				}),
			}); err != nil {
				return nil, err
			}
			escalated[key] = struct{}{}
			report.ReconciliationsEscalated++
			mutated[cellID] = struct{}{}
		case "suspend_contracts":
			orgKey := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.OrganizationID)
			if _, seen := suspendedOrgs[orgKey]; seen {
				continue
			}
			activeContracts := activeFederationContractsForOrganization(run.result.FederationContracts, reconciliation.OrganizationID)
			if len(activeContracts) == 0 {
				continue
			}
			for _, contract := range activeContracts {
				if _, err := s.SuspendFederationContract(ctx, cellID, contract.ID, SecureCellLifecycleRequest{
					ActorDID: run.request.OwnerIdentity.AgentID(),
					Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.OverdueReason),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_contract_id":            contract.ID,
						"federation_contract_status_before": string(contract.Status),
						"federation_contract_status_after":  string(SecureCellFederationContractStatusSuspended),
						"federation_incident_directive_extension_appeal_reconciliation_review_status_after":      string(SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed),
						"federation_incident_directive_extension_appeal_reconciliation_attestation_status_after": string(overdue.AttestationStatus),
					}),
				}); err != nil {
					return nil, err
				}
				report.ContractsSuspended++
			}
			suspendedOrgs[orgKey] = struct{}{}
			mutated[cellID] = struct{}{}
		}
	}
	report.CellsMutated = len(mutated)
	if len(mutated) > 0 {
		report.CellIDs = make([]string, 0, len(mutated))
		for cellID := range mutated {
			report.CellIDs = append(report.CellIDs, cellID)
		}
		sort.Strings(report.CellIDs)
	}
	return report, nil
}

func (s *Service) recordFederationIncidentDirectiveExtensionAppealReconciliationEscalation(ctx context.Context, cellID string, comparisonKey string, lifecycle SecureCellLifecycleRequest) (*SecureCellResult, error) {
	run, err := s.getRun(cellID)
	if err != nil {
		return nil, err
	}
	if err := ensureCellMutable(run.result); err != nil {
		return nil, err
	}
	summary, err := secureCellFederationIncidentDirectiveExtensionAppealReconciliationSummaryByKey(run, comparisonKey)
	if err != nil {
		return nil, err
	}
	actorDID := firstNonEmpty(strings.TrimSpace(lifecycle.ActorDID), run.request.OwnerIdentity.AgentID())
	if !secureCellActorAllowed(run, actorDID, true) {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-automation: %w: actor %q is not permitted to escalate reconciliation %q", ErrPolicyDenied, actorDID, comparisonKey)
	}
	reviewStatus := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(summary)
	attestationStatus := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(summary)
	receipt, err := s.evaluateStage(ctx, run.request, "escalate_federation_incident_directive_extension_appeal_reconciliation", lastReceiptHash(run.result), map[string]string{
		"federation_organization_id":                                                       summary.OrganizationID,
		"federation_incident_id":                                                           summary.IncidentID,
		"federation_incident_response_id":                                                  summary.ResponseID,
		"federation_incident_directive_id":                                                 summary.DirectiveID,
		"federation_incident_directive_extension_id":                                       summary.ExtensionID,
		"federation_incident_directive_extension_dispute_id":                               summary.DisputeID,
		"federation_incident_directive_extension_appeal_id":                                summary.AppealID,
		"federation_incident_directive_extension_appeal_reconciliation_key":                summary.ComparisonKey,
		"federation_incident_directive_extension_appeal_reconciliation_status":             string(summary.Status),
		"federation_incident_directive_extension_appeal_reconciliation_review":             string(reviewStatus),
		"federation_incident_directive_extension_appeal_reconciliation_attestation_status": string(attestationStatus),
		"federation_incident_directive_extension_local_appeal_id":                          summary.LocalAppealID,
		"federation_counterparty_incident_directive_extension_appeal_snapshot_id":          summary.CounterpartySnapshotID,
		"federation_counterparty_incident_directive_extension_appeal_bundle_id":            summary.CounterpartyBundleID,
		"federation_counterparty_incident_directive_extension_appeal_id":                   summary.CounterpartyAppealID,
		"transition_reason": strings.TrimSpace(lifecycle.Reason),
	}, actorDID)
	if err != nil {
		return nil, err
	}
	if receipt.Decision != policy.Allow.String() {
		return nil, fmt.Errorf("securecells/federation-incident-directive-extension-appeal-reconciliation-automation: %w", ErrPolicyDenied)
	}
	transition := SecureCellTransition{
		ID:               transitionID(run.request, "federation_incident_directive_extension_appeal_reconciliation_escalated", summary.ComparisonKey),
		Action:           "secure_cell.federation_incident_directive_extension_appeal_reconciliation_escalated",
		Actor:            actorDID,
		TargetType:       "federation_incident_directive_extension_appeal_reconciliation",
		TargetDID:        summary.ComparisonKey,
		CellStatusBefore: run.result.Status,
		CellStatusAfter:  run.result.Status,
		PolicyReceipt:    cloneSignedPolicyReceipt(receipt),
		Reason:           strings.TrimSpace(lifecycle.Reason),
		Metadata: mergeStringMaps(lifecycle.Metadata, map[string]string{
			"federation_organization_id":                                                       summary.OrganizationID,
			"federation_sponsor_of_record":                                                     summary.SponsorOfRecord,
			"federation_organization_name":                                                     summary.OrganizationName,
			"federation_incident_id":                                                           summary.IncidentID,
			"federation_incident_response_id":                                                  summary.ResponseID,
			"federation_incident_directive_id":                                                 summary.DirectiveID,
			"federation_incident_directive_extension_id":                                       summary.ExtensionID,
			"federation_incident_directive_extension_dispute_id":                               summary.DisputeID,
			"federation_incident_directive_extension_appeal_id":                                summary.AppealID,
			"federation_incident_directive_extension_appeal_reconciliation_key":                summary.ComparisonKey,
			"federation_incident_directive_extension_appeal_reconciliation_status":             string(summary.Status),
			"federation_incident_directive_extension_appeal_reconciliation_review":             string(reviewStatus),
			"federation_incident_directive_extension_appeal_reconciliation_attestation_status": string(attestationStatus),
			"federation_incident_directive_extension_local_appeal_id":                          summary.LocalAppealID,
			"federation_counterparty_incident_directive_extension_appeal_snapshot_id":          summary.CounterpartySnapshotID,
			"federation_counterparty_incident_directive_extension_appeal_bundle_id":            summary.CounterpartyBundleID,
			"federation_counterparty_incident_directive_extension_appeal_id":                   summary.CounterpartyAppealID,
		}),
		OccurredAt: receipt.EvaluatedAt.UTC(),
	}
	if err := s.rebuildArtifacts(ctx, run, receipt, transition); err != nil {
		return nil, err
	}
	s.setRun(run)
	return cloneResult(run.result)
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionOrAttestationRequiresGovernedReview(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) bool {
	if item.Status != "" && item.Status != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationStatusAligned {
		return true
	}
	if item.ReviewActionCount > 0 {
		return true
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() {
		return true
	}
	if item.CounterpartyAttestationCount > 0 {
		return true
	}
	if item.LastCounterpartyAttestedAt != nil && !item.LastCounterpartyAttestedAt.IsZero() {
		return true
	}
	if item.ReviewStatus != "" && item.ReviewStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed {
		return true
	}
	if item.AttestationStatus != "" && item.AttestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested {
		return true
	}
	return false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationBaselineAt(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) *time.Time {
	var baseline *time.Time
	for _, candidate := range []*time.Time{item.LocalUpdatedAt, item.CounterpartyReceivedAt, item.CounterpartyGeneratedAt} {
		if candidate == nil || candidate.IsZero() {
			continue
		}
		if baseline == nil || candidate.UTC().After(baseline.UTC()) {
			value := candidate.UTC()
			baseline = &value
		}
	}
	return baseline
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatus {
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested
	}
	if item.LastCounterpartyAttestedAt == nil || item.LastCounterpartyAttestedAt.IsZero() {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() && item.LastCounterpartyAttestedAt.Before(*item.LastReviewedAt) {
		return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested
	}
	if item.AttestationStatus != "" {
		return item.AttestationStatus
	}
	return SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewDueAt(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) *time.Time {
	if !secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionOrAttestationRequiresGovernedReview(item) {
		return nil
	}
	baseline := secureCellFederationIncidentDirectiveExtensionAppealReconciliationBaselineAt(item)
	if baseline == nil {
		return nil
	}
	dueAt := baseline.Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewSLA)
	return &dueAt
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeDueAt(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) *time.Time {
	if item.LastReviewedAt == nil || item.LastReviewedAt.IsZero() {
		return nil
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed {
		return nil
	}
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(item) != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested {
		return nil
	}
	dueAt := item.LastReviewedAt.Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAckSLA)
	return &dueAt
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionDueAt(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary) *time.Time {
	if secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed {
		return nil
	}
	status := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(item)
	if status == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved {
		return nil
	}
	if item.LastCounterpartyAttestedAt != nil && !item.LastCounterpartyAttestedAt.IsZero() && (status == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusAcknowledged || status == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusCorrected) {
		dueAt := item.LastCounterpartyAttestedAt.Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionSLA)
		return &dueAt
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() {
		dueAt := item.LastReviewedAt.Add(secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionSLA)
		return &dueAt
	}
	return nil
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueStateForAt(item SecureCellFederationIncidentDirectiveExtensionAppealReconciliationSummary, at time.Time) (secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState, bool) {
	if !secureCellFederationIncidentDirectiveExtensionAppealReconciliationActionOrAttestationRequiresGovernedReview(item) {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState{}, false
	}
	reviewStatus := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveReviewStatus(item)
	attestationStatus := secureCellFederationIncidentDirectiveExtensionAppealReconciliationEffectiveCounterpartyAttestationStatus(item)
	reviewDueAt := secureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewDueAt(item)
	if reviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusUnreviewed && strings.TrimSpace(item.CounterpartySnapshotID) != "" && reviewDueAt != nil && !reviewDueAt.After(at) {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState{
			reviewStatus:      reviewStatus,
			attestationStatus: attestationStatus,
			automationAction:  "auto_dispute",
			overdueReason:     "incident directive extension appeal reconciliation review deadline reached",
			dueAt:             reviewDueAt.UTC(),
			reviewDueAt:       cloneTimePtr(reviewDueAt),
		}, true
	}
	counterpartyAckDueAt := secureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAcknowledgeDueAt(item)
	if reviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed && attestationStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusUnattested && counterpartyAckDueAt != nil && !counterpartyAckDueAt.After(at) {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState{
			reviewStatus:         reviewStatus,
			attestationStatus:    attestationStatus,
			automationAction:     "escalate_counterparty",
			overdueReason:        "counterparty appeal dispute acknowledgement deadline reached",
			dueAt:                counterpartyAckDueAt.UTC(),
			reviewDueAt:          cloneTimePtr(reviewDueAt),
			counterpartyAckDueAt: cloneTimePtr(counterpartyAckDueAt),
		}, true
	}
	resolutionDueAt := secureCellFederationIncidentDirectiveExtensionAppealReconciliationResolutionDueAt(item)
	if reviewStatus == SecureCellFederationIncidentDirectiveExtensionAppealReconciliationReviewStatusDisputed && attestationStatus != SecureCellFederationIncidentDirectiveExtensionAppealReconciliationCounterpartyAttestationStatusResolved && resolutionDueAt != nil && !resolutionDueAt.After(at) {
		return secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState{
			reviewStatus:         reviewStatus,
			attestationStatus:    attestationStatus,
			automationAction:     "suspend_contracts",
			overdueReason:        "incident directive extension appeal reconciliation resolution deadline reached",
			dueAt:                resolutionDueAt.UTC(),
			reviewDueAt:          cloneTimePtr(reviewDueAt),
			counterpartyAckDueAt: cloneTimePtr(counterpartyAckDueAt),
			resolutionDueAt:      cloneTimePtr(resolutionDueAt),
		}, true
	}
	return secureCellFederationIncidentDirectiveExtensionAppealReconciliationOverdueState{}, false
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationTrigger(action string) string {
	switch strings.TrimSpace(action) {
	case "auto_dispute":
		return "review_due"
	case "escalate_counterparty":
		return "counterparty_ack_due"
	case "suspend_contracts":
		return "resolution_due"
	default:
		return ""
	}
}

func secureCellFederationIncidentDirectiveExtensionAppealReconciliationAutomationPriority(action string) int {
	switch strings.TrimSpace(action) {
	case "suspend_contracts":
		return 3
	case "escalate_counterparty":
		return 2
	case "auto_dispute":
		return 1
	default:
		return 0
	}
}

func secureCellTransitionAutomatedFederationIncidentDirectiveExtensionAppealReconciliationAction(transition SecureCellTransition) bool {
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_extension_appeal_reconciliation_sweep_mode"]), "automated")
}
