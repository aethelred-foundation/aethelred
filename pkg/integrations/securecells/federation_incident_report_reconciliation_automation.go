package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	secureCellFederationIncidentReportReconciliationReviewSLA     = 6 * time.Hour
	secureCellFederationIncidentReportReconciliationResolutionSLA = 24 * time.Hour
)

// SecureCellOverdueFederationIncidentReportReconciliationFilter narrows
// operator queries over bilateral filing reconciliations that crossed a
// governed review or dispute-resolution deadline.
type SecureCellOverdueFederationIncidentReportReconciliationFilter struct {
	CellID         string                                                 `json:"cell_id,omitempty"`
	OrganizationID string                                                 `json:"organization_id,omitempty"`
	IncidentID     string                                                 `json:"incident_id,omitempty"`
	ComparisonKey  string                                                 `json:"comparison_key,omitempty"`
	Status         SecureCellFederationIncidentReportReconciliationStatus `json:"status,omitempty"`
	ReviewStatus   SecureCellFederationIncidentReportReviewStatus         `json:"review_status,omitempty"`
	Before         *time.Time                                             `json:"before,omitempty"`
	Limit          int                                                    `json:"limit,omitempty"`
}

// SecureCellOverdueFederationIncidentReportReconciliation projects one filing
// reconciliation whose next governed milestone is overdue.
type SecureCellOverdueFederationIncidentReportReconciliation struct {
	CellID               string                                                 `json:"cell_id"`
	CellName             string                                                 `json:"cell_name,omitempty"`
	Jurisdiction         string                                                 `json:"jurisdiction,omitempty"`
	CellStatus           SecureCellStatus                                       `json:"cell_status"`
	OrganizationID       string                                                 `json:"organization_id"`
	SponsorOfRecord      string                                                 `json:"sponsor_of_record,omitempty"`
	OrganizationName     string                                                 `json:"organization_name,omitempty"`
	ComparisonKey        string                                                 `json:"comparison_key"`
	IncidentID           string                                                 `json:"incident_id,omitempty"`
	Regulator            string                                                 `json:"regulator,omitempty"`
	Framework            string                                                 `json:"framework,omitempty"`
	ReportType           string                                                 `json:"report_type,omitempty"`
	ReportingParty       SecureCellFederationIncidentResponseParty              `json:"reporting_party,omitempty"`
	Status               SecureCellFederationIncidentReportReconciliationStatus `json:"status"`
	ReviewStatus         SecureCellFederationIncidentReportReviewStatus         `json:"review_status"`
	AutomationAction     string                                                 `json:"automation_action"`
	OverdueReason        string                                                 `json:"overdue_reason"`
	DueAt                time.Time                                              `json:"due_at"`
	OverdueSeconds       int64                                                  `json:"overdue_seconds"`
	ReviewDueAt          *time.Time                                             `json:"review_due_at,omitempty"`
	ResolutionDueAt      *time.Time                                             `json:"resolution_due_at,omitempty"`
	LocalReportID        string                                                 `json:"local_report_id,omitempty"`
	CounterpartyReportID string                                                 `json:"counterparty_report_id,omitempty"`
	LastReviewedBy       string                                                 `json:"last_reviewed_by,omitempty"`
	LastReviewedAt       *time.Time                                             `json:"last_reviewed_at,omitempty"`
	Divergences          []string                                               `json:"divergences,omitempty"`
	UpdatedAt            time.Time                                              `json:"updated_at"`
}

// SecureCellFederationIncidentReportReconciliationAutomationActionFilter
// narrows operator queries over automated reconciliation actions.
type SecureCellFederationIncidentReportReconciliationAutomationActionFilter struct {
	CellID         string     `json:"cell_id,omitempty"`
	OrganizationID string     `json:"organization_id,omitempty"`
	IncidentID     string     `json:"incident_id,omitempty"`
	ComparisonKey  string     `json:"comparison_key,omitempty"`
	ContractID     string     `json:"contract_id,omitempty"`
	Action         string     `json:"action,omitempty"`
	Since          *time.Time `json:"since,omitempty"`
	Until          *time.Time `json:"until,omitempty"`
	Limit          int        `json:"limit,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationAutomationActionRecord
// projects one automated protective action applied against bilateral filing
// drift or an unresolved reconciliation dispute.
type SecureCellFederationIncidentReportReconciliationAutomationActionRecord struct {
	CellID               string                                                 `json:"cell_id"`
	CellName             string                                                 `json:"cell_name,omitempty"`
	Jurisdiction         string                                                 `json:"jurisdiction,omitempty"`
	CellStatus           SecureCellStatus                                       `json:"cell_status"`
	OrganizationID       string                                                 `json:"organization_id,omitempty"`
	SponsorOfRecord      string                                                 `json:"sponsor_of_record,omitempty"`
	ComparisonKey        string                                                 `json:"comparison_key,omitempty"`
	IncidentID           string                                                 `json:"incident_id,omitempty"`
	Regulator            string                                                 `json:"regulator,omitempty"`
	ReconciliationStatus SecureCellFederationIncidentReportReconciliationStatus `json:"reconciliation_status,omitempty"`
	ReviewStatusBefore   SecureCellFederationIncidentReportReviewStatus         `json:"review_status_before,omitempty"`
	ReviewStatusAfter    SecureCellFederationIncidentReportReviewStatus         `json:"review_status_after,omitempty"`
	ContractID           string                                                 `json:"contract_id,omitempty"`
	ContractStatusBefore SecureCellFederationContractStatus                     `json:"contract_status_before,omitempty"`
	ContractStatusAfter  SecureCellFederationContractStatus                     `json:"contract_status_after,omitempty"`
	Action               string                                                 `json:"action"`
	Trigger              string                                                 `json:"trigger,omitempty"`
	DueAt                *time.Time                                             `json:"due_at,omitempty"`
	Actor                string                                                 `json:"actor"`
	AutomatedActor       string                                                 `json:"automated_actor,omitempty"`
	Reason               string                                                 `json:"reason,omitempty"`
	TransitionID         string                                                 `json:"transition_id"`
	OccurredAt           time.Time                                              `json:"occurred_at"`
	Metadata             map[string]string                                      `json:"metadata,omitempty"`
}

// SecureCellFederationIncidentReportReconciliationSweepResult summarizes one
// automated reconciliation sweep across the live secure-cell fleet.
type SecureCellFederationIncidentReportReconciliationSweepResult struct {
	At                          time.Time `json:"at"`
	CellsScanned                int       `json:"cells_scanned"`
	ReconciliationsScanned      int       `json:"reconciliations_scanned"`
	CellsMutated                int       `json:"cells_mutated"`
	ReconciliationsAutoDisputed int       `json:"reconciliations_auto_disputed"`
	ContractsSuspended          int       `json:"contracts_suspended"`
	CellIDs                     []string  `json:"cell_ids,omitempty"`
}

type secureCellFederationIncidentReportReconciliationOverdueState struct {
	reviewStatus     SecureCellFederationIncidentReportReviewStatus
	automationAction string
	overdueReason    string
	dueAt            time.Time
	reviewDueAt      *time.Time
	resolutionDueAt  *time.Time
}

// ListOverdueFederationIncidentReportReconciliations returns operator-facing
// projections for filing reconciliations whose next governed milestone is overdue.
func (s *Service) ListOverdueFederationIncidentReportReconciliations(_ context.Context, filter SecureCellOverdueFederationIncidentReportReconciliationFilter) ([]SecureCellOverdueFederationIncidentReportReconciliation, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	incidentID := strings.TrimSpace(filter.IncidentID)
	comparisonKey := strings.TrimSpace(filter.ComparisonKey)

	items := make([]SecureCellOverdueFederationIncidentReportReconciliation, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, reconciliation := range secureCellFederationIncidentReportReconciliationsFromRun(run) {
			if organizationID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.OrganizationID), organizationID) {
				continue
			}
			if incidentID != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.IncidentID), incidentID) {
				continue
			}
			if comparisonKey != "" && !strings.EqualFold(strings.TrimSpace(reconciliation.ComparisonKey), comparisonKey) {
				continue
			}
			if filter.Status != "" && reconciliation.Status != filter.Status {
				continue
			}
			overdue, ok := secureCellFederationIncidentReportReconciliationOverdueStateForAt(reconciliation, at)
			if !ok {
				continue
			}
			if filter.ReviewStatus != "" && overdue.reviewStatus != filter.ReviewStatus {
				continue
			}
			items = append(items, SecureCellOverdueFederationIncidentReportReconciliation{
				CellID:               reconciliation.CellID,
				CellName:             reconciliation.CellName,
				Jurisdiction:         reconciliation.Jurisdiction,
				CellStatus:           reconciliation.CellStatus,
				OrganizationID:       reconciliation.OrganizationID,
				SponsorOfRecord:      reconciliation.SponsorOfRecord,
				OrganizationName:     reconciliation.OrganizationName,
				ComparisonKey:        reconciliation.ComparisonKey,
				IncidentID:           reconciliation.IncidentID,
				Regulator:            reconciliation.Regulator,
				Framework:            reconciliation.Framework,
				ReportType:           reconciliation.ReportType,
				ReportingParty:       reconciliation.ReportingParty,
				Status:               reconciliation.Status,
				ReviewStatus:         overdue.reviewStatus,
				AutomationAction:     overdue.automationAction,
				OverdueReason:        overdue.overdueReason,
				DueAt:                overdue.dueAt,
				OverdueSeconds:       int64(at.Sub(overdue.dueAt).Seconds()),
				ReviewDueAt:          cloneTimePtr(overdue.reviewDueAt),
				ResolutionDueAt:      cloneTimePtr(overdue.resolutionDueAt),
				LocalReportID:        reconciliation.LocalReportID,
				CounterpartyReportID: reconciliation.CounterpartyReportID,
				LastReviewedBy:       reconciliation.LastReviewedBy,
				LastReviewedAt:       cloneTimePtr(reconciliation.LastReviewedAt),
				Divergences:          append([]string(nil), reconciliation.Divergences...),
				UpdatedAt:            secureCellFederationIncidentReportReconciliationUpdatedAt(reconciliation),
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

// ListFederationIncidentReportReconciliationAutomationActions returns
// automated protective actions already applied by reconciliation SLA sweeps.
func (s *Service) ListFederationIncidentReportReconciliationAutomationActions(_ context.Context, filter SecureCellFederationIncidentReportReconciliationAutomationActionFilter) ([]SecureCellFederationIncidentReportReconciliationAutomationActionRecord, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	cellID := strings.TrimSpace(filter.CellID)
	organizationID := strings.TrimSpace(filter.OrganizationID)
	incidentID := strings.TrimSpace(filter.IncidentID)
	comparisonKey := strings.TrimSpace(filter.ComparisonKey)
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

	items := make([]SecureCellFederationIncidentReportReconciliationAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentReportReconciliationAction(transition) {
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
			if comparisonKey != "" && !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_comparison_key"]), comparisonKey) {
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
			items = append(items, SecureCellFederationIncidentReportReconciliationAutomationActionRecord{
				CellID:               run.result.CellID,
				CellName:             run.result.Name,
				Jurisdiction:         run.request.Jurisdiction,
				CellStatus:           run.result.Status,
				OrganizationID:       strings.TrimSpace(transition.Metadata["federation_organization_id"]),
				SponsorOfRecord:      strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
				ComparisonKey:        strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_comparison_key"]),
				IncidentID:           strings.TrimSpace(transition.Metadata["federation_incident_id"]),
				Regulator:            strings.TrimSpace(transition.Metadata["federation_regulator"]),
				ReconciliationStatus: SecureCellFederationIncidentReportReconciliationStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_status"])),
				ReviewStatusBefore:   SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_review_status_before"])),
				ReviewStatusAfter:    SecureCellFederationIncidentReportReviewStatus(strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_review_status_after"])),
				ContractID:           strings.TrimSpace(transition.Metadata["federation_contract_id"]),
				ContractStatusBefore: SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_before"])),
				ContractStatusAfter:  SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_after"])),
				Action:               transition.Action,
				Trigger:              strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_trigger"]),
				DueAt:                parseSecureCellTransitionDueAtWithKey(transition.Metadata, "federation_incident_report_reconciliation_due_at"),
				Actor:                transition.Actor,
				AutomatedActor:       strings.TrimSpace(transition.Metadata["automated_actor"]),
				Reason:               transition.Reason,
				TransitionID:         transition.ID,
				OccurredAt:           occurredAt,
				Metadata:             cloneStringMap(transition.Metadata),
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

// SweepFederationIncidentReportReconciliations applies automated protective
// dispute and containment rules to stale bilateral filing reconciliations.
func (s *Service) SweepFederationIncidentReportReconciliations(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentReportReconciliationSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-report-reconciliation: service is required")
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

	report := &SecureCellFederationIncidentReportReconciliationSweepResult{
		At:           at.UTC(),
		CellsScanned: len(cellIDs),
	}
	if len(cellIDs) == 0 {
		return report, nil
	}

	mutated := make(map[string]struct{})
	autoDisputed := make(map[string]struct{})
	suspendedOrgs := make(map[string]struct{})
	for _, cellID := range cellIDs {
		run, err := s.getRun(cellID)
		if err != nil {
			return nil, err
		}
		reconciliations := secureCellFederationIncidentReportReconciliationsFromRun(run)
		report.ReconciliationsScanned += len(reconciliations)
		for _, reconciliation := range reconciliations {
			overdue, ok := secureCellFederationIncidentReportReconciliationOverdueStateForAt(reconciliation, at)
			if !ok {
				continue
			}
			baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
				"federation_incident_report_reconciliation_sweep_mode":           "automated",
				"federation_incident_report_reconciliation_action":               overdue.automationAction,
				"federation_incident_report_reconciliation_trigger":              secureCellFederationIncidentReportReconciliationTrigger(overdue.automationAction),
				"federation_incident_report_reconciliation_comparison_key":       reconciliation.ComparisonKey,
				"federation_incident_report_reconciliation_status":               string(reconciliation.Status),
				"federation_incident_report_reconciliation_review_status_before": string(overdue.reviewStatus),
				"federation_organization_id":                                     reconciliation.OrganizationID,
				"federation_sponsor_of_record":                                   reconciliation.SponsorOfRecord,
				"federation_incident_id":                                         reconciliation.IncidentID,
				"federation_regulator":                                           reconciliation.Regulator,
				"federation_incident_report_reconciliation_local_report_id":      reconciliation.LocalReportID,
				"federation_counterparty_incident_report_id":                     reconciliation.CounterpartyReportID,
			})
			if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
				baseMetadata["automated_actor"] = automatedActor
			}
			baseMetadata["federation_incident_report_reconciliation_due_at"] = overdue.dueAt.UTC().Format(time.RFC3339Nano)
			if overdue.reviewDueAt != nil && !overdue.reviewDueAt.IsZero() {
				baseMetadata["federation_incident_report_reconciliation_review_due_at"] = overdue.reviewDueAt.UTC().Format(time.RFC3339Nano)
			}
			if overdue.resolutionDueAt != nil && !overdue.resolutionDueAt.IsZero() {
				baseMetadata["federation_incident_report_reconciliation_resolution_due_at"] = overdue.resolutionDueAt.UTC().Format(time.RFC3339Nano)
			}

			switch overdue.automationAction {
			case "auto_dispute":
				key := strings.TrimSpace(reconciliation.CellID) + "|" + strings.TrimSpace(reconciliation.ComparisonKey)
				if _, seen := autoDisputed[key]; seen {
					continue
				}
				if _, err := s.DisputeFederationIncidentReportReconciliation(ctx, cellID, reconciliation.ComparisonKey, SecureCellFederationIncidentReportReconciliationDisputeRequest{
					ActorDID:    run.request.OwnerIdentity.AgentID(),
					Reason:      firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.overdueReason),
					Divergences: append([]string(nil), reconciliation.Divergences...),
					Metadata: mergeStringMaps(baseMetadata, map[string]string{
						"federation_incident_report_reconciliation_review_status_after": string(SecureCellFederationIncidentReportReviewStatusDisputed),
					}),
				}); err != nil {
					return nil, err
				}
				autoDisputed[key] = struct{}{}
				report.ReconciliationsAutoDisputed++
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
						Reason:   firstNonEmpty(strings.TrimSpace(lifecycle.Reason), overdue.overdueReason),
						Metadata: mergeStringMaps(baseMetadata, map[string]string{
							"federation_contract_id":                                        contract.ID,
							"federation_contract_status_before":                             string(contract.Status),
							"federation_contract_status_after":                              string(SecureCellFederationContractStatusSuspended),
							"federation_incident_report_reconciliation_review_status_after": string(SecureCellFederationIncidentReportReviewStatusDisputed),
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

func secureCellFederationIncidentReportReconciliationRequiresGovernedReview(item SecureCellFederationIncidentReportReconciliationSummary) bool {
	return item.Status != "" && item.Status != SecureCellFederationIncidentReportReconciliationStatusAligned
}

func secureCellFederationIncidentReportReconciliationBaselineAt(item SecureCellFederationIncidentReportReconciliationSummary) *time.Time {
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

func secureCellFederationIncidentReportReconciliationUpdatedAt(item SecureCellFederationIncidentReportReconciliationSummary) time.Time {
	if baseline := secureCellFederationIncidentReportReconciliationBaselineAt(item); baseline != nil {
		return baseline.UTC()
	}
	if item.LastReviewedAt != nil && !item.LastReviewedAt.IsZero() {
		return item.LastReviewedAt.UTC()
	}
	return time.Time{}
}

func secureCellFederationIncidentReportReconciliationEffectiveReviewStatus(item SecureCellFederationIncidentReportReconciliationSummary) SecureCellFederationIncidentReportReviewStatus {
	if !secureCellFederationIncidentReportReconciliationRequiresGovernedReview(item) {
		return item.ReviewStatus
	}
	baseline := secureCellFederationIncidentReportReconciliationBaselineAt(item)
	if baseline != nil && (item.LastReviewedAt == nil || item.LastReviewedAt.Before(*baseline)) {
		return SecureCellFederationIncidentReportReviewStatusUnreviewed
	}
	if item.ReviewStatus != "" {
		return item.ReviewStatus
	}
	return SecureCellFederationIncidentReportReviewStatusUnreviewed
}

func secureCellFederationIncidentReportReconciliationReviewDueAt(item SecureCellFederationIncidentReportReconciliationSummary) *time.Time {
	if !secureCellFederationIncidentReportReconciliationRequiresGovernedReview(item) {
		return nil
	}
	baseline := secureCellFederationIncidentReportReconciliationBaselineAt(item)
	if baseline == nil {
		return nil
	}
	dueAt := baseline.Add(secureCellFederationIncidentReportReconciliationReviewSLA)
	return &dueAt
}

func secureCellFederationIncidentReportReconciliationResolutionDueAt(item SecureCellFederationIncidentReportReconciliationSummary) *time.Time {
	if item.LastReviewedAt == nil || item.LastReviewedAt.IsZero() {
		return nil
	}
	if secureCellFederationIncidentReportReconciliationEffectiveReviewStatus(item) != SecureCellFederationIncidentReportReviewStatusDisputed {
		return nil
	}
	dueAt := item.LastReviewedAt.Add(secureCellFederationIncidentReportReconciliationResolutionSLA)
	return &dueAt
}

func secureCellFederationIncidentReportReconciliationOverdueStateForAt(item SecureCellFederationIncidentReportReconciliationSummary, at time.Time) (secureCellFederationIncidentReportReconciliationOverdueState, bool) {
	if !secureCellFederationIncidentReportReconciliationRequiresGovernedReview(item) {
		return secureCellFederationIncidentReportReconciliationOverdueState{}, false
	}
	reviewStatus := secureCellFederationIncidentReportReconciliationEffectiveReviewStatus(item)
	reviewDueAt := secureCellFederationIncidentReportReconciliationReviewDueAt(item)
	if reviewStatus == SecureCellFederationIncidentReportReviewStatusUnreviewed && reviewDueAt != nil && !reviewDueAt.After(at) {
		return secureCellFederationIncidentReportReconciliationOverdueState{
			reviewStatus:     reviewStatus,
			automationAction: "auto_dispute",
			overdueReason:    "incident report reconciliation review deadline reached",
			dueAt:            reviewDueAt.UTC(),
			reviewDueAt:      cloneTimePtr(reviewDueAt),
		}, true
	}
	resolutionDueAt := secureCellFederationIncidentReportReconciliationResolutionDueAt(item)
	if reviewStatus == SecureCellFederationIncidentReportReviewStatusDisputed && resolutionDueAt != nil && !resolutionDueAt.After(at) {
		return secureCellFederationIncidentReportReconciliationOverdueState{
			reviewStatus:     reviewStatus,
			automationAction: "suspend_contracts",
			overdueReason:    "incident report reconciliation dispute resolution deadline reached",
			dueAt:            resolutionDueAt.UTC(),
			reviewDueAt:      cloneTimePtr(reviewDueAt),
			resolutionDueAt:  cloneTimePtr(resolutionDueAt),
		}, true
	}
	return secureCellFederationIncidentReportReconciliationOverdueState{}, false
}

func secureCellFederationIncidentReportReconciliationTrigger(action string) string {
	switch strings.TrimSpace(action) {
	case "auto_dispute":
		return "review_due"
	case "suspend_contracts":
		return "resolution_due"
	default:
		return ""
	}
}

func secureCellTransitionAutomatedFederationIncidentReportReconciliationAction(transition SecureCellTransition) bool {
	if strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_report_reconciliation_sweep_mode"]), "automated") {
		return true
	}
	return false
}

func parseSecureCellTransitionDueAtWithKey(metadata map[string]string, key string) *time.Time {
	value := strings.TrimSpace(metadata[key])
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil
	}
	utc := parsed.UTC()
	return &utc
}
