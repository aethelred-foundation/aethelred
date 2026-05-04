package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type secureCellFederationIncidentDirectiveAutomationPlan struct {
	action        string
	trigger       string
	reason        string
	pendingAction string
	dueAt         time.Time
	tierID        string
	targetDID     string
}

// ListFederationIncidentDirectiveAutomationActions returns automated directive
// supervision actions already applied by the live runtime.
func (s *Service) ListFederationIncidentDirectiveAutomationActions(_ context.Context, filter SecureCellFederationIncidentDirectiveAutomationActionFilter) ([]SecureCellFederationIncidentDirectiveAutomationActionRecord, error) {
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

	items := make([]SecureCellFederationIncidentDirectiveAutomationActionRecord, 0)
	for _, run := range s.runs {
		if run == nil || run.result == nil {
			continue
		}
		if cellID != "" && !strings.EqualFold(strings.TrimSpace(run.result.CellID), cellID) {
			continue
		}
		for _, transition := range run.result.Transitions {
			if !secureCellTransitionAutomatedFederationIncidentDirectiveAction(transition) {
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
			items = append(items, SecureCellFederationIncidentDirectiveAutomationActionRecord{
				CellID:               strings.TrimSpace(run.result.CellID),
				CellName:             strings.TrimSpace(run.result.Name),
				Jurisdiction:         strings.TrimSpace(run.request.Jurisdiction),
				CellStatus:           run.result.Status,
				OrganizationID:       strings.TrimSpace(transition.Metadata["federation_organization_id"]),
				SponsorOfRecord:      strings.TrimSpace(transition.Metadata["federation_sponsor_of_record"]),
				IncidentID:           strings.TrimSpace(transition.Metadata["federation_incident_id"]),
				ResponseID:           strings.TrimSpace(transition.Metadata["federation_incident_response_id"]),
				DirectiveID:          strings.TrimSpace(transition.Metadata["federation_incident_directive_id"]),
				DirectiveTitle:       strings.TrimSpace(transition.Metadata["federation_incident_directive_title"]),
				DirectivePriority:    SecureCellFederationIncidentDirectivePriority(strings.TrimSpace(transition.Metadata["federation_incident_directive_priority"])),
				DirectiveStatus:      SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_status"])),
				PendingAction:        strings.TrimSpace(transition.Metadata["federation_incident_directive_pending_action"]),
				ContractID:           strings.TrimSpace(transition.Metadata["federation_contract_id"]),
				ContractStatusBefore: SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_before"])),
				ContractStatusAfter:  SecureCellFederationContractStatus(strings.TrimSpace(transition.Metadata["federation_contract_status_after"])),
				Action:               transition.Action,
				Trigger:              strings.TrimSpace(transition.Metadata["federation_incident_directive_trigger"]),
				TierID:               strings.TrimSpace(transition.Metadata["federation_incident_response_tier_id"]),
				TargetDID:            firstNonEmpty(strings.TrimSpace(transition.Metadata["federation_incident_response_target_did"]), strings.TrimSpace(transition.Metadata["decision_route_target"])),
				DueAt:                parseSecureCellTransitionDueAtWithKey(transition.Metadata, "federation_incident_directive_due_at"),
				Actor:                transition.Actor,
				AutomatedActor:       strings.TrimSpace(transition.Metadata["automated_actor"]),
				Reason:               strings.TrimSpace(transition.Reason),
				TransitionID:         strings.TrimSpace(transition.ID),
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

// SweepFederationIncidentDirectives applies automated escalation or fail-closed
// contract suspension to overdue bilateral incident directives.
func (s *Service) SweepFederationIncidentDirectives(ctx context.Context, at time.Time, lifecycle SecureCellLifecycleRequest) (*SecureCellFederationIncidentDirectiveSweepResult, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/federation-incident-directive: service is required")
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

	report := &SecureCellFederationIncidentDirectiveSweepResult{
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
			report.DirectivesScanned += len(response.IncidentDirectives)
			for _, directive := range response.IncidentDirectives {
				plan, ok := secureCellFederationIncidentDirectiveAutomationPlanFromRun(run, response, directive, at)
				if !ok {
					continue
				}
				if secureCellFederationIncidentDirectiveAutomationAlreadyApplied(run, directive.ID, directive.Status, plan.pendingAction, plan.action) {
					continue
				}

				baseMetadata := mergeStringMaps(lifecycle.Metadata, map[string]string{
					"federation_incident_directive_sweep_mode":     "automated",
					"federation_incident_directive_action":         plan.action,
					"federation_incident_directive_trigger":        plan.trigger,
					"federation_incident_directive_id":             directive.ID,
					"federation_incident_directive_title":          directive.Title,
					"federation_incident_directive_priority":       string(directive.Priority),
					"federation_incident_directive_status":         string(directive.Status),
					"federation_incident_directive_pending_action": plan.pendingAction,
					"federation_incident_directive_due_at":         plan.dueAt.UTC().Format(time.RFC3339Nano),
					"federation_incident_response_id":              response.ID,
					"federation_organization_id":                   response.OrganizationID,
					"federation_sponsor_of_record":                 response.SponsorOfRecord,
					"federation_incident_id":                       response.IncidentID,
				})
				if automatedActor := strings.TrimSpace(lifecycle.ActorDID); automatedActor != "" && automatedActor != run.request.OwnerIdentity.AgentID() {
					baseMetadata["automated_actor"] = automatedActor
				}

				switch plan.action {
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

func secureCellFederationIncidentDirectiveAutomationPlanFromRun(run *secureCellRun, response SecureCellFederationIncidentResponse, directive SecureCellFederationIncidentDirective, at time.Time) (secureCellFederationIncidentDirectiveAutomationPlan, bool) {
	if run == nil || run.result == nil {
		return secureCellFederationIncidentDirectiveAutomationPlan{}, false
	}
	overdue, ok := secureCellOverdueFederationIncidentDirectiveFromRun(run, response, directive, at)
	if !ok {
		return secureCellFederationIncidentDirectiveAutomationPlan{}, false
	}

	switch directive.Status {
	case SecureCellFederationIncidentDirectiveStatusIssued, SecureCellFederationIncidentDirectiveStatusAcknowledged:
		if tier, ok := secureCellNextFederationIncidentResponseEscalationTier(response); ok {
			return secureCellFederationIncidentDirectiveAutomationPlan{
				action:        "escalate_response",
				trigger:       overdue.PendingAction + "_due",
				reason:        "directive deadline reached without " + overdue.PendingAction,
				pendingAction: overdue.PendingAction,
				dueAt:         overdue.DueAt,
				tierID:        strings.TrimSpace(tier.TierID),
				targetDID:     strings.TrimSpace(tier.TargetDID),
			}, true
		}
		if len(activeFederationContractsForOrganization(run.result.FederationContracts, response.OrganizationID)) > 0 {
			return secureCellFederationIncidentDirectiveAutomationPlan{
				action:        "suspend_contracts",
				trigger:       overdue.PendingAction + "_due",
				reason:        "directive deadline reached without an available escalation tier",
				pendingAction: overdue.PendingAction,
				dueAt:         overdue.DueAt,
			}, true
		}
	case SecureCellFederationIncidentDirectiveStatusCompleted:
		if len(activeFederationContractsForOrganization(run.result.FederationContracts, response.OrganizationID)) > 0 {
			return secureCellFederationIncidentDirectiveAutomationPlan{
				action:        "suspend_contracts",
				trigger:       "verify_due",
				reason:        "directive completion verification deadline reached",
				pendingAction: overdue.PendingAction,
				dueAt:         overdue.DueAt,
			}, true
		}
	}
	return secureCellFederationIncidentDirectiveAutomationPlan{}, false
}

func secureCellNextFederationIncidentResponseEscalationTier(response SecureCellFederationIncidentResponse) (SecureCellFederationEscalationTier, bool) {
	for _, tier := range response.EscalationLadder {
		if secureCellStringSliceContains(response.EscalatedTierIDs, tier.TierID) {
			continue
		}
		stepType := secureCellFederationIncidentResponseTierStepType(tier.TierID)
		if stepType != "" && secureCellFederationIncidentResponseStepStatus(response, stepType) == SecureCellFederationIncidentPlaybookStepStatusCompleted {
			continue
		}
		return tier, true
	}
	return SecureCellFederationEscalationTier{}, false
}

func secureCellFederationIncidentDirectiveAutomationAlreadyApplied(run *secureCellRun, directiveID string, directiveStatus SecureCellFederationIncidentDirectiveStatus, pendingAction string, action string) bool {
	if run == nil || run.result == nil {
		return false
	}
	directiveID = strings.TrimSpace(directiveID)
	pendingAction = strings.TrimSpace(pendingAction)
	action = strings.TrimSpace(action)
	for _, transition := range run.result.Transitions {
		if !secureCellTransitionAutomatedFederationIncidentDirectiveAction(transition) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_id"]), directiveID) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_pending_action"]), pendingAction) {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_action"]), action) {
			continue
		}
		if SecureCellFederationIncidentDirectiveStatus(strings.TrimSpace(transition.Metadata["federation_incident_directive_status"])) != directiveStatus {
			continue
		}
		return true
	}
	return false
}

func secureCellTransitionAutomatedFederationIncidentDirectiveAction(transition SecureCellTransition) bool {
	return strings.EqualFold(strings.TrimSpace(transition.Metadata["federation_incident_directive_sweep_mode"]), "automated")
}
