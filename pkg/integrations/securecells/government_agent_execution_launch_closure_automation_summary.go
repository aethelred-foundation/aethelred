package securecells

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction groups
// repeated pending/automation action pairs across the filtered estate.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction struct {
	PendingAction    string   `json:"pending_action"`
	AutomationAction string   `json:"automation_action"`
	Count            int      `json:"count"`
	CellIDs          []string `json:"cell_ids,omitempty"`
}

// SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary is the
// portfolio SLA rollup for closure automation pressure.
type SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary struct {
	SummaryID                  string                                                                   `json:"summary_id"`
	Jurisdiction               string                                                                   `json:"jurisdiction,omitempty"`
	ServiceCode                string                                                                   `json:"service_code,omitempty"`
	ServiceTier                string                                                                   `json:"service_tier,omitempty"`
	EvaluatedAt                time.Time                                                                `json:"evaluated_at"`
	ActionCount                int                                                                      `json:"action_count"`
	BlockedCount               int                                                                      `json:"blocked_count"`
	DueCount                   int                                                                      `json:"due_count"`
	OverdueCount               int                                                                      `json:"overdue_count"`
	EscalationRecommendedCount int                                                                      `json:"escalation_recommended_count"`
	NextDueAt                  *time.Time                                                               `json:"next_due_at,omitempty"`
	MaxOverdueSeconds          int64                                                                    `json:"max_overdue_seconds"`
	TopActions                 []SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction `json:"top_actions,omitempty"`
	Items                      []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction        `json:"items"`
	SummaryDigest              string                                                                   `json:"summary_digest"`
	GeneratedAt                time.Time                                                                `json:"generated_at"`
}

// GetGovernmentAgentExecutionLaunchClosureAutomationSummary returns the
// closure automation rollup for matching government-service workflows.
func (s *Service) GetGovernmentAgentExecutionLaunchClosureAutomationSummary(ctx context.Context, filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter) (*SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary, error) {
	if s == nil {
		return nil, fmt.Errorf("securecells/government-agent-execution-launch-closure-automation-summary: service is required")
	}
	at := time.Now().UTC()
	if filter.Before != nil && !filter.Before.IsZero() {
		at = filter.Before.UTC()
	}
	items, err := s.ListGovernmentAgentExecutionLaunchClosureAutomationActions(ctx, SecureCellGovernmentAgentProgramFilter{
		CellID:       strings.TrimSpace(filter.CellID),
		Jurisdiction: strings.TrimSpace(filter.Jurisdiction),
		ServiceCode:  strings.TrimSpace(filter.ServiceCode),
		ServiceTier:  strings.TrimSpace(filter.ServiceTier),
		Limit:        filter.Limit,
	})
	if err != nil {
		return nil, err
	}
	summary := secureCellGovernmentAgentExecutionLaunchClosureAutomationSummary(filter, items, at, time.Now().UTC())
	return &summary, nil
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationSummary(
	filter SecureCellGovernmentAgentExecutionLaunchClosureOverdueActionFilter,
	items []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction,
	evaluatedAt time.Time,
	generatedAt time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary {
	summary := SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary{
		Jurisdiction: strings.TrimSpace(filter.Jurisdiction),
		ServiceCode:  strings.TrimSpace(filter.ServiceCode),
		ServiceTier:  strings.TrimSpace(filter.ServiceTier),
		EvaluatedAt:  evaluatedAt.UTC(),
		Items:        append([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction(nil), items...),
		GeneratedAt:  generatedAt.UTC(),
	}
	topActions := map[string]*SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction{}
	for _, item := range items {
		summary.ActionCount++
		switch secureCellGovernmentAgentExecutionLaunchClosureAutomationStatusAt(item, evaluatedAt) {
		case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked:
			summary.BlockedCount++
		case SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue:
			summary.OverdueCount++
			if item.DueAt != nil {
				seconds := int64(evaluatedAt.Sub(item.DueAt.UTC()).Seconds())
				if seconds > summary.MaxOverdueSeconds {
					summary.MaxOverdueSeconds = seconds
				}
			}
		default:
			summary.DueCount++
		}
		if item.EscalationRecommended {
			summary.EscalationRecommendedCount++
		}
		if item.DueAt != nil && (summary.NextDueAt == nil || item.DueAt.UTC().Before(summary.NextDueAt.UTC())) {
			due := item.DueAt.UTC()
			summary.NextDueAt = &due
		}
		key := strings.TrimSpace(item.PendingAction) + "|" + strings.TrimSpace(item.AutomationAction)
		action, ok := topActions[key]
		if !ok {
			action = &SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction{
				PendingAction:    item.PendingAction,
				AutomationAction: item.AutomationAction,
			}
			topActions[key] = action
		}
		action.Count++
		action.CellIDs = append(action.CellIDs, item.CellID)
	}
	summary.TopActions = make([]SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction, 0, len(topActions))
	for _, action := range topActions {
		action.CellIDs = uniqueTrimmedStrings(action.CellIDs)
		summary.TopActions = append(summary.TopActions, *action)
	}
	sort.SliceStable(summary.TopActions, func(i, j int) bool {
		if summary.TopActions[i].Count == summary.TopActions[j].Count {
			if summary.TopActions[i].PendingAction == summary.TopActions[j].PendingAction {
				return summary.TopActions[i].AutomationAction < summary.TopActions[j].AutomationAction
			}
			return summary.TopActions[i].PendingAction < summary.TopActions[j].PendingAction
		}
		return summary.TopActions[i].Count > summary.TopActions[j].Count
	})
	summary.SummaryDigest = secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryDigest(summary)
	summary.SummaryID = "government-agent-execution-launch-closure-automation-summary:" + firstNonEmpty(summary.Jurisdiction, "all") + ":" + summary.SummaryDigest[:12]
	return summary
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationStatusAt(
	item SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction,
	at time.Time,
) SecureCellGovernmentAgentExecutionLaunchClosureActionQueueStatus {
	if item.ActionKind == SecureCellGovernmentAgentExecutionLaunchClosureActionEscalateBlocked {
		if item.DueAt != nil && at.After(item.DueAt.UTC()) {
			return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue
		}
		return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueBlocked
	}
	if item.DueAt != nil && at.After(item.DueAt.UTC()) {
		return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueOverdue
	}
	return SecureCellGovernmentAgentExecutionLaunchClosureActionQueueDue
}

func secureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryDigest(summary SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummary) string {
	core := struct {
		Jurisdiction string                                                                   `json:"jurisdiction,omitempty"`
		ServiceCode  string                                                                   `json:"service_code,omitempty"`
		ServiceTier  string                                                                   `json:"service_tier,omitempty"`
		EvaluatedAt  time.Time                                                                `json:"evaluated_at"`
		TopActions   []SecureCellGovernmentAgentExecutionLaunchClosureAutomationSummaryAction `json:"top_actions,omitempty"`
		Items        []SecureCellGovernmentAgentExecutionLaunchClosureAutomationAction        `json:"items"`
	}{
		Jurisdiction: summary.Jurisdiction,
		ServiceCode:  summary.ServiceCode,
		ServiceTier:  summary.ServiceTier,
		EvaluatedAt:  summary.EvaluatedAt.UTC(),
		TopActions:   summary.TopActions,
		Items:        summary.Items,
	}
	return EvidenceHash(core)
}
